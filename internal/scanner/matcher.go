// Package scanner provides malware scanning functionality
package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/greysquirr3l/wordfence-go/internal/intel"
	"github.com/greysquirr3l/wordfence-go/internal/logging"
)

// DefaultMatchTimeout is the default timeout for pattern matching
const DefaultMatchTimeout = 1 * time.Second

// ErrMatchTimeout indicates a pattern match timed out
type ErrMatchTimeout struct {
	SignatureID int
}

func (e *ErrMatchTimeout) Error() string {
	return fmt.Sprintf("match timeout for signature %d", e.SignatureID)
}

// MatchResult represents a successful pattern match
type MatchResult struct {
	SignatureID   int
	MatchedString string
	Position      int
}

// CompiledPattern represents a compiled regex pattern using multi-layer engine
type CompiledPattern struct {
	Pattern  *CompiledRegex
	Original string
}

// CompiledSignature represents a signature with a compiled pattern
type CompiledSignature struct {
	Signature     *intel.Signature
	Pattern       *CompiledPattern
	AnchoredStart bool
	CompileError  error
}

// CompiledCommonString represents a common string with a compiled pattern
type CompiledCommonString struct {
	CommonString *intel.CommonString
	Pattern      *CompiledPattern
	// Index in the Aho-Corasick automaton (for fast lookup)
	ACIndex int
}

// Matcher compiles and matches signatures against content
type Matcher struct {
	signatures      map[int]*CompiledSignature
	commonStrings   []*CompiledCommonString
	noCommonStrSigs []*CompiledSignature // Signatures without common strings
	timeout         time.Duration
	matchAll        bool
	logger          *logging.Logger
	mu              sync.RWMutex
	prepared        bool

	// Aho-Corasick automaton for fast common string pre-filtering
	// Single O(n) pass identifies ALL matching common strings
	acAutomaton    *ahocorasick.AhoCorasick
	acStringToIdx  map[string]int // Map common string -> index in commonStrings
	commonStrTexts []string       // Raw strings for AC automaton

	// Pool for MatchContext objects to reduce GC pressure
	contextPool sync.Pool
}

// MatcherOption configures a Matcher
type MatcherOption func(*Matcher)

// WithMatchTimeout sets the match timeout
func WithMatchTimeout(timeout time.Duration) MatcherOption {
	return func(m *Matcher) {
		m.timeout = timeout
	}
}

// WithMatchAll configures whether to find all matches or stop at first
func WithMatchAll(matchAll bool) MatcherOption {
	return func(m *Matcher) {
		m.matchAll = matchAll
	}
}

// WithMatcherLogger sets the logger
func WithMatcherLogger(logger *logging.Logger) MatcherOption {
	return func(m *Matcher) {
		m.logger = logger
	}
}

// NewMatcher creates a new Matcher for the given signature set
func NewMatcher(sigSet *intel.SignatureSet, opts ...MatcherOption) *Matcher {
	m := &Matcher{
		signatures:     make(map[int]*CompiledSignature),
		commonStrings:  make([]*CompiledCommonString, 0),
		timeout:        DefaultMatchTimeout,
		matchAll:       false,
		logger:         logging.New(logging.LevelInfo),
		acStringToIdx:  make(map[string]int),
		commonStrTexts: make([]string, 0),
	}

	// Initialize context pool
	m.contextPool = sync.Pool{
		New: func() interface{} {
			return &MatchContext{
				matches:  make(map[int]*MatchResult, 16),
				timeouts: make(map[int]bool, 4),
			}
		},
	}

	for _, opt := range opts {
		opt(m)
	}

	// Compile signatures
	m.compileSignatures(sigSet)

	return m
}

// compileSignatures compiles all signatures and common strings
func (m *Matcher) compileSignatures(sigSet *intel.SignatureSet) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Compile common strings and build Aho-Corasick automaton
	acPatterns := make([]string, 0, len(sigSet.CommonStrings))

	for idx, cs := range sigSet.CommonStrings {
		compiled := &CompiledCommonString{
			CommonString: cs,
			ACIndex:      idx,
		}

		// Store raw string for Aho-Corasick
		acPatterns = append(acPatterns, cs.String)
		m.acStringToIdx[cs.String] = idx
		m.commonStrTexts = append(m.commonStrTexts, cs.String)

		// Also compile as regex pattern for fallback (escaped for literal matching)
		pattern, err := m.compilePattern(escapeRegex(cs.String))
		if err != nil {
			m.logger.Debug("Failed to compile common string pattern: %v", err)
		} else {
			compiled.Pattern = pattern
		}

		m.commonStrings = append(m.commonStrings, compiled)
	}

	// Build Aho-Corasick automaton for O(n) common string matching
	if len(acPatterns) > 0 {
		builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
			AsciiCaseInsensitive: false,
			MatchOnlyWholeWords:  false,
			MatchKind:            ahocorasick.LeftMostLongestMatch,
			DFA:                  true, // DFA mode for O(N) runtime
		})
		ac := builder.Build(acPatterns)
		m.acAutomaton = &ac
	}

	// Compile signatures using multi-layer regex engine
	for id, sig := range sigSet.Signatures {
		compiled := &CompiledSignature{
			Signature:     sig,
			AnchoredStart: strings.HasPrefix(sig.Rule, "^"),
		}

		pattern, err := m.compilePattern(sig.Rule)
		if err != nil {
			compiled.CompileError = err
			m.logger.Debug("Failed to compile signature %d: %v", id, err)
		} else {
			compiled.Pattern = pattern
		}

		m.signatures[id] = compiled

		// Track signatures without common strings
		if !sig.HasCommonStrings() && compiled.Pattern != nil {
			m.noCommonStrSigs = append(m.noCommonStrSigs, compiled)
		}
	}

	m.prepared = true
}

// escapeRegex escapes special regex characters for literal matching
func escapeRegex(s string) string {
	special := []string{"\\", ".", "+", "*", "?", "(", ")", "[", "]", "{", "}", "|", "^", "$"}
	result := s
	for _, ch := range special {
		result = strings.ReplaceAll(result, ch, "\\"+ch)
	}
	return result
}

// compilePattern compiles a pattern using the multi-layer regex engine
// (go-re2 for ~99.8% of patterns, regexp2/PCRE fallback for the rest)
func (m *Matcher) compilePattern(pattern string) (*CompiledPattern, error) {
	compiled, err := CompileRegex(pattern, m.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to compile pattern: %w", err)
	}

	return &CompiledPattern{
		Pattern:  compiled,
		Original: pattern,
	}, nil
}

// MatchContext holds state for matching against a single file
type MatchContext struct {
	matcher            *Matcher
	matches            map[int]*MatchResult
	timeouts           map[int]bool
	commonStringStates []bool
	mu                 sync.Mutex
}

// NewMatchContext creates a new match context from the pool
func (m *Matcher) NewMatchContext() *MatchContext {
	mc := m.contextPool.Get().(*MatchContext)
	mc.matcher = m

	// Clear and resize maps
	clear(mc.matches)
	clear(mc.timeouts)

	// Resize commonStringStates if needed, then clear
	if cap(mc.commonStringStates) < len(m.commonStrings) {
		mc.commonStringStates = make([]bool, len(m.commonStrings))
	} else {
		mc.commonStringStates = mc.commonStringStates[:len(m.commonStrings)]
		clear(mc.commonStringStates)
	}

	return mc
}

// Release returns the MatchContext to the pool for reuse
// Call this when done with the context to reduce GC pressure
func (mc *MatchContext) Release() {
	if mc == nil || mc.matcher == nil {
		return
	}

	// Clear references to allow GC of match results
	clear(mc.matches)
	clear(mc.timeouts)

	matcher := mc.matcher
	mc.matcher = nil

	matcher.contextPool.Put(mc)
}

// Match matches the content against all signatures
func (mc *MatchContext) Match(ctx context.Context, content []byte) error {
	return mc.MatchChunk(ctx, content, true)
}

// MatchChunk matches a chunk of content
func (mc *MatchContext) MatchChunk(ctx context.Context, content []byte, isStart bool) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Zero-copy conversion: content must remain immutable during matching
	// This eliminates memory allocation for the entire file content
	contentStr := unsafe.String(unsafe.SliceData(content), len(content))

	// Use Aho-Corasick for O(n) common string pre-filtering
	// Single pass identifies ALL matching common strings
	possibleSigs := mc.checkCommonStringsAC(content)

	// Match signatures without common strings
	for _, sig := range mc.matcher.noCommonStrSigs {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled: %w", ctx.Err())
		default:
		}

		if mc.matchSignature(sig, contentStr, isStart) && !mc.matcher.matchAll {
			return nil
		}
	}

	// Match possible signatures (those whose common strings all matched)
	for _, sig := range possibleSigs {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled: %w", ctx.Err())
		default:
		}

		if mc.matchSignature(sig, contentStr, isStart) && !mc.matcher.matchAll {
			return nil
		}
	}

	return nil
}

// checkCommonStringsAC uses Aho-Corasick for O(n) common string matching
// This replaces the O(n*m) sequential bytes.Contains approach
func (mc *MatchContext) checkCommonStringsAC(content []byte) []*CompiledSignature {
	commonStringCounts := make(map[int]int)

	// Use Aho-Corasick if available (single O(n) pass for ALL patterns)
	if mc.matcher.acAutomaton != nil {
		// Zero-copy string conversion for AC matching
		contentStr := unsafe.String(unsafe.SliceData(content), len(content))

		// Find all matches in a single pass
		iter := mc.matcher.acAutomaton.Iter(contentStr)
		for {
			match := iter.Next()
			if match == nil {
				break
			}

			idx := match.Pattern()
			if idx < len(mc.commonStringStates) && !mc.commonStringStates[idx] {
				mc.commonStringStates[idx] = true
				cs := mc.matcher.commonStrings[idx]
				for _, sigID := range cs.CommonString.SignatureIDs {
					if _, ok := mc.matches[sigID]; !ok {
						commonStringCounts[sigID]++
					}
				}
			}
		}
	} else {
		// Fallback to regex-based matching (slower)
		contentStr := unsafe.String(unsafe.SliceData(content), len(content))
		return mc.checkCommonStringsRegex(contentStr)
	}

	// Find signatures where all common strings matched
	var possibleSigs []*CompiledSignature
	for sigID, count := range commonStringCounts {
		sig, ok := mc.matcher.signatures[sigID]
		if !ok {
			continue
		}
		if count == sig.Signature.GetCommonStringCount() {
			possibleSigs = append(possibleSigs, sig)
		}
	}

	return possibleSigs
}

// checkCommonStringsRegex is the fallback regex-based common string check
func (mc *MatchContext) checkCommonStringsRegex(content string) []*CompiledSignature {
	commonStringCounts := make(map[int]int)

	for idx, cs := range mc.matcher.commonStrings {
		if mc.commonStringStates[idx] {
			// Already matched
			for _, sigID := range cs.CommonString.SignatureIDs {
				if _, ok := mc.matches[sigID]; !ok {
					commonStringCounts[sigID]++
				}
			}
			continue
		}

		if cs.Pattern == nil {
			continue
		}

		match, err := cs.Pattern.Pattern.FindStringMatch(content)
		if err != nil {
			mc.matcher.logger.Debug("Common string match error: %v", err)
			continue
		}

		if match != nil {
			mc.commonStringStates[idx] = true
			for _, sigID := range cs.CommonString.SignatureIDs {
				if _, ok := mc.matches[sigID]; !ok {
					commonStringCounts[sigID]++
				}
			}
		}
	}

	// Find signatures where all common strings matched
	var possibleSigs []*CompiledSignature
	for sigID, count := range commonStringCounts {
		sig, ok := mc.matcher.signatures[sigID]
		if !ok {
			continue
		}
		if count == sig.Signature.GetCommonStringCount() {
			possibleSigs = append(possibleSigs, sig)
		}
	}

	return possibleSigs
}

// matchSignature attempts to match a single signature
func (mc *MatchContext) matchSignature(sig *CompiledSignature, content string, isStart bool) bool {
	if sig.Pattern == nil {
		return false
	}

	// Skip anchored patterns if not at start
	if sig.AnchoredStart && !isStart {
		return false
	}

	// Skip already matched signatures
	if _, ok := mc.matches[sig.Signature.ID]; ok {
		return false
	}

	match, err := sig.Pattern.Pattern.FindStringMatch(content)
	if err != nil {
		// Check for timeout
		if strings.Contains(err.Error(), "timeout") {
			mc.timeouts[sig.Signature.ID] = true
		}
		mc.matcher.logger.Debug("Signature %d match error: %v", sig.Signature.ID, err)
		return false
	}

	if match != nil {
		mc.matches[sig.Signature.ID] = &MatchResult{
			SignatureID:   sig.Signature.ID,
			MatchedString: match.Value,
			Position:      match.Index,
		}
		return true
	}

	return false
}

// GetMatches returns all matches found
func (mc *MatchContext) GetMatches() []*MatchResult {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	results := make([]*MatchResult, 0, len(mc.matches))
	for _, match := range mc.matches {
		results = append(results, match)
	}
	return results
}

// GetTimeouts returns signature IDs that timed out
func (mc *MatchContext) GetTimeouts() []int {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	timeouts := make([]int, 0, len(mc.timeouts))
	for sigID := range mc.timeouts {
		timeouts = append(timeouts, sigID)
	}
	return timeouts
}

// HasMatches returns true if any matches were found
func (mc *MatchContext) HasMatches() bool {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return len(mc.matches) > 0
}

// MatchCount returns the number of matches found
func (mc *MatchContext) MatchCount() int {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return len(mc.matches)
}
