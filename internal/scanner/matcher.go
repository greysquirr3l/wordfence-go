// Package scanner provides malware scanning functionality
package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"

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

// CompiledPattern represents a compiled regex pattern
type CompiledPattern struct {
	Pattern  *regexp2.Regexp
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
		signatures:    make(map[int]*CompiledSignature),
		commonStrings: make([]*CompiledCommonString, 0),
		timeout:       DefaultMatchTimeout,
		matchAll:      false,
		logger:        logging.New(logging.LevelInfo),
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

	// Compile common strings
	for _, cs := range sigSet.CommonStrings {
		compiled := &CompiledCommonString{
			CommonString: cs,
		}

		pattern, err := m.compilePattern(regexp2.Escape(cs.String))
		if err != nil {
			m.logger.Debug("Failed to compile common string pattern: %v", err)
		} else {
			compiled.Pattern = pattern
		}

		m.commonStrings = append(m.commonStrings, compiled)
	}

	// Compile signatures
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

// compilePattern compiles a PCRE pattern using regexp2
func (m *Matcher) compilePattern(pattern string) (*CompiledPattern, error) {
	// regexp2 options for PCRE compatibility
	opts := regexp2.Multiline | regexp2.Singleline

	re, err := regexp2.Compile(pattern, regexp2.RegexOptions(opts))
	if err != nil {
		return nil, fmt.Errorf("failed to compile pattern: %w", err)
	}

	// Set match timeout
	re.MatchTimeout = m.timeout

	return &CompiledPattern{
		Pattern:  re,
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

// NewMatchContext creates a new match context
func (m *Matcher) NewMatchContext() *MatchContext {
	return &MatchContext{
		matcher:            m,
		matches:            make(map[int]*MatchResult),
		timeouts:           make(map[int]bool),
		commonStringStates: make([]bool, len(m.commonStrings)),
	}
}

// Match matches the content against all signatures
func (mc *MatchContext) Match(ctx context.Context, content []byte) error {
	return mc.MatchChunk(ctx, content, true)
}

// MatchChunk matches a chunk of content
func (mc *MatchContext) MatchChunk(ctx context.Context, content []byte, isStart bool) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	contentStr := string(content)

	// Check common strings first to narrow down possible signatures
	possibleSigs := mc.checkCommonStrings(contentStr)

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

// checkCommonStrings checks which common strings match and returns possible signatures
func (mc *MatchContext) checkCommonStrings(content string) []*CompiledSignature {
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
			MatchedString: match.String(),
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
