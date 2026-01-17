// Package scanner provides malware scanning functionality
package scanner

import (
	"sync"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/wasilibs/go-re2"
)

// RegexEngine provides a multi-layer regex matching strategy:
// 1. Try go-re2 (WASM-based, fast for complex patterns, ~99.8% of rules)
// 2. Fall back to regexp2 (PCRE-compatible, 100% rule coverage)
//
// Engine selection happens at compile time, not match time, for zero runtime overhead.

// CompiledRegex represents a compiled regex with automatic engine selection
type CompiledRegex struct {
	// RE2 pattern (nil if not RE2-compatible)
	re2Pattern *re2.Regexp

	// PCRE pattern via regexp2 (always compiled as fallback)
	pcrePattern *regexp2.Regexp

	// Original pattern string
	original string

	// UseRE2 indicates which engine to use (determined at compile time)
	useRE2 bool

	// Timeout for PCRE matches
	timeout time.Duration
}

// regexPool pools CompiledRegex wrappers to reduce allocations
var regexPool = sync.Pool{
	New: func() interface{} {
		return &CompiledRegex{}
	},
}

// CompileRegex compiles a pattern using the multi-layer strategy
// It tries RE2 first, and falls back to regexp2 for PCRE-only features
func CompileRegex(pattern string, timeout time.Duration) (*CompiledRegex, error) {
	cr := &CompiledRegex{
		original: pattern,
		timeout:  timeout,
	}

	// Try RE2 first (faster for complex patterns)
	re2Pat, err := re2.Compile(pattern)
	if err == nil {
		cr.re2Pattern = re2Pat
		cr.useRE2 = true
	}

	// Always compile PCRE as fallback (or primary if RE2 failed)
	opts := regexp2.Multiline | regexp2.Singleline
	pcrePat, err := regexp2.Compile(pattern, regexp2.RegexOptions(opts))
	if err != nil {
		// Pattern is invalid in both engines
		return nil, err
	}
	pcrePat.MatchTimeout = timeout
	cr.pcrePattern = pcrePat

	return cr, nil
}

// FindStringMatch finds the first match in the input string
func (cr *CompiledRegex) FindStringMatch(s string) (*RegexMatch, error) {
	if cr.useRE2 && cr.re2Pattern != nil {
		loc := cr.re2Pattern.FindStringIndex(s)
		if loc == nil {
			return nil, nil
		}
		return &RegexMatch{
			Value: s[loc[0]:loc[1]],
			Index: loc[0],
		}, nil
	}

	// Use PCRE fallback
	match, err := cr.pcrePattern.FindStringMatch(s)
	if err != nil {
		return nil, err
	}
	if match == nil {
		return nil, nil
	}
	return &RegexMatch{
		Value: match.String(),
		Index: match.Index,
	}, nil
}

// MatchString returns true if the pattern matches anywhere in the string
func (cr *CompiledRegex) MatchString(s string) (bool, error) {
	if cr.useRE2 && cr.re2Pattern != nil {
		return cr.re2Pattern.MatchString(s), nil
	}

	// Use PCRE fallback
	return cr.pcrePattern.MatchString(s)
}

// RegexMatch represents a regex match result
type RegexMatch struct {
	Value string
	Index int
}

// String returns the matched string
func (m *RegexMatch) String() string {
	return m.Value
}

// IsRE2Compatible returns whether this pattern uses the fast RE2 engine
func (cr *CompiledRegex) IsRE2Compatible() bool {
	return cr.useRE2
}

// Original returns the original pattern string
func (cr *CompiledRegex) Original() string {
	return cr.original
}
