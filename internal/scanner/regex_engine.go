// Package scanner provides malware scanning functionality
package scanner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/wasilibs/go-re2"
)

// RegexEngine provides a multi-layer regex matching strategy:
// 1. Try go-re2 (WASM-based, fast for complex patterns, ~99.8% of rules)
// 2. Fall back to regexp2 (PCRE-compatible, 100% rule coverage)
//
// Engine selection happens at compile time, not match time, for zero runtime overhead.

// re2MaxRepetition is the maximum single repetition count RE2 supports.
// RE2 limits repetition to prevent ReDoS attacks.
const re2MaxRepetition = 1000

// re2MaxNestedProduct is the maximum product of nested repetitions.
// RE2 calculates total "cost" by multiplying nested repetitions.
// For example, (x{100}){20} has cost 100*20=2000 which exceeds limits.
const re2MaxNestedProduct = 1000

// repetitionPattern matches regex repetition quantifiers like {n}, {n,}, {n,m}
var repetitionPattern = regexp.MustCompile(`\{(\d+)(?:,(\d*))?\}`)

// groupRepetitionPattern matches a closing paren followed by a repetition quantifier
// This catches patterns like (...){2} where nested repetitions multiply
var groupRepetitionPattern = regexp.MustCompile(`\)\{(\d+)(?:,(\d*))?\}`)

// isRE2Compatible performs a quick pre-check to detect patterns that will
// definitely fail RE2 compilation, avoiding noisy stderr error messages.
// This checks for:
// - Large repetition counts (>{re2MaxRepetition})
// - Nested repetitions whose product exceeds limits
// - PCRE-specific features RE2 doesn't support (\Z, \h, \v, \R, etc.)
// - Invalid escape sequences that RE2 rejects
func isRE2Compatible(pattern string) bool {
	// Check for PCRE-specific escape sequences that RE2 doesn't support
	// \Z - end of string or before final newline
	// \h - horizontal whitespace
	// \H - non-horizontal whitespace
	// \v - vertical whitespace (RE2 has \v but interprets it as vertical tab only)
	// \V - non-vertical whitespace
	// \R - any line break sequence
	// \K - reset match start
	// \G - anchor to end of previous match
	pcreOnlyEscapes := []string{`\Z`, `\h`, `\H`, `\V`, `\R`, `\K`, `\G`}
	for _, esc := range pcreOnlyEscapes {
		if strings.Contains(pattern, esc) {
			return false
		}
	}

	// Check for \b inside character classes like [\b] - PCRE treats as backspace,
	// but RE2 rejects it as invalid
	if strings.Contains(pattern, `[\b`) || strings.Contains(pattern, `\b]`) {
		return false
	}

	// Collect all repetition values to check for multiplicative effects
	var repetitions []int
	matches := repetitionPattern.FindAllStringSubmatch(pattern, -1)
	for _, match := range matches {
		// match[1] is the first number, match[2] is the optional second number (max)
		// For RE2, we care about the maximum value in the range
		maxVal := 0
		if n, err := strconv.Atoi(match[1]); err == nil {
			if n > re2MaxRepetition {
				return false
			}
			maxVal = n
		}
		if match[2] != "" {
			if m, err := strconv.Atoi(match[2]); err == nil {
				if m > re2MaxRepetition {
					return false
				}
				if m > maxVal {
					maxVal = m
				}
			}
		}
		if maxVal > 0 {
			repetitions = append(repetitions, maxVal)
		}
	}

	// Check for group repetitions - these cause multiplicative cost in RE2
	// RE2 calculates total cost by multiplying nested repetitions
	// For example: (something{100}){20} = 100*20 = 2000 cost
	groupMatches := groupRepetitionPattern.FindAllStringSubmatch(pattern, -1)
	if len(groupMatches) > 0 && len(repetitions) > 1 {
		// Calculate the product of the two largest repetitions
		// This is a conservative heuristic - RE2's actual calculation is more complex
		// but this catches most problematic patterns
		largest := 0
		secondLargest := 0
		for _, r := range repetitions {
			if r > largest {
				secondLargest = largest
				largest = r
			} else if r > secondLargest {
				secondLargest = r
			}
		}

		// If the product of the two largest repetitions exceeds the limit, reject
		if largest*secondLargest > re2MaxNestedProduct {
			return false
		}

		// Also reject if we have many repetitions that could compound
		// (more than 3 repetitions with any being > 50 is risky)
		if len(repetitions) > 3 {
			for _, r := range repetitions {
				if r > 50 {
					return false
				}
			}
		}
	}

	// Check for escape sequences RE2 doesn't support
	for i := 0; i < len(pattern)-1; i++ {
		if pattern[i] == '\\' {
			next := pattern[i+1]
			// RE2 doesn't support \1-\9 backreferences in the same way as PCRE
			// and rejects certain invalid escape sequences
			if next >= '1' && next <= '9' {
				// Check if this looks like an invalid octal or backreference
				// that might cause RE2 to emit an error
				if i+2 < len(pattern) {
					following := pattern[i+2]
					// Patterns like \5c, \bd are likely problematic
					if (following >= 'a' && following <= 'z') ||
						(following >= 'A' && following <= 'Z') {
						return false
					}
				}
			}
		}
	}

	return true
}

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

// CompileRegex compiles a pattern using the multi-layer strategy
// It tries RE2 first, and falls back to regexp2 for PCRE-only features
func CompileRegex(pattern string, timeout time.Duration) (*CompiledRegex, error) {
	cr := &CompiledRegex{
		original: pattern,
		timeout:  timeout,
	}

	// Pre-check for RE2 compatibility to avoid noisy stderr messages
	// from the underlying C++ RE2 library when compilation fails
	if isRE2Compatible(pattern) {
		// Try RE2 (faster for complex patterns)
		re2Pat, err := re2.Compile(pattern)
		if err == nil {
			cr.re2Pattern = re2Pat
			cr.useRE2 = true
		}
	}

	// Always compile PCRE as fallback (or primary if RE2 failed)
	opts := regexp2.Multiline | regexp2.Singleline
	pcrePat, err := regexp2.Compile(pattern, regexp2.RegexOptions(opts))
	if err != nil {
		// Pattern is invalid in both engines
		return nil, fmt.Errorf("failed to compile regex pattern: %w", err)
	}
	pcrePat.MatchTimeout = timeout
	cr.pcrePattern = pcrePat

	return cr, nil
}

// FindStringMatch finds the first match in the input string.
// Returns nil match (not error) when no match is found.
func (cr *CompiledRegex) FindStringMatch(s string) (*RegexMatch, error) {
	if cr.useRE2 && cr.re2Pattern != nil {
		loc := cr.re2Pattern.FindStringIndex(s)
		if loc == nil {
			return nil, nil // nolint:nilnil // nil match is valid "no match found" result
		}
		return &RegexMatch{
			Value: s[loc[0]:loc[1]],
			Index: loc[0],
		}, nil
	}

	// Use PCRE fallback
	match, err := cr.pcrePattern.FindStringMatch(s)
	if err != nil {
		return nil, fmt.Errorf("pcre match error: %w", err)
	}
	if match == nil {
		return nil, nil // nolint:nilnil // nil match is valid "no match found" result
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
	matched, err := cr.pcrePattern.MatchString(s)
	if err != nil {
		return false, fmt.Errorf("pcre match error: %w", err)
	}
	return matched, nil
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
