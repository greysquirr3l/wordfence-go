package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/greysquirr3l/wordfence-go/internal/intel"
)

func createTestSignatureSet() *intel.SignatureSet {
	ss := intel.NewSignatureSet()

	// Add common strings
	ss.CommonStrings = append(ss.CommonStrings, intel.NewCommonString("eval"))
	ss.CommonStrings = append(ss.CommonStrings, intel.NewCommonString("base64_decode"))

	// Add test signatures
	ss.Signatures[1] = intel.NewSignature(
		1,
		`eval\s*\(`,
		"Eval Pattern",
		"Detects eval() calls",
		[]int{0},
	)
	ss.CommonStrings[0].SignatureIDs = append(ss.CommonStrings[0].SignatureIDs, 1)

	ss.Signatures[2] = intel.NewSignature(
		2,
		`base64_decode\s*\(`,
		"Base64 Decode",
		"Detects base64_decode() calls",
		[]int{1},
	)
	ss.CommonStrings[1].SignatureIDs = append(ss.CommonStrings[1].SignatureIDs, 2)

	ss.Signatures[3] = intel.NewSignature(
		3,
		`system\s*\(`,
		"System Call",
		"Detects system() calls",
		[]int{}, // No common strings
	)

	return ss
}

func TestMatcherCreation(t *testing.T) {
	ss := createTestSignatureSet()
	m := NewMatcher(ss)

	if m == nil {
		t.Fatal("expected matcher to be created")
	}

	if len(m.signatures) != 3 {
		t.Errorf("expected 3 compiled signatures, got %d", len(m.signatures))
	}

	if len(m.commonStrings) != 2 {
		t.Errorf("expected 2 common strings, got %d", len(m.commonStrings))
	}
}

func TestMatcherWithOptions(t *testing.T) {
	ss := createTestSignatureSet()

	timeout := 500 * time.Millisecond
	m := NewMatcher(ss,
		WithMatchTimeout(timeout),
		WithMatchAll(true),
	)

	if m.timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, m.timeout)
	}

	if !m.matchAll {
		t.Error("expected matchAll to be true")
	}
}

func TestMatchContextBasicMatch(t *testing.T) {
	ss := createTestSignatureSet()
	m := NewMatcher(ss)

	ctx := context.Background()
	content := []byte(`<?php eval($_POST['cmd']); ?>`)

	mc := m.NewMatchContext()
	if err := mc.Match(ctx, content); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mc.HasMatches() {
		t.Error("expected matches")
	}

	matches := mc.GetMatches()
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}

	// Should match signature 1 (eval pattern)
	found := false
	for _, match := range matches {
		if match.SignatureID == 1 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected signature 1 to match")
	}
}

func TestMatchContextNoCommonStringSignature(t *testing.T) {
	ss := createTestSignatureSet()
	m := NewMatcher(ss)

	ctx := context.Background()
	content := []byte(`<?php system('whoami'); ?>`)

	mc := m.NewMatchContext()
	if err := mc.Match(ctx, content); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mc.HasMatches() {
		t.Error("expected matches")
	}

	matches := mc.GetMatches()
	found := false
	for _, match := range matches {
		if match.SignatureID == 3 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected signature 3 (system) to match")
	}
}

func TestMatchContextMultipleMatches(t *testing.T) {
	ss := createTestSignatureSet()
	m := NewMatcher(ss, WithMatchAll(true))

	ctx := context.Background()
	content := []byte(`<?php
		eval(base64_decode($_POST['cmd']));
		system('ls');
	?>`)

	mc := m.NewMatchContext()
	if err := mc.Match(ctx, content); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	matches := mc.GetMatches()
	if len(matches) < 3 {
		t.Errorf("expected at least 3 matches (eval, base64_decode, system), got %d", len(matches))
	}
}

func TestMatchContextNoMatch(t *testing.T) {
	ss := createTestSignatureSet()
	m := NewMatcher(ss)

	ctx := context.Background()
	content := []byte(`<?php echo "Hello World"; ?>`)

	mc := m.NewMatchContext()
	if err := mc.Match(ctx, content); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mc.HasMatches() {
		t.Error("expected no matches")
	}

	if mc.MatchCount() != 0 {
		t.Errorf("expected match count 0, got %d", mc.MatchCount())
	}
}

func TestMatchContextCancellation(t *testing.T) {
	ss := createTestSignatureSet()
	m := NewMatcher(ss)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	content := []byte(`<?php eval($_POST['cmd']); ?>`)

	mc := m.NewMatchContext()
	err := mc.Match(ctx, content)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func TestMatchResultFields(t *testing.T) {
	ss := createTestSignatureSet()
	m := NewMatcher(ss)

	ctx := context.Background()
	content := []byte(`<?php eval('test'); ?>`)

	mc := m.NewMatchContext()
	_ = mc.Match(ctx, content)

	matches := mc.GetMatches()
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}

	match := matches[0]
	if match.SignatureID != 1 {
		t.Errorf("expected signature ID 1, got %d", match.SignatureID)
	}
	if match.MatchedString == "" {
		t.Error("expected matched string to be set")
	}
	if match.Position < 0 {
		t.Error("expected position to be non-negative")
	}
}

func TestErrMatchTimeout(t *testing.T) {
	err := &ErrMatchTimeout{SignatureID: 42}
	expected := "match timeout for signature 42"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestMatcherComplexPatterns(t *testing.T) {
	ss := intel.NewSignatureSet()

	// Pattern with lookahead
	ss.Signatures[1] = intel.NewSignature(
		1,
		`(?i)passw(?=ord|d)`,
		"Password Pattern",
		"Matches password variations",
		[]int{},
	)

	// Case insensitive pattern
	ss.Signatures[2] = intel.NewSignature(
		2,
		`(?i)shell_exec`,
		"Shell Exec",
		"Detects shell_exec",
		[]int{},
	)

	m := NewMatcher(ss, WithMatchAll(true))
	ctx := context.Background()

	tests := []struct {
		name       string
		content    string
		expectedID int
		shouldFind bool
	}{
		{"password match", "The password is secret", 1, true},
		{"SHELL_EXEC uppercase", "<?php SHELL_EXEC('ls'); ?>", 2, true},
		{"shell_exec lowercase", "<?php shell_exec('ls'); ?>", 2, true},
		{"no match", "This is clean code", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := m.NewMatchContext()
			_ = mc.Match(ctx, []byte(tt.content))

			if tt.shouldFind {
				found := false
				for _, match := range mc.GetMatches() {
					if match.SignatureID == tt.expectedID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected to find signature %d", tt.expectedID)
				}
			} else {
				if mc.HasMatches() {
					t.Error("expected no matches")
				}
			}
		})
	}
}
