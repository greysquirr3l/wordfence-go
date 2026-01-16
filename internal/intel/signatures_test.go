package intel

import (
	"encoding/json"
	"testing"
)

func TestNewSignature(t *testing.T) {
	sig := NewSignature(1, "test.*pattern", "Test Signature", "A test signature", []int{0, 1})

	if sig.ID != 1 {
		t.Errorf("expected ID 1, got %d", sig.ID)
	}
	if sig.Rule != "test.*pattern" {
		t.Errorf("expected rule 'test.*pattern', got %s", sig.Rule)
	}
	if sig.Name != "Test Signature" {
		t.Errorf("expected name 'Test Signature', got %s", sig.Name)
	}
	if sig.Description != "A test signature" {
		t.Errorf("expected description 'A test signature', got %s", sig.Description)
	}
	if len(sig.CommonStrings) != 2 {
		t.Errorf("expected 2 common strings, got %d", len(sig.CommonStrings))
	}
}

func TestSignatureHasCommonStrings(t *testing.T) {
	sigWithCS := NewSignature(1, "test", "Test", "", []int{0, 1})
	sigWithoutCS := NewSignature(2, "test", "Test", "", []int{})

	if !sigWithCS.HasCommonStrings() {
		t.Error("expected signature with common strings to return true")
	}
	if sigWithoutCS.HasCommonStrings() {
		t.Error("expected signature without common strings to return false")
	}
}

func TestNewSignatureSet(t *testing.T) {
	ss := NewSignatureSet()

	if ss.CommonStrings == nil {
		t.Error("expected CommonStrings to be initialized")
	}
	if ss.Signatures == nil {
		t.Error("expected Signatures to be initialized")
	}
	if len(ss.Signatures) != 0 {
		t.Errorf("expected empty signatures, got %d", len(ss.Signatures))
	}
}

func TestSignatureSetOperations(t *testing.T) {
	ss := NewSignatureSet()

	// Add common strings
	ss.CommonStrings = append(ss.CommonStrings, NewCommonString("eval"))
	ss.CommonStrings = append(ss.CommonStrings, NewCommonString("base64"))

	// Add signature
	sig := NewSignature(123, "eval.*base64", "Base64 Eval", "Suspicious eval with base64", []int{0, 1})
	ss.Signatures[sig.ID] = sig
	ss.CommonStrings[0].SignatureIDs = append(ss.CommonStrings[0].SignatureIDs, 123)
	ss.CommonStrings[1].SignatureIDs = append(ss.CommonStrings[1].SignatureIDs, 123)

	// Test GetSignature
	retrieved, err := ss.GetSignature(123)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if retrieved.ID != 123 {
		t.Errorf("expected signature ID 123, got %d", retrieved.ID)
	}

	// Test GetSignature with invalid ID
	_, err = ss.GetSignature(999)
	if err == nil {
		t.Error("expected error for invalid signature ID")
	}

	// Test HasSignature
	if !ss.HasSignature(123) {
		t.Error("expected HasSignature(123) to return true")
	}
	if ss.HasSignature(999) {
		t.Error("expected HasSignature(999) to return false")
	}

	// Test Count
	if ss.Count() != 1 {
		t.Errorf("expected count 1, got %d", ss.Count())
	}

	// Test RemoveSignature
	if !ss.RemoveSignature(123) {
		t.Error("expected RemoveSignature to return true")
	}
	if ss.HasSignature(123) {
		t.Error("expected signature to be removed")
	}
	if ss.Count() != 0 {
		t.Errorf("expected count 0 after removal, got %d", ss.Count())
	}

	// Verify common string associations were cleaned up
	if len(ss.CommonStrings[0].SignatureIDs) != 0 {
		t.Errorf("expected common string 0 to have no signatures, got %d", len(ss.CommonStrings[0].SignatureIDs))
	}
}

func TestSignatureSetGetCommonStringsForSignature(t *testing.T) {
	ss := NewSignatureSet()
	ss.CommonStrings = append(ss.CommonStrings, NewCommonString("eval"))
	ss.CommonStrings = append(ss.CommonStrings, NewCommonString("base64"))
	ss.CommonStrings = append(ss.CommonStrings, NewCommonString("exec"))

	sig := NewSignature(1, "test", "Test", "", []int{0, 2})

	strings := ss.GetCommonStringsForSignature(sig)
	if len(strings) != 2 {
		t.Errorf("expected 2 strings, got %d", len(strings))
	}
	if strings[0] != "eval" {
		t.Errorf("expected 'eval', got %s", strings[0])
	}
	if strings[1] != "exec" {
		t.Errorf("expected 'exec', got %s", strings[1])
	}
}

func TestParseSignatureSet(t *testing.T) {
	commonStrings := []string{"eval", "base64_decode"}
	rules := []*RawSignatureRule{
		{
			ID:             1,
			Type:           0,
			Rule:           "eval\\s*\\(",
			Category:       "malware",
			Description:    "Suspicious eval",
			Enabled:        0, // 0 means enabled
			Name:           "eval_detected",
			LogDescription: "Eval Detected",
			CommonStrings:  []int{0},
		},
		{
			ID:             2,
			Type:           0,
			Rule:           "base64_decode\\s*\\(",
			Category:       "malware",
			Description:    "Base64 decode",
			Enabled:        0,
			Name:           "base64_detected",
			LogDescription: "Base64 Detected",
			CommonStrings:  []int{1},
		},
		{
			ID:             3,
			Type:           0,
			Rule:           "disabled_rule",
			Category:       "malware",
			Description:    "Disabled rule",
			Enabled:        1, // Non-zero means disabled
			Name:           "disabled",
			LogDescription: "Disabled",
			CommonStrings:  []int{},
		},
	}

	ss, err := ParseSignatureSet(commonStrings, rules, 12345)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check common strings
	if len(ss.CommonStrings) != 2 {
		t.Errorf("expected 2 common strings, got %d", len(ss.CommonStrings))
	}

	// Check signatures (should only have 2, as rule 3 is disabled)
	if ss.Count() != 2 {
		t.Errorf("expected 2 signatures, got %d", ss.Count())
	}

	// Check that disabled rule was skipped
	if ss.HasSignature(3) {
		t.Error("disabled rule should not be in signature set")
	}

	// Check update time
	if ss.UpdateTime != 12345 {
		t.Errorf("expected update time 12345, got %d", ss.UpdateTime)
	}

	// Check common string associations
	if len(ss.CommonStrings[0].SignatureIDs) != 1 || ss.CommonStrings[0].SignatureIDs[0] != 1 {
		t.Errorf("expected common string 0 to be associated with signature 1")
	}
}

func TestSignatureSetJSONSerialization(t *testing.T) {
	ss := NewSignatureSet()
	ss.CommonStrings = append(ss.CommonStrings, NewCommonString("test"))
	ss.Signatures[1] = NewSignature(1, "test", "Test", "Test desc", []int{0})
	ss.UpdateTime = 12345

	// Marshal to JSON
	data, err := json.Marshal(ss)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Unmarshal back
	var restored SignatureSet
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Verify
	if restored.Count() != 1 {
		t.Errorf("expected 1 signature, got %d", restored.Count())
	}
	if len(restored.CommonStrings) != 1 {
		t.Errorf("expected 1 common string, got %d", len(restored.CommonStrings))
	}
	if restored.UpdateTime != 12345 {
		t.Errorf("expected update time 12345, got %d", restored.UpdateTime)
	}
}

func TestSignatureSetGetHash(t *testing.T) {
	ss1 := NewSignatureSet()
	ss1.Signatures[1] = NewSignature(1, "test", "Test", "", []int{})

	ss2 := NewSignatureSet()
	ss2.Signatures[1] = NewSignature(1, "test", "Test", "", []int{})

	ss3 := NewSignatureSet()
	ss3.Signatures[1] = NewSignature(1, "different", "Test", "", []int{})

	hash1 := ss1.GetHash()
	hash2 := ss2.GetHash()
	hash3 := ss3.GetHash()

	// Same content should produce same hash
	if string(hash1) != string(hash2) {
		t.Error("identical signature sets should have same hash")
	}

	// Different content should produce different hash
	if string(hash1) == string(hash3) {
		t.Error("different signature sets should have different hashes")
	}
}
