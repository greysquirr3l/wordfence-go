// Package intel provides threat intelligence data structures for Wordfence CLI
package intel

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

// CommonString represents a string shared across multiple signatures
type CommonString struct {
	String       string `json:"string"`
	SignatureIDs []int  `json:"signature_ids"`
}

// NewCommonString creates a new CommonString
func NewCommonString(s string) *CommonString {
	return &CommonString{
		String:       s,
		SignatureIDs: make([]int, 0),
	}
}

// Signature represents a malware detection signature
type Signature struct {
	ID            int    `json:"id"`
	Rule          string `json:"rule"` // PCRE pattern
	Name          string `json:"name"`
	Description   string `json:"description"`
	CommonStrings []int  `json:"common_strings"` // Indices into SignatureSet.CommonStrings
}

// NewSignature creates a new Signature
func NewSignature(id int, rule, name, description string, commonStrings []int) *Signature {
	return &Signature{
		ID:            id,
		Rule:          rule,
		Name:          name,
		Description:   description,
		CommonStrings: commonStrings,
	}
}

// HasCommonStrings returns true if the signature has common strings for optimization
func (s *Signature) HasCommonStrings() bool {
	return len(s.CommonStrings) > 0
}

// GetCommonStringCount returns the number of common strings
func (s *Signature) GetCommonStringCount() int {
	return len(s.CommonStrings)
}

// SignatureSet represents a set of malware signatures
type SignatureSet struct {
	CommonStrings []*CommonString
	Signatures    map[int]*Signature
	UpdateTime    int64
}

// NewSignatureSet creates a new SignatureSet
func NewSignatureSet() *SignatureSet {
	return &SignatureSet{
		CommonStrings: make([]*CommonString, 0),
		Signatures:    make(map[int]*Signature),
	}
}

// GetSignature returns a signature by ID
func (ss *SignatureSet) GetSignature(id int) (*Signature, error) {
	sig, ok := ss.Signatures[id]
	if !ok {
		return nil, fmt.Errorf("invalid signature identifier: %d", id)
	}
	return sig, nil
}

// HasSignature checks if a signature exists
func (ss *SignatureSet) HasSignature(id int) bool {
	_, ok := ss.Signatures[id]
	return ok
}

// RemoveSignature removes a signature from the set
func (ss *SignatureSet) RemoveSignature(id int) bool {
	sig, ok := ss.Signatures[id]
	if !ok {
		return false
	}

	// Remove signature ID from common strings
	for _, idx := range sig.CommonStrings {
		if idx < len(ss.CommonStrings) {
			cs := ss.CommonStrings[idx]
			// Remove id from SignatureIDs
			newIDs := make([]int, 0, len(cs.SignatureIDs)-1)
			for _, sigID := range cs.SignatureIDs {
				if sigID != id {
					newIDs = append(newIDs, sigID)
				}
			}
			cs.SignatureIDs = newIDs
		}
	}

	delete(ss.Signatures, id)
	return true
}

// Count returns the number of signatures
func (ss *SignatureSet) Count() int {
	return len(ss.Signatures)
}

// GetHash returns a hash of the signature set for cache invalidation
func (ss *SignatureSet) GetHash() []byte {
	h := sha256.New()
	delimiter := ";"

	for _, sig := range ss.Signatures {
		// Build common strings portion
		commonStrs := make([]string, 0, len(sig.CommonStrings))
		for _, idx := range sig.CommonStrings {
			if idx < len(ss.CommonStrings) {
				commonStrs = append(commonStrs, ss.CommonStrings[idx].String)
			}
		}

		data := fmt.Sprintf("%d%s%s%s%s",
			sig.ID,
			delimiter,
			sig.Rule,
			delimiter,
			strings.Join(commonStrs, delimiter),
		)
		h.Write([]byte(data))
	}

	return h.Sum(nil)
}

// GetCommonStringsForSignature returns the common strings for a signature
func (ss *SignatureSet) GetCommonStringsForSignature(sig *Signature) []string {
	result := make([]string, 0, len(sig.CommonStrings))
	for _, idx := range sig.CommonStrings {
		if idx < len(ss.CommonStrings) {
			result = append(result, ss.CommonStrings[idx].String)
		}
	}
	return result
}

// RawSignatureRule contains the parsed fields of a signature rule
// This is used to avoid import cycles between intel and api packages
type RawSignatureRule struct {
	ID             int
	Type           int    // 0 = malware, non-zero = other
	Rule           string // PCRE pattern
	Category       string
	Description    string
	Enabled        int // 0 = enabled
	Name           string
	LogDescription string
	CommonStrings  []int
}

// ParseSignatureSet parses a signature set from raw API response data
func ParseSignatureSet(commonStrings []string, rules []*RawSignatureRule, updateTime int64) (*SignatureSet, error) {
	ss := NewSignatureSet()
	ss.UpdateTime = updateTime

	// Parse common strings
	for _, s := range commonStrings {
		ss.CommonStrings = append(ss.CommonStrings, NewCommonString(s))
	}

	// Parse rules
	for _, rule := range rules {
		// Skip disabled rules (Enabled != 0 means disabled)
		if rule.Enabled != 0 {
			continue
		}

		sig := NewSignature(
			rule.ID,
			rule.Rule,
			rule.LogDescription, // LogDescription is the human-readable name
			rule.Description,
			rule.CommonStrings,
		)

		ss.Signatures[sig.ID] = sig

		// Update common string associations
		for _, idx := range rule.CommonStrings {
			if idx >= 0 && idx < len(ss.CommonStrings) {
				ss.CommonStrings[idx].SignatureIDs = append(ss.CommonStrings[idx].SignatureIDs, sig.ID)
			}
		}
	}

	return ss, nil
}

// MarshalJSON implements json.Marshaler for SignatureSet
func (ss *SignatureSet) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(struct {
		CommonStrings []*CommonString    `json:"common_strings"`
		Signatures    map[int]*Signature `json:"signatures"`
		UpdateTime    int64              `json:"update_time"`
	}{
		CommonStrings: ss.CommonStrings,
		Signatures:    ss.Signatures,
		UpdateTime:    ss.UpdateTime,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling signature set: %w", err)
	}
	return data, nil
}

// UnmarshalJSON implements json.Unmarshaler for SignatureSet
func (ss *SignatureSet) UnmarshalJSON(data []byte) error {
	var v struct {
		CommonStrings []*CommonString    `json:"common_strings"`
		Signatures    map[int]*Signature `json:"signatures"`
		UpdateTime    int64              `json:"update_time"`
	}

	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("unmarshaling signature set: %w", err)
	}

	ss.CommonStrings = v.CommonStrings
	ss.Signatures = v.Signatures
	ss.UpdateTime = v.UpdateTime

	return nil
}

// ParseRawAPIResponse parses the raw API response format from get_patterns
// The format is: rules: array of [id, timestamp, rule, description, scope, enabled, category, name, commonStrings[]]
func ParseRawAPIResponse(data []byte) (*SignatureSet, error) {
	var resp struct {
		Rules               []json.RawMessage `json:"rules"`
		CommonStrings       []string          `json:"commonStrings"`
		SignatureUpdateTime int64             `json:"signatureUpdateTime"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	// Convert to RawSignatureRule format
	rules := make([]*RawSignatureRule, 0, len(resp.Rules))
	for _, rawRule := range resp.Rules {
		var arr []json.RawMessage
		if err := json.Unmarshal(rawRule, &arr); err != nil {
			continue // Skip malformed rules
		}

		if len(arr) < 9 {
			continue
		}

		rule := &RawSignatureRule{}

		// Parse each field: [id, timestamp, rule, description, scope, enabled, category, name, commonStrings[]]
		if err := json.Unmarshal(arr[0], &rule.ID); err != nil {
			continue
		}
		// arr[1] is timestamp, skip
		if err := json.Unmarshal(arr[2], &rule.Rule); err != nil {
			continue
		}
		if err := json.Unmarshal(arr[3], &rule.Description); err != nil {
			continue
		}
		// arr[4] is scope, skip
		if err := json.Unmarshal(arr[5], &rule.Enabled); err != nil {
			continue
		}
		if err := json.Unmarshal(arr[6], &rule.Category); err != nil {
			continue
		}
		if err := json.Unmarshal(arr[7], &rule.LogDescription); err != nil {
			continue
		}
		if err := json.Unmarshal(arr[8], &rule.CommonStrings); err != nil {
			rule.CommonStrings = []int{} // Default to empty
		}

		// The API format uses enabled=0 for enabled, non-zero for disabled
		// Type is not in this format, default to 0 (malware)
		rule.Type = 0

		rules = append(rules, rule)
	}

	return ParseSignatureSet(resp.CommonStrings, rules, resp.SignatureUpdateTime)
}
