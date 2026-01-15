// Package intel provides threat intelligence data structures for Wordfence CLI
package intel

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nickcampbell/wordfence-go/internal/api"
)

// CommonString represents a string shared across multiple signatures
type CommonString struct {
	String       string
	SignatureIDs []int
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
	ID            int
	Rule          string // PCRE pattern
	Name          string
	Description   string
	CommonStrings []int // Indices into SignatureSet.CommonStrings
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

// ParseSignatureSet parses a signature set from the API response
func ParseSignatureSet(resp *api.GetPatternsResponse) (*SignatureSet, error) {
	ss := NewSignatureSet()
	ss.UpdateTime = resp.SignatureUpdateTime

	// Parse common strings
	for _, s := range resp.CommonStrings {
		ss.CommonStrings = append(ss.CommonStrings, NewCommonString(s))
	}

	// Parse rules
	for _, rawRule := range resp.Rules {
		rule, err := api.ParseSignatureRule(rawRule)
		if err != nil {
			return nil, fmt.Errorf("failed to parse signature rule: %w", err)
		}

		// Skip non-malware rules (Type != 0)
		if rule.Type != 0 {
			continue
		}

		// Skip disabled rules (Enabled != 0)
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
	return json.Marshal(struct {
		CommonStrings []*CommonString    `json:"common_strings"`
		Signatures    map[int]*Signature `json:"signatures"`
		UpdateTime    int64              `json:"update_time"`
	}{
		CommonStrings: ss.CommonStrings,
		Signatures:    ss.Signatures,
		UpdateTime:    ss.UpdateTime,
	})
}

// UnmarshalJSON implements json.Unmarshaler for SignatureSet
func (ss *SignatureSet) UnmarshalJSON(data []byte) error {
	var v struct {
		CommonStrings []*CommonString    `json:"common_strings"`
		Signatures    map[int]*Signature `json:"signatures"`
		UpdateTime    int64              `json:"update_time"`
	}

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	ss.CommonStrings = v.CommonStrings
	ss.Signatures = v.Signatures
	ss.UpdateTime = v.UpdateTime

	return nil
}
