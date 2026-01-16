// Package intel provides vulnerability data structures
package intel

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SoftwareType represents the type of WordPress software
type SoftwareType string

const (
	// SoftwareTypeCore represents WordPress core software
	SoftwareTypeCore SoftwareType = "core"
	// SoftwareTypePlugin represents a WordPress plugin
	SoftwareTypePlugin SoftwareType = "plugin"
	// SoftwareTypeTheme represents a WordPress theme
	SoftwareTypeTheme SoftwareType = "theme"
)

// VersionAny matches any version
const VersionAny = "*"

// VersionRange represents a range of affected versions
type VersionRange struct {
	FromVersion   string `json:"from_version"`
	FromInclusive bool   `json:"from_inclusive"`
	ToVersion     string `json:"to_version"`
	ToInclusive   bool   `json:"to_inclusive"`
}

// Includes checks if a version is within the range
func (vr *VersionRange) Includes(version string) bool {
	// Handle wildcard
	if vr.FromVersion == VersionAny && vr.ToVersion == VersionAny {
		return true
	}

	// Compare from version
	if vr.FromVersion != VersionAny {
		cmp := CompareVersions(vr.FromVersion, version)
		if cmp > 0 || (cmp == 0 && !vr.FromInclusive) {
			return false
		}
	}

	// Compare to version
	if vr.ToVersion != VersionAny {
		cmp := CompareVersions(vr.ToVersion, version)
		if cmp < 0 || (cmp == 0 && !vr.ToInclusive) {
			return false
		}
	}

	return true
}

// Software represents affected software
type Software struct {
	Type             SoftwareType             `json:"type"`
	Name             string                   `json:"name"`
	Slug             string                   `json:"slug"`
	AffectedVersions map[string]*VersionRange `json:"affected_versions"`
	Patched          bool                     `json:"patched"`
	PatchedVersions  []string                 `json:"patched_versions"`
}

// CVSS represents CVSS score information
type CVSS struct {
	Vector string  `json:"vector"`
	Score  float64 `json:"score"`
	Rating string  `json:"rating"`
}

// CWE represents a Common Weakness Enumeration
type CWE struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID            string      `json:"id"`
	Title         string      `json:"title"`
	Description   string      `json:"description"`
	Software      []*Software `json:"software"`
	Informational bool        `json:"informational"`
	References    []string    `json:"references"`
	Published     string      `json:"published"`
	Updated       string      `json:"updated"`
	CVE           string      `json:"cve"`
	CVSS          *CVSS       `json:"cvss"`
	CWE           *CWE        `json:"cwe"`
}

// GetWordfenceLink returns the Wordfence vulnerability page URL
func (v *Vulnerability) GetWordfenceLink() string {
	for _, ref := range v.References {
		if strings.Contains(ref, "wordfence.com") {
			// Add source parameter
			if strings.Contains(ref, "?") {
				return ref + "&source=cli-scan"
			}
			return ref + "?source=cli-scan"
		}
	}
	return ""
}

// IsAffected checks if the given software is affected by this vulnerability
func (v *Vulnerability) IsAffected(softwareType SoftwareType, slug, version string) *Software {
	for _, sw := range v.Software {
		if sw.Type != softwareType || sw.Slug != slug {
			continue
		}
		for _, vr := range sw.AffectedVersions {
			if vr.Includes(version) {
				return sw
			}
		}
	}
	return nil
}

// VulnerabilityIndex indexes vulnerabilities for quick lookup
type VulnerabilityIndex struct {
	vulnerabilities map[string]*Vulnerability
	byType          map[SoftwareType]map[string][]*indexEntry
}

type indexEntry struct {
	versionRange *VersionRange
	vulnID       string
}

// NewVulnerabilityIndex creates a new vulnerability index
func NewVulnerabilityIndex() *VulnerabilityIndex {
	return &VulnerabilityIndex{
		vulnerabilities: make(map[string]*Vulnerability),
		byType: map[SoftwareType]map[string][]*indexEntry{
			SoftwareTypeCore:   make(map[string][]*indexEntry),
			SoftwareTypePlugin: make(map[string][]*indexEntry),
			SoftwareTypeTheme:  make(map[string][]*indexEntry),
		},
	}
}

// Add adds a vulnerability to the index
func (vi *VulnerabilityIndex) Add(vuln *Vulnerability) {
	vi.vulnerabilities[vuln.ID] = vuln

	for _, sw := range vuln.Software {
		typeIndex := vi.byType[sw.Type]
		if typeIndex == nil {
			typeIndex = make(map[string][]*indexEntry)
			vi.byType[sw.Type] = typeIndex
		}

		for _, vr := range sw.AffectedVersions {
			entry := &indexEntry{
				versionRange: vr,
				vulnID:       vuln.ID,
			}
			typeIndex[sw.Slug] = append(typeIndex[sw.Slug], entry)
		}
	}
}

// Get retrieves a vulnerability by ID
func (vi *VulnerabilityIndex) Get(id string) *Vulnerability {
	return vi.vulnerabilities[id]
}

// Count returns the total number of vulnerabilities
func (vi *VulnerabilityIndex) Count() int {
	return len(vi.vulnerabilities)
}

// GetVulnerabilities returns all vulnerabilities affecting the given software
func (vi *VulnerabilityIndex) GetVulnerabilities(softwareType SoftwareType, slug, version string) []*Vulnerability {
	typeIndex := vi.byType[softwareType]
	if typeIndex == nil {
		return nil
	}

	entries := typeIndex[slug]
	if entries == nil {
		return nil
	}

	var result []*Vulnerability
	seen := make(map[string]bool)

	for _, entry := range entries {
		if seen[entry.vulnID] {
			continue
		}
		if entry.versionRange.Includes(version) {
			if vuln := vi.vulnerabilities[entry.vulnID]; vuln != nil {
				result = append(result, vuln)
				seen[entry.vulnID] = true
			}
		}
	}

	return result
}

// ParseVulnerabilityIndex parses vulnerabilities from the scanner feed
func ParseVulnerabilityIndex(data []byte) (*VulnerabilityIndex, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse vulnerability feed: %w", err)
	}

	index := NewVulnerabilityIndex()

	for id, rawVuln := range raw {
		vuln, err := parseVulnerability(id, rawVuln)
		if err != nil {
			continue // Skip invalid entries
		}
		index.Add(vuln)
	}

	return index, nil
}

func parseVulnerability(id string, data json.RawMessage) (*Vulnerability, error) {
	var v struct {
		Title         string   `json:"title"`
		Description   string   `json:"description"`
		Informational bool     `json:"informational"`
		Published     string   `json:"published"`
		Updated       string   `json:"updated"`
		CVE           string   `json:"cve"`
		References    []string `json:"references"`
		Software      []struct {
			Type             string   `json:"type"`
			Name             string   `json:"name"`
			Slug             string   `json:"slug"`
			Patched          bool     `json:"patched"`
			PatchedVersions  []string `json:"patched_versions"`
			AffectedVersions map[string]struct {
				FromVersion   string `json:"from_version"`
				FromInclusive bool   `json:"from_inclusive"`
				ToVersion     string `json:"to_version"`
				ToInclusive   bool   `json:"to_inclusive"`
			} `json:"affected_versions"`
		} `json:"software"`
		CVSS *struct {
			Vector string  `json:"vector"`
			Score  float64 `json:"score"`
			Rating string  `json:"rating"`
		} `json:"cvss"`
	}

	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parsing vulnerability data: %w", err)
	}

	vuln := &Vulnerability{
		ID:            id,
		Title:         v.Title,
		Description:   v.Description,
		Informational: v.Informational,
		Published:     v.Published,
		Updated:       v.Updated,
		CVE:           v.CVE,
		References:    v.References,
	}

	if v.CVSS != nil {
		vuln.CVSS = &CVSS{
			Vector: v.CVSS.Vector,
			Score:  v.CVSS.Score,
			Rating: v.CVSS.Rating,
		}
	}

	for _, sw := range v.Software {
		software := &Software{
			Type:             SoftwareType(sw.Type),
			Name:             sw.Name,
			Slug:             sw.Slug,
			Patched:          sw.Patched,
			PatchedVersions:  sw.PatchedVersions,
			AffectedVersions: make(map[string]*VersionRange),
		}

		for key, av := range sw.AffectedVersions {
			software.AffectedVersions[key] = &VersionRange{
				FromVersion:   av.FromVersion,
				FromInclusive: av.FromInclusive,
				ToVersion:     av.ToVersion,
				ToInclusive:   av.ToInclusive,
			}
		}

		vuln.Software = append(vuln.Software, software)
	}

	return vuln, nil
}

// CompareVersions compares two version strings
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func CompareVersions(v1, v2 string) int {
	// Normalize versions
	parts1 := normalizeVersion(v1)
	parts2 := normalizeVersion(v2)

	// Compare each part
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		if i < len(parts1) {
			p1 = parts1[i]
		}
		if i < len(parts2) {
			p2 = parts2[i]
		}

		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}

	return 0
}

// normalizeVersion splits a version string into comparable parts
func normalizeVersion(version string) []int {
	// Remove common suffixes
	version = strings.TrimPrefix(version, "v")

	// Split by common delimiters
	re := regexp.MustCompile(`[.\-_]`)
	parts := re.Split(version, -1)

	result := make([]int, 0, len(parts))
	for _, part := range parts {
		// Extract numeric portion
		numStr := ""
		for _, c := range part {
			if c >= '0' && c <= '9' {
				numStr += string(c)
			} else {
				break
			}
		}
		if numStr != "" {
			num, _ := strconv.Atoi(numStr)
			result = append(result, num)
		}
	}

	return result
}

// MarshalJSON implements json.Marshaler for VulnerabilityIndex
func (vi *VulnerabilityIndex) MarshalJSON() ([]byte, error) {
	// Marshal as a map of vulnerability ID -> vulnerability
	data, err := json.Marshal(vi.vulnerabilities)
	if err != nil {
		return nil, fmt.Errorf("marshaling vulnerability index: %w", err)
	}
	return data, nil
}

// UnmarshalJSON implements json.Unmarshaler for VulnerabilityIndex
func (vi *VulnerabilityIndex) UnmarshalJSON(data []byte) error {
	// Parse as the raw format and rebuild the index
	index, err := ParseVulnerabilityIndex(data)
	if err != nil {
		return fmt.Errorf("unmarshaling vulnerability index: %w", err)
	}
	vi.vulnerabilities = index.vulnerabilities
	vi.byType = index.byType
	return nil
}
