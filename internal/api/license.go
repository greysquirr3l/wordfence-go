// Package api provides license management for Wordfence CLI
package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LicenseURL is the URL to obtain a Wordfence CLI license
const LicenseURL = "https://www.wordfence.com/products/wordfence-cli/"

// License represents a Wordfence CLI license
type License struct {
	Key  string
	Paid bool
}

// NewLicense creates a new license with the given key
func NewLicense(key string) *License {
	return &License{
		Key:  strings.TrimSpace(key),
		Paid: false,
	}
}

// String returns the license key
func (l *License) String() string {
	return l.Key
}

// IsValid checks if the license key has a valid format
func (l *License) IsValid() bool {
	// License keys are typically 32+ character hex strings
	key := strings.TrimSpace(l.Key)
	if len(key) < 32 {
		return false
	}
	
	// Check if it's a valid hex string
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	
	return true
}

// LicenseManager handles license loading and validation
type LicenseManager struct {
	noc1 *NOC1Client
}

// NewLicenseManager creates a new license manager
func NewLicenseManager(noc1 *NOC1Client) *LicenseManager {
	return &LicenseManager{
		noc1: noc1,
	}
}

// LoadFromEnv loads the license from environment variables
func LoadFromEnv() (*License, error) {
	key := os.Getenv("WORDFENCE_CLI_LICENSE")
	if key == "" {
		return nil, nil // No license in env
	}
	return NewLicense(key), nil
}

// LoadFromFile loads the license from the default config file
func LoadFromFile() (*License, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}

	// Check standard config file locations
	configPaths := []string{
		filepath.Join(configDir, "wordfence", "wordfence-cli.ini"),
		filepath.Join(os.Getenv("HOME"), ".config", "wordfence", "wordfence-cli.ini"),
		"/etc/wordfence/wordfence-cli.ini",
	}

	for _, path := range configPaths {
		license, err := loadFromINIFile(path)
		if err != nil {
			continue // Try next path
		}
		if license != nil {
			return license, nil
		}
	}

	return nil, nil // No license found
}

// loadFromINIFile loads the license from an INI file
func loadFromINIFile(path string) (*License, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Simple INI parsing for license key
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "license") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return NewLicense(strings.TrimSpace(parts[1])), nil
			}
		}
	}

	return nil, nil
}

// Validate validates the license against the Wordfence API
func (m *LicenseManager) Validate(ctx context.Context, license *License) error {
	if license == nil {
		return fmt.Errorf("no license provided")
	}

	if !license.IsValid() {
		return fmt.Errorf("invalid license key format")
	}

	// Set the license on the NOC1 client
	m.noc1.License = license

	// Ping the API to validate
	valid, err := m.noc1.PingAPIKey(ctx)
	if err != nil {
		return fmt.Errorf("license validation failed: %w", err)
	}

	if !valid {
		return fmt.Errorf("license key is not valid")
	}

	return nil
}

// ConvertSiteLicense converts a site license to a CLI license
func (m *LicenseManager) ConvertSiteLicense(ctx context.Context, siteLicense *License, acceptTerms bool) (*License, error) {
	// Set the site license on the client
	m.noc1.License = siteLicense

	// Get the CLI API key
	cliKey, err := m.noc1.GetCLIAPIKey(ctx, acceptTerms)
	if err != nil {
		return nil, fmt.Errorf("failed to convert site license: %w", err)
	}

	return NewLicense(cliKey), nil
}

// LicenseRequiredError indicates that a license is required
type LicenseRequiredError struct{}

func (e LicenseRequiredError) Error() string {
	return fmt.Sprintf("a valid Wordfence CLI license is required; obtain one at %s", LicenseURL)
}

// NewLicenseRequiredError creates a new LicenseRequiredError
func NewLicenseRequiredError() error {
	return LicenseRequiredError{}
}

// IsLicenseRequiredError checks if an error is a LicenseRequiredError
func IsLicenseRequiredError(err error) bool {
	_, ok := err.(LicenseRequiredError)
	return ok
}
