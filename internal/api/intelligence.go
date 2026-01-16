// Package api provides the Intelligence API client for vulnerability data
package api //nolint:revive // api is a well-understood package name for API clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/greysquirr3l/wordfence-go/internal/intel"
	"github.com/greysquirr3l/wordfence-go/internal/logging"
)

// IntelligenceBaseURL is the default Intelligence API base URL
const IntelligenceBaseURL = "https://www.wordfence.com/api/intelligence/v2"

// IntelligenceClient is a client for the Wordfence Intelligence API
type IntelligenceClient struct {
	*Client
	License *License
}

// IntelligenceOption configures an IntelligenceClient
type IntelligenceOption func(*IntelligenceClient)

// WithIntelligenceLicense sets the license
func WithIntelligenceLicense(license *License) IntelligenceOption {
	return func(c *IntelligenceClient) {
		c.License = license
	}
}

// WithIntelligenceLogger sets the logger
func WithIntelligenceLogger(logger *logging.Logger) IntelligenceOption {
	return func(c *IntelligenceClient) {
		c.Logger = logger
	}
}

// NewIntelligenceClient creates a new Intelligence API client
func NewIntelligenceClient(opts ...IntelligenceOption) *IntelligenceClient {
	c := &IntelligenceClient{
		Client: NewClient(IntelligenceBaseURL),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// buildPath builds the API path with license key
func (c *IntelligenceClient) buildPath(endpoint string) string {
	if c.License != nil {
		return fmt.Sprintf("/%s/%s", c.License.Key, endpoint)
	}
	return "/" + endpoint
}

// GetScannerVulnerabilities fetches the scanner vulnerability feed
func (c *IntelligenceClient) GetScannerVulnerabilities(ctx context.Context) (*intel.VulnerabilityIndex, error) {
	path := c.buildPath("scanner")

	resp, err := c.Get(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch scanner vulnerabilities: %w", err)
	}

	index, err := intel.ParseVulnerabilityIndex(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vulnerability feed: %w", err)
	}

	return index, nil
}

// GetProductionVulnerabilities fetches the production vulnerability feed (more detailed)
func (c *IntelligenceClient) GetProductionVulnerabilities(ctx context.Context) (*intel.VulnerabilityIndex, error) {
	path := c.buildPath("production")

	resp, err := c.Get(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch production vulnerabilities: %w", err)
	}

	index, err := intel.ParseVulnerabilityIndex(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vulnerability feed: %w", err)
	}

	return index, nil
}

// GetSoftwareVulnerabilities fetches vulnerabilities for specific software
func (c *IntelligenceClient) GetSoftwareVulnerabilities(ctx context.Context, softwareType intel.SoftwareType, slug string) ([]*intel.Vulnerability, error) {
	params := url.Values{}
	params.Set("type", string(softwareType))
	params.Set("slug", slug)

	path := c.buildPath("software") + "?" + params.Encode()

	resp, err := c.Get(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch software vulnerabilities: %w", err)
	}

	var vulns []*intel.Vulnerability
	if err := json.Unmarshal(resp, &vulns); err != nil {
		return nil, fmt.Errorf("failed to parse software vulnerabilities: %w", err)
	}

	return vulns, nil
}
