// Package api provides NOC1 API client for Wordfence
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/nickcampbell/wordfence-go/internal/logging"
)

// NOC1BaseURL is the default NOC1 API base URL
const NOC1BaseURL = "https://noc1.wordfence.com/v2.27/"

// NOC1Client is a client for the Wordfence NOC1 API
type NOC1Client struct {
	*Client
	License *License
}

// NOC1Option is a function that configures a NOC1Client
type NOC1Option func(*NOC1Client)

// WithNOC1License sets the license for the NOC1 client
func WithNOC1License(license *License) NOC1Option {
	return func(c *NOC1Client) {
		c.License = license
	}
}

// WithNOC1Logger sets the logger for the NOC1 client
func WithNOC1Logger(logger *logging.Logger) NOC1Option {
	return func(c *NOC1Client) {
		c.Logger = logger
	}
}

// NewNOC1Client creates a new NOC1 API client
func NewNOC1Client(opts ...NOC1Option) *NOC1Client {
	c := &NOC1Client{
		Client: NewClient(NOC1BaseURL),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// buildQuery builds the query parameters for an API request
func (c *NOC1Client) buildQuery(action string, extraParams url.Values) url.Values {
	query := url.Values{}
	query.Set("action", action)
	query.Set("cli", "1")
	query.Set("s", "{}") // Empty site stats JSON

	if c.License != nil {
		query.Set("k", c.License.Key)
	}

	for k, v := range extraParams {
		for _, val := range v {
			query.Set(k, val)
		}
	}

	return query
}

// request makes a request to the NOC1 API
func (c *NOC1Client) request(ctx context.Context, action string, extraParams url.Values) ([]byte, error) {
	query := c.buildQuery(action, extraParams)
	path := "?" + query.Encode()

	resp, err := c.Get(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("NOC1 API request failed: %w", err)
	}

	return resp, nil
}

// requestJSON makes a request and parses the JSON response
func (c *NOC1Client) requestJSON(ctx context.Context, action string, extraParams url.Values, result interface{}) error {
	resp, err := c.request(ctx, action, extraParams)
	if err != nil {
		return err
	}

	// Check for error message in response
	var errResp struct {
		ErrorMsg string `json:"errorMsg"`
	}
	if err := json.Unmarshal(resp, &errResp); err == nil && errResp.ErrorMsg != "" {
		return &APIError{
			Action:  action,
			Message: errResp.ErrorMsg,
		}
	}

	if err := json.Unmarshal(resp, result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	return nil
}

// PingAPIKeyResponse is the response from ping_api_key
type PingAPIKeyResponse struct {
	OK         int  `json:"ok"`
	IsPaidKey  bool `json:"_isPaidKey"`
}

// PingAPIKey validates the license key
func (c *NOC1Client) PingAPIKey(ctx context.Context) (bool, error) {
	if c.License == nil {
		return false, fmt.Errorf("no license configured")
	}

	var resp PingAPIKeyResponse
	if err := c.requestJSON(ctx, "ping_api_key", nil, &resp); err != nil {
		return false, err
	}

	// Update license paid status
	c.License.Paid = resp.IsPaidKey

	return resp.OK == 1, nil
}

// GetCLIAPIKeyResponse is the response from get_cli_api_key
type GetCLIAPIKeyResponse struct {
	APIKey string `json:"apiKey"`
}

// GetCLIAPIKey converts a site license key to a CLI license key
func (c *NOC1Client) GetCLIAPIKey(ctx context.Context, acceptTerms bool) (string, error) {
	params := url.Values{}
	if acceptTerms {
		params.Set("accept_terms", "1")
	} else {
		params.Set("accept_terms", "0")
	}

	var resp GetCLIAPIKeyResponse
	if err := c.requestJSON(ctx, "get_cli_api_key", params, &resp); err != nil {
		return "", err
	}

	return resp.APIKey, nil
}

// GetTermsResponse is the response from get_terms
type GetTermsResponse struct {
	Terms string `json:"terms"`
}

// GetTerms retrieves the terms of service
func (c *NOC1Client) GetTerms(ctx context.Context) (string, error) {
	var resp GetTermsResponse
	if err := c.requestJSON(ctx, "get_terms", nil, &resp); err != nil {
		return "", err
	}

	return resp.Terms, nil
}

// RecordTOUPPResponse is the response from record_toupp
type RecordTOUPPResponse struct {
	OK int `json:"ok"`
}

// RecordTOUPP records acceptance of terms of use / privacy policy
func (c *NOC1Client) RecordTOUPP(ctx context.Context) (bool, error) {
	var resp RecordTOUPPResponse
	if err := c.requestJSON(ctx, "record_toupp", nil, &resp); err != nil {
		return false, err
	}

	return resp.OK == 1, nil
}

// GetPatternsResponse is the response from get_patterns
type GetPatternsResponse struct {
	BadStrings          []string          `json:"badstrings"`
	CommonStrings       []string          `json:"commonStrings"`
	Rules               []json.RawMessage `json:"rules"`
	SignatureUpdateTime int64             `json:"signatureUpdateTime"`
	Word1               string            `json:"word1"`
	Word2               string            `json:"word2"`
	Word3               string            `json:"word3"`
	IsPaidKey           bool              `json:"_isPaidKey"`
}

// SignatureRule represents a malware signature rule
type SignatureRule struct {
	ID            int    // Index 0
	Type          int    // Index 1 (0 = malware, non-zero = other)
	Rule          string // Index 2 - PCRE pattern
	Category      string // Index 3
	Description   string // Index 4
	Enabled       int    // Index 5 (0 = enabled)
	Name          string // Index 6
	LogDescription string // Index 7
	CommonStrings []int  // Index 8 - Indices into commonStrings array
}

// ParseSignatureRule parses a signature rule from JSON array
func ParseSignatureRule(raw json.RawMessage) (*SignatureRule, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("failed to parse rule array: %w", err)
	}

	if len(arr) < 9 {
		return nil, fmt.Errorf("rule array has %d elements, expected 9", len(arr))
	}

	rule := &SignatureRule{}

	// Parse each field
	if err := json.Unmarshal(arr[0], &rule.ID); err != nil {
		return nil, fmt.Errorf("failed to parse rule ID: %w", err)
	}
	if err := json.Unmarshal(arr[1], &rule.Type); err != nil {
		return nil, fmt.Errorf("failed to parse rule type: %w", err)
	}
	if err := json.Unmarshal(arr[2], &rule.Rule); err != nil {
		return nil, fmt.Errorf("failed to parse rule pattern: %w", err)
	}
	if err := json.Unmarshal(arr[3], &rule.Category); err != nil {
		return nil, fmt.Errorf("failed to parse rule category: %w", err)
	}
	if err := json.Unmarshal(arr[4], &rule.Description); err != nil {
		return nil, fmt.Errorf("failed to parse rule description: %w", err)
	}
	if err := json.Unmarshal(arr[5], &rule.Enabled); err != nil {
		return nil, fmt.Errorf("failed to parse rule enabled: %w", err)
	}
	if err := json.Unmarshal(arr[6], &rule.Name); err != nil {
		return nil, fmt.Errorf("failed to parse rule name: %w", err)
	}
	if err := json.Unmarshal(arr[7], &rule.LogDescription); err != nil {
		return nil, fmt.Errorf("failed to parse rule log description: %w", err)
	}
	if err := json.Unmarshal(arr[8], &rule.CommonStrings); err != nil {
		return nil, fmt.Errorf("failed to parse rule common strings: %w", err)
	}

	return rule, nil
}

// GetPatterns retrieves malware signature patterns
func (c *NOC1Client) GetPatterns(ctx context.Context) (*GetPatternsResponse, error) {
	var resp GetPatternsResponse
	if err := c.requestJSON(ctx, "get_patterns", nil, &resp); err != nil {
		return nil, err
	}

	// Update license paid status
	if c.License != nil {
		c.License.Paid = resp.IsPaidKey
	}

	return &resp, nil
}

// GetPatternsWithTimeout retrieves patterns with a custom timeout
func (c *NOC1Client) GetPatternsWithTimeout(ctx context.Context, timeout time.Duration) (*GetPatternsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return c.GetPatterns(ctx)
}

// APIError represents an error from the NOC1 API
type APIError struct {
	Action  string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("NOC1 API error (%s): %s", e.Action, e.Message)
}

// IsAPIError checks if an error is an APIError
func IsAPIError(err error) (*APIError, bool) {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr, true
	}
	return nil, false
}
