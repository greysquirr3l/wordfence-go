// Package api provides NOC1 API client for Wordfence
package api //nolint:revive // api is a well-understood package name for API clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/greysquirr3l/wordfence-go/internal/intel"
	"github.com/greysquirr3l/wordfence-go/internal/logging"
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
	path := "/?" + query.Encode()

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
		return &NOC1Error{
			Action:  action,
			Message: errResp.ErrorMsg,
		}
	}

	if err := json.Unmarshal(resp, result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	return nil
}

// StringBool is a bool that can be unmarshaled from a string or bool
type StringBool bool

// UnmarshalJSON implements json.Unmarshaler
func (sb *StringBool) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*sb = StringBool(b)
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("unmarshaling string bool: %w", err)
	}

	*sb = StringBool(s == "1" || s == "true")
	return nil
}

// PingAPIKeyResponse is the response from ping_api_key
type PingAPIKeyResponse struct {
	OK        int        `json:"ok"`
	IsPaidKey StringBool `json:"_isPaidKey"`
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
	c.License.Paid = bool(resp.IsPaidKey)

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
	IsPaidKey           StringBool        `json:"_isPaidKey"`
}

// SignatureRule represents a malware signature rule
type SignatureRule struct {
	ID             int    // Index 0
	Type           int    // Index 1 (0 = malware, non-zero = other)
	Rule           string // Index 2 - PCRE pattern
	Category       string // Index 3
	Description    string // Index 4
	Enabled        int    // Index 5 (0 = enabled)
	Name           string // Index 6
	LogDescription string // Index 7
	CommonStrings  []int  // Index 8 - Indices into commonStrings array
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
		c.License.Paid = bool(resp.IsPaidKey)
	}

	return &resp, nil
}

// GetPatternsWithTimeout retrieves patterns with a custom timeout
func (c *NOC1Client) GetPatternsWithTimeout(ctx context.Context, timeout time.Duration) (*GetPatternsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return c.GetPatterns(ctx)
}

// NOC1Error represents an error from the NOC1 API
type NOC1Error struct {
	Action  string
	Message string
}

func (e *NOC1Error) Error() string {
	return fmt.Sprintf("NOC1 API error (%s): %s", e.Action, e.Message)
}

// IsNOC1Error checks if an error is an NOC1Error
func IsNOC1Error(err error) (*NOC1Error, bool) {
	var apiErr *NOC1Error
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

// GetPatternsAsSignatureSet fetches patterns and parses them into a SignatureSet
func (c *NOC1Client) GetPatternsAsSignatureSet(ctx context.Context) (*intel.SignatureSet, error) {
	resp, err := c.GetPatterns(ctx)
	if err != nil {
		return nil, err
	}

	return ParsePatternsResponse(resp)
}


// GetWPFileContent retrieves the correct content for a WordPress file
func (c *NOC1Client) GetWPFileContent(ctx context.Context, fileType, filePath, coreVersion string, extensionName, extensionVersion string) ([]byte, error) {
	params := url.Values{}
	params.Set("cType", fileType)
	params.Set("file", filePath)
	params.Set("v", coreVersion)

	if extensionName != "" {
		params.Set("cName", extensionName)
	}
	if extensionVersion != "" {
		params.Set("cVersion", extensionVersion)
	}

	resp, err := c.request(ctx, "get_wp_file_content", params)
	if err != nil {
		return nil, err
	}

	// Check for error in response (JSON error message)
	var errResp struct {
		ErrorMsg string `json:"errorMsg"`
	}
	if err := json.Unmarshal(resp, &errResp); err == nil && errResp.ErrorMsg != "" {
		return nil, &NOC1Error{
			Action:  "get_wp_file_content",
			Message: errResp.ErrorMsg,
		}
	}

	return resp, nil
}

// ParsePatternsResponse converts a GetPatternsResponse into a SignatureSet
func ParsePatternsResponse(resp *GetPatternsResponse) (*intel.SignatureSet, error) {
	// Convert raw rules to intel.RawSignatureRule
	rules := make([]*intel.RawSignatureRule, 0, len(resp.Rules))

	for _, rawRule := range resp.Rules {
		rule, err := ParseSignatureRule(rawRule)
		if err != nil {
			// Skip malformed rules but log them
			continue
		}

		rules = append(rules, &intel.RawSignatureRule{
			ID:             rule.ID,
			Type:           rule.Type,
			Rule:           rule.Rule,
			Category:       rule.Category,
			Description:    rule.Description,
			Enabled:        rule.Enabled,
			Name:           rule.Name,
			LogDescription: rule.LogDescription,
			CommonStrings:  rule.CommonStrings,
		})
	}

	sigSet, err := intel.ParseSignatureSet(resp.CommonStrings, rules, resp.SignatureUpdateTime)
	if err != nil {
		return nil, fmt.Errorf("parsing signature set: %w", err)
	}
	return sigSet, nil
}
