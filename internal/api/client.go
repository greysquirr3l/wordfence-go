// Package api provides HTTP client functionality for Wordfence APIs
package api //nolint:revive // api is a well-understood package name for API clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/greysquirr3l/wordfence-go/internal/logging"
)

// DefaultTimeout is the default HTTP request timeout
const DefaultTimeout = 30 * time.Second

// DefaultRetries is the default number of retry attempts
const DefaultRetries = 3

// DefaultRetryWait is the default wait time between retries
const DefaultRetryWait = 1 * time.Second

// Client is a base HTTP client for API requests
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Logger     *logging.Logger
	UserAgent  string
	Retries    int
	RetryWait  time.Duration
}

// ClientOption is a function that configures a Client
type ClientOption func(*Client)

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.HTTPClient.Timeout = timeout
	}
}

// WithRetries sets the number of retry attempts
func WithRetries(retries int) ClientOption {
	return func(c *Client) {
		c.Retries = retries
	}
}

// WithRetryWait sets the wait time between retries
func WithRetryWait(wait time.Duration) ClientOption {
	return func(c *Client) {
		c.RetryWait = wait
	}
}

// WithLogger sets the logger for the client
func WithLogger(logger *logging.Logger) ClientOption {
	return func(c *Client) {
		c.Logger = logger
	}
}

// NewClient creates a new HTTP client with the given base URL
func NewClient(baseURL string, opts ...ClientOption) *Client {
	c := &Client{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		UserAgent: "python-requests/2.31.0",
		Retries:   DefaultRetries,
		RetryWait: DefaultRetryWait,
		Logger:    logging.New(logging.LevelInfo),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Request makes an HTTP request and returns the response body
func (c *Client) Request(ctx context.Context, method, path string, body io.Reader, headers map[string]string) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			c.Logger.Debug("Retrying request (attempt %d/%d) after error: %v", attempt, c.Retries, lastErr)
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
			case <-time.After(c.RetryWait * time.Duration(attempt)):
				// Exponential backoff
			}
		}

		resp, err := c.doRequest(ctx, method, path, body, headers)
		if err != nil {
			lastErr = err
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", c.Retries+1, lastErr)
}

// doRequest performs a single HTTP request
func (c *Client) doRequest(ctx context.Context, method, path string, body io.Reader, headers map[string]string) ([]byte, error) {
	fullURL := c.BaseURL + path

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	req.Header.Set("User-Agent", c.UserAgent)

	// Set custom headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	c.Logger.Debug("HTTP %s %s", method, fullURL)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       string(respBody),
		}
	}

	c.Logger.Debug("HTTP %s %s -> %d (%d bytes)", method, fullURL, resp.StatusCode, len(respBody))

	return respBody, nil
}

// Get makes a GET request
func (c *Client) Get(ctx context.Context, path string, headers map[string]string) ([]byte, error) {
	return c.Request(ctx, http.MethodGet, path, nil, headers)
}

// Post makes a POST request with form data
func (c *Client) Post(ctx context.Context, path string, data url.Values, headers map[string]string) ([]byte, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	headers["Content-Type"] = "application/x-www-form-urlencoded"

	return c.Request(ctx, http.MethodPost, path, strings.NewReader(data.Encode()), headers)
}

// PostJSON makes a POST request with JSON data
func (c *Client) PostJSON(ctx context.Context, path string, data interface{}, headers map[string]string) ([]byte, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if headers == nil {
		headers = make(map[string]string)
	}
	headers["Content-Type"] = "application/json"

	return c.Request(ctx, http.MethodPost, path, bytes.NewReader(jsonData), headers)
}

// HTTPError represents an HTTP error response
type HTTPError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *HTTPError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("HTTP %s: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("HTTP %s", e.Status)
}

// IsHTTPError checks if an error is an HTTPError and returns it
func IsHTTPError(err error) (*HTTPError, bool) {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr, true
	}
	return nil, false
}

// IsNotFound checks if the error is a 404 Not Found
func IsNotFound(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode == http.StatusNotFound
	}
	return false
}

// IsUnauthorized checks if the error is a 401 Unauthorized
func IsUnauthorized(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode == http.StatusUnauthorized
	}
	return false
}

// IsForbidden checks if the error is a 403 Forbidden
func IsForbidden(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode == http.StatusForbidden
	}
	return false
}
