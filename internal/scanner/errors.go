// Package scanner provides the malware scanner implementation
package scanner

import (
	"fmt"
	"time"
)

// ScanErrorCode identifies the type of scan error
type ScanErrorCode string

// Error codes for scan operations
const (
	ErrCodeFileAccess    ScanErrorCode = "FILE_ACCESS"
	ErrCodeFileRead      ScanErrorCode = "FILE_READ"
	ErrCodeFileTooLarge  ScanErrorCode = "FILE_TOO_LARGE"
	ErrCodeMatchTimeout  ScanErrorCode = "MATCH_TIMEOUT"
	ErrCodeMatchFailed   ScanErrorCode = "MATCH_FAILED"
	ErrCodeContextCancel ScanErrorCode = "CONTEXT_CANCELLED"
	ErrCodeRateLimited   ScanErrorCode = "RATE_LIMITED"
	ErrCodeCircuitOpen   ScanErrorCode = "CIRCUIT_OPEN"
	ErrCodeValidation    ScanErrorCode = "VALIDATION"
	ErrCodeInternal      ScanErrorCode = "INTERNAL"
)

// ScanError provides structured error information for scan operations.
// This follows the domain error pattern from advanced_go_concepts.md
type ScanError struct {
	Code      ScanErrorCode
	Path      string
	Operation string
	Message   string
	Cause     error
	Timestamp time.Time
	Context   map[string]interface{}
}

// Error implements the error interface
func (e *ScanError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s failed for %s: %s: %v",
			e.Code, e.Operation, e.Path, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s failed for %s: %s",
		e.Code, e.Operation, e.Path, e.Message)
}

// Unwrap returns the underlying cause for error wrapping
func (e *ScanError) Unwrap() error {
	return e.Cause
}

// Is checks if the target error matches this error's code
func (e *ScanError) Is(target error) bool {
	if t, ok := target.(*ScanError); ok {
		return e.Code == t.Code
	}
	return false
}

// WithContext adds contextual information to the error
func (e *ScanError) WithContext(key string, value interface{}) *ScanError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// NewScanError creates a new scan error
func NewScanError(code ScanErrorCode, path, operation, message string, cause error) *ScanError {
	return &ScanError{
		Code:      code,
		Path:      path,
		Operation: operation,
		Message:   message,
		Cause:     cause,
		Timestamp: time.Now(),
	}
}

// Convenience constructors for common error types

// ErrFileAccess creates an error for file access failures
func ErrFileAccess(path string, cause error) *ScanError {
	return NewScanError(ErrCodeFileAccess, path, "open", "cannot access file", cause)
}

// ErrFileRead creates an error for file read failures
func ErrFileRead(path string, cause error) *ScanError {
	return NewScanError(ErrCodeFileRead, path, "read", "cannot read file", cause)
}

// ErrFileTooLarge creates an error for files exceeding size limit
func ErrFileTooLarge(path string, size, limit int64) *ScanError {
	return NewScanError(ErrCodeFileTooLarge, path, "validate", "file exceeds size limit", nil).
		WithContext("size", size).
		WithContext("limit", limit)
}

// NewMatchTimeoutError creates an error for regex match timeouts
func NewMatchTimeoutError(path string, signatureID int, duration time.Duration) *ScanError {
	return NewScanError(ErrCodeMatchTimeout, path, "match", "pattern match timed out", nil).
		WithContext("signature_id", signatureID).
		WithContext("duration_ms", duration.Milliseconds())
}

// ErrContextCancelled creates an error for cancelled operations
func ErrContextCancelled(path string, cause error) *ScanError {
	return NewScanError(ErrCodeContextCancel, path, "scan", "operation cancelled", cause)
}

// IsRetryable returns true if the error might succeed on retry
func (e *ScanError) IsRetryable() bool {
	switch e.Code {
	case ErrCodeRateLimited, ErrCodeCircuitOpen, ErrCodeMatchTimeout:
		return true
	default:
		return false
	}
}

// IsFatal returns true if the error should stop the entire scan
func (e *ScanError) IsFatal() bool {
	switch e.Code {
	case ErrCodeContextCancel:
		return true
	default:
		return false
	}
}

// ScanErrorStats tracks error statistics during a scan
type ScanErrorStats struct {
	ByCode    map[ScanErrorCode]int64
	ByPath    map[string]int
	Retryable int64
	Fatal     int64
	Total     int64
}

// NewScanErrorStats creates a new error statistics tracker
func NewScanErrorStats() *ScanErrorStats {
	return &ScanErrorStats{
		ByCode: make(map[ScanErrorCode]int64),
		ByPath: make(map[string]int),
	}
}

// Record adds an error to the statistics
func (s *ScanErrorStats) Record(err *ScanError) {
	s.Total++
	s.ByCode[err.Code]++
	s.ByPath[err.Path]++

	if err.IsRetryable() {
		s.Retryable++
	}
	if err.IsFatal() {
		s.Fatal++
	}
}
