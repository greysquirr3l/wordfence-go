// Package scanner provides the malware scanner implementation
package scanner

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitState represents the state of a circuit breaker
type CircuitState int32

const (
	// CircuitClosed allows requests through
	CircuitClosed CircuitState = iota
	// CircuitOpen blocks all requests
	CircuitOpen
	// CircuitHalfOpen allows a test request through
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker prevents cascading failures by stopping operations
// when failure rate exceeds threshold
type CircuitBreaker struct {
	state           atomic.Int32
	failures        atomic.Int32
	successes       atomic.Int32
	lastFailureTime atomic.Int64 // Unix nano

	threshold   int           // failures before opening
	timeout     time.Duration // time before trying again
	halfOpenMax int           // successes needed to close
	mu          sync.Mutex    // for state transitions
}

// Common circuit breaker errors
var (
	ErrCircuitOpen = errors.New("circuit breaker is open")
)

// NewCircuitBreaker creates a circuit breaker with the given settings.
// threshold: number of failures before opening the circuit
// timeout: how long to wait before allowing a test request
// halfOpenMax: successful requests needed to close the circuit
func NewCircuitBreaker(threshold int, timeout time.Duration, halfOpenMax int) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if halfOpenMax <= 0 {
		halfOpenMax = 3
	}

	cb := &CircuitBreaker{
		threshold:   threshold,
		timeout:     timeout,
		halfOpenMax: halfOpenMax,
	}
	cb.state.Store(int32(CircuitClosed))
	return cb
}

// Execute runs the given function if the circuit allows it
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if !cb.allowRequest() {
		return ErrCircuitOpen
	}

	err := fn()
	cb.recordResult(err)
	return err
}

// allowRequest checks if a request should be allowed
func (cb *CircuitBreaker) allowRequest() bool {
	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitClosed:
		return true

	case CircuitOpen:
		// Check if timeout has elapsed
		lastFailure := time.Unix(0, cb.lastFailureTime.Load())
		if time.Since(lastFailure) >= cb.timeout {
			// Try transitioning to half-open
			cb.mu.Lock()
			if CircuitState(cb.state.Load()) == CircuitOpen {
				cb.state.Store(int32(CircuitHalfOpen))
				cb.successes.Store(0)
			}
			cb.mu.Unlock()
			return true
		}
		return false

	case CircuitHalfOpen:
		// Allow limited requests in half-open state
		return true

	default:
		return false
	}
}

// recordResult updates the circuit state based on operation result
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	state := CircuitState(cb.state.Load())

	if err != nil {
		// Failure
		cb.lastFailureTime.Store(time.Now().UnixNano())

		switch state {
		case CircuitClosed:
			failures := cb.failures.Add(1)
			if int(failures) >= cb.threshold {
				cb.state.Store(int32(CircuitOpen))
				cb.failures.Store(0)
			}

		case CircuitHalfOpen:
			// Any failure in half-open goes back to open
			cb.state.Store(int32(CircuitOpen))
			cb.successes.Store(0)
		}
	} else {
		// Success
		switch state {
		case CircuitClosed:
			// Reset failure count on success
			cb.failures.Store(0)

		case CircuitHalfOpen:
			successes := cb.successes.Add(1)
			if int(successes) >= cb.halfOpenMax {
				// Enough successes, close the circuit
				cb.state.Store(int32(CircuitClosed))
				cb.failures.Store(0)
				cb.successes.Store(0)
			}
		}
	}
}

// State returns the current circuit state
func (cb *CircuitBreaker) State() CircuitState {
	return CircuitState(cb.state.Load())
}

// Reset manually resets the circuit to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state.Store(int32(CircuitClosed))
	cb.failures.Store(0)
	cb.successes.Store(0)
}

// Failures returns the current failure count
func (cb *CircuitBreaker) Failures() int {
	return int(cb.failures.Load())
}
