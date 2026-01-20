//go:build windows

package scanner

import (
	"context"
	"errors"
)

// getLoadAvg returns an error on Windows (not supported)
func getLoadAvg() (float64, error) {
	return 0, errors.New("load average not supported on Windows")
}

// checkLoadAverage returns false on Windows (not supported)
func (s *Scanner) checkLoadAverage() bool {
	// Load average monitoring not available on Windows
	return false
}

// waitForLoad is a no-op on Windows
func (s *Scanner) waitForLoad(_ context.Context) {
	// Load average monitoring not available on Windows
}
