//go:build !windows

package scanner

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// getLoadAvg returns the 1-minute load average on Unix systems
func getLoadAvg() (float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, fmt.Errorf("reading loadavg: %w", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, nil
	}

	load, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("parsing loadavg: %w", err)
	}

	return load, nil
}

// checkLoadAverage returns true if system load is too high
func (s *Scanner) checkLoadAverage() bool {
	if s.options.MaxLoadAvg <= 0 {
		return false
	}

	load, err := getLoadAvg()
	if err != nil {
		return false // Can't read load, don't throttle
	}

	return load >= s.options.MaxLoadAvg
}

// waitForLoad waits until system load drops below the limit
func (s *Scanner) waitForLoad(ctx context.Context) {
	if s.options.MaxLoadAvg <= 0 {
		return
	}

	for s.checkLoadAverage() {
		s.logger.Debug("System load too high, waiting...")
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
