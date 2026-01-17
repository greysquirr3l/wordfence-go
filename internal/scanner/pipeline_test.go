package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/greysquirr3l/wordfence-go/internal/intel"
)

func createPipelineTestSignatureSet() *intel.SignatureSet {
	ss := intel.NewSignatureSet()

	// Add common strings
	ss.CommonStrings = append(ss.CommonStrings, intel.NewCommonString("eval"))
	ss.CommonStrings = append(ss.CommonStrings, intel.NewCommonString("test"))

	// Add test signatures
	ss.Signatures[1] = intel.NewSignature(
		1,
		`eval\s*\(`,
		"Eval Pattern",
		"Detects eval() calls",
		[]int{0},
	)
	ss.CommonStrings[0].SignatureIDs = append(ss.CommonStrings[0].SignatureIDs, 1)

	ss.Signatures[2] = intel.NewSignature(
		2,
		`test`,
		"Test Pattern",
		"Test signature",
		[]int{1},
	)
	ss.CommonStrings[1].SignatureIDs = append(ss.CommonStrings[1].SignatureIDs, 2)

	return ss
}

func TestPipelineScannerCreation(t *testing.T) {
	sigSet := createPipelineTestSignatureSet()

	scanner := NewPipelineScanner(sigSet,
		WithPipelineWorkers(2),
		WithPipelineMatchTimeout(time.Second),
	)

	if scanner == nil {
		t.Fatal("Expected non-nil scanner")
	}

	if scanner.options.Workers != 2 {
		t.Errorf("Expected 2 workers, got %d", scanner.options.Workers)
	}
}

func TestPipelineScannerScan(t *testing.T) {
	// Create a temporary directory with test files
	tmpDir, err := os.MkdirTemp("", "pipeline_test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a test PHP file with detectable content
	testFile := filepath.Join(tmpDir, "test.php")
	content := []byte("<?php eval(base64_decode('malware')); ?>")
	if err := os.WriteFile(testFile, content, 0600); err != nil {
		t.Fatal(err)
	}

	// Create signature set
	sigSet := createPipelineTestSignatureSet()

	scanner := NewPipelineScanner(sigSet,
		WithPipelineWorkers(2),
		WithPipelineMatchTimeout(time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	var found bool
	for result := range results {
		if result.Error != nil {
			t.Logf("Scan error: %v", result.Error)
			continue
		}
		if result.HasMatches() {
			found = true
			t.Logf("Found %d matches in %s", len(result.Matches), result.Path)
		}
	}

	if !found {
		t.Error("Expected to find matches")
	}
}

func TestPipelineScannerIdempotency(t *testing.T) {
	paths := []string{"/path/a", "/path/b", "/path/c"}
	timestamp := time.Date(2026, 1, 17, 12, 0, 0, 0, time.UTC)

	// Same inputs should produce same scan ID
	id1 := GenerateScanID(paths, timestamp)
	id2 := GenerateScanID(paths, timestamp)

	if id1 != id2 {
		t.Errorf("Same inputs should produce same scan ID: %s vs %s", id1, id2)
	}

	// Different order should produce same ID (paths are sorted)
	reversePaths := []string{"/path/c", "/path/b", "/path/a"}
	id3 := GenerateScanID(reversePaths, timestamp)

	if id1 != id3 {
		t.Errorf("Path order shouldn't affect scan ID: %s vs %s", id1, id3)
	}

	// Different timestamp should produce different ID
	timestamp2 := timestamp.Add(time.Hour)
	id4 := GenerateScanID(paths, timestamp2)

	if id1 == id4 {
		t.Error("Different timestamps should produce different scan IDs")
	}
}

func TestPipelineScannerGracefulShutdown(t *testing.T) {
	sigSet := intel.NewSignatureSet()
	scanner := NewPipelineScanner(sigSet, WithPipelineWorkers(2))

	// Test shutdown without starting a scan
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := scanner.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}

	// Second shutdown should be no-op
	err = scanner.Shutdown(ctx)
	if err != nil {
		t.Errorf("Second shutdown should succeed: %v", err)
	}
}

func TestPipelineScannerStats(t *testing.T) {
	sigSet := intel.NewSignatureSet()
	scanner := NewPipelineScanner(sigSet)

	stats := scanner.GetStats()
	if stats.Discovered != 0 {
		t.Errorf("Expected 0 discovered, got %d", stats.Discovered)
	}
}

func TestBufferPoolHitRate(t *testing.T) {
	pool := NewContentPool()

	// First get creates new buffers
	buf1 := pool.GetForSize(1024)     // small
	buf2 := pool.GetForSize(32 * 1024) // medium

	// Return buffers
	pool.PutForSize(buf1)
	pool.PutForSize(buf2)

	// Second get should reuse
	_ = pool.GetForSize(1024)
	_ = pool.GetForSize(32 * 1024)

	hitRate := pool.HitRate()
	t.Logf("Buffer pool hit rate: %.2f", hitRate)
}

func TestCircuitBreakerIntegration(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond, 2)

	// Should start closed
	if cb.State() != CircuitClosed {
		t.Error("Circuit should start closed")
	}

	// Simulate failures
	for i := 0; i < 3; i++ {
		_ = cb.Execute(func() error {
			return os.ErrNotExist
		})
	}

	// Should be open after threshold failures
	if cb.State() != CircuitOpen {
		t.Error("Circuit should be open after failures")
	}

	// Requests should be blocked
	err := cb.Execute(func() error {
		return nil
	})

	if !errors.Is(err, ErrCircuitOpen) {
		t.Error("Expected ErrCircuitOpen when circuit is open")
	}
}

func TestTokenBucketRateLimiter(t *testing.T) {
	// 10 tokens per second with burst of 5
	limiter := NewTokenBucketLimiter(100*time.Millisecond, 5)
	defer limiter.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Should get first 5 immediately (burst)
	for i := 0; i < 5; i++ {
		if !limiter.TryAcquire() {
			t.Errorf("Should acquire token %d immediately", i)
		}
	}

	// 6th should block or fail
	if limiter.TryAcquire() {
		t.Error("Should not acquire beyond burst without waiting")
	}

	// Wait should eventually succeed
	err := limiter.Wait(ctx)
	if err != nil {
		t.Errorf("Wait should succeed: %v", err)
	}
}

func TestDrainResults(t *testing.T) {
	results := make(chan *ScanResult, 10)

	// Add some results
	for i := 0; i < 5; i++ {
		results <- &ScanResult{Path: "/test"}
	}
	close(results)

	count := DrainResults(results)
	if count != 5 {
		t.Errorf("Expected 5 drained results, got %d", count)
	}
}
