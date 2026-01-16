package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileCacheOperations(t *testing.T) {
	dir := t.TempDir()

	cache, err := NewFileCache(dir)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	key := "test-key"
	data := []byte("test data content")

	// Test Put
	if err := cache.Put(key, data); err != nil {
		t.Fatalf("failed to put data: %v", err)
	}

	// Test Get
	retrieved, err := cache.Get(key, time.Hour)
	if err != nil {
		t.Fatalf("failed to get data: %v", err)
	}

	if string(retrieved) != string(data) {
		t.Errorf("expected %q, got %q", string(data), string(retrieved))
	}
}

func TestFileCacheExpiration(t *testing.T) {
	dir := t.TempDir()

	cache, err := NewFileCache(dir)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	key := "expiring-key"
	data := []byte("expiring data")

	// Put data
	if err := cache.Put(key, data); err != nil {
		t.Fatalf("failed to put data: %v", err)
	}

	// Get with very short max age (should work immediately)
	_, err = cache.Get(key, time.Hour)
	if err != nil {
		t.Fatalf("expected data to be present: %v", err)
	}

	// Verify that normal max age retrieval works
	retrieved, err := cache.Get(key, time.Minute)
	if err != nil {
		t.Fatalf("expected data to be present with 1 minute max age: %v", err)
	}
	if string(retrieved) != string(data) {
		t.Errorf("data mismatch")
	}
}

func TestFileCacheRemove(t *testing.T) {
	dir := t.TempDir()

	cache, err := NewFileCache(dir)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	key := "removable-key"
	data := []byte("data to remove")

	// Put data
	if err := cache.Put(key, data); err != nil {
		t.Fatalf("failed to put data: %v", err)
	}

	// Verify it exists
	_, err = cache.Get(key, time.Hour)
	if err != nil {
		t.Fatalf("expected data to exist: %v", err)
	}

	// Remove
	if err := cache.Remove(key); err != nil {
		t.Fatalf("failed to remove data: %v", err)
	}

	// Verify it's gone
	_, err = cache.Get(key, time.Hour)
	if err == nil {
		t.Error("expected data to be removed")
	}
}

func TestFileCachePurge(t *testing.T) {
	dir := t.TempDir()

	cache, err := NewFileCache(dir)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Put multiple items
	keys := []string{"key1", "key2", "key3"}
	for _, key := range keys {
		if err := cache.Put(key, []byte("data for "+key)); err != nil {
			t.Fatalf("failed to put %s: %v", key, err)
		}
	}

	// Purge
	if err := cache.Purge(); err != nil {
		t.Fatalf("failed to purge: %v", err)
	}

	// Verify all are gone
	for _, key := range keys {
		_, err := cache.Get(key, time.Hour)
		if err == nil {
			t.Errorf("expected %s to be purged", key)
		}
	}
}

func TestFileCacheGetNonExistent(t *testing.T) {
	dir := t.TempDir()

	cache, err := NewFileCache(dir)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	_, err = cache.Get("non-existent-key", time.Hour)
	if err == nil {
		t.Error("expected error for non-existent key")
	}
}

func TestFileCachePath(t *testing.T) {
	dir := t.TempDir()

	cache, err := NewFileCache(dir)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	key := "path-test"
	data := []byte("test data")

	if err := cache.Put(key, data); err != nil {
		t.Fatalf("failed to put data: %v", err)
	}

	// Verify file was created in cache directory
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read cache dir: %v", err)
	}

	if len(files) == 0 {
		t.Error("expected cache file to be created")
	}
}

func TestNoOpCache(t *testing.T) {
	cache := &NoOpCache{}

	// Put should succeed (but do nothing)
	if err := cache.Put("key", []byte("data")); err != nil {
		t.Errorf("Put should not error: %v", err)
	}

	// Get should always fail
	_, err := cache.Get("key", time.Hour)
	if err == nil {
		t.Error("Get should always fail for NoOpCache")
	}

	// Remove should succeed
	if err := cache.Remove("key"); err != nil {
		t.Errorf("Remove should not error: %v", err)
	}

	// Purge should succeed
	if err := cache.Purge(); err != nil {
		t.Errorf("Purge should not error: %v", err)
	}
}

func TestNewNoOpCache(t *testing.T) {
	cache := NewNoOpCache()

	if cache == nil {
		t.Fatal("expected cache to be created")
	}
}

func TestDefaultCacheDir(t *testing.T) {
	dir, err := DefaultCacheDir()
	if err != nil {
		t.Fatalf("failed to get default cache dir: %v", err)
	}

	if dir == "" {
		t.Error("expected non-empty default cache dir")
	}

	// Should contain "wordfence" in the path
	if !filepath.IsAbs(dir) {
		t.Error("expected absolute path")
	}
}

func TestFileCacheConcurrency(t *testing.T) {
	dir := t.TempDir()

	cache, err := NewFileCache(dir)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(_ int) {
			key := "concurrent-key"
			data := []byte("data")

			for j := 0; j < 10; j++ {
				_ = cache.Put(key, data)
				_, _ = cache.Get(key, time.Hour)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
