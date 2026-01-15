// Package cache provides file-based caching for Wordfence CLI
package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultCacheDir returns the default cache directory
func DefaultCacheDir() (string, error) {
	// Try XDG_CACHE_HOME first
	if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
		return filepath.Join(xdgCache, "wordfence"), nil
	}

	// Fall back to ~/.cache
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	return filepath.Join(homeDir, ".cache", "wordfence"), nil
}

// FileCache is a file-based cache implementation
type FileCache struct {
	dir  string
	mu   sync.RWMutex
	perm os.FileMode
}

// FileCacheOption is a function that configures a FileCache
type FileCacheOption func(*FileCache)

// WithFileMode sets the file permissions for cached files
func WithFileMode(mode os.FileMode) FileCacheOption {
	return func(c *FileCache) {
		c.perm = mode
	}
}

// NewFileCache creates a new file-based cache
func NewFileCache(dir string, opts ...FileCacheOption) (*FileCache, error) {
	c := &FileCache{
		dir:  dir,
		perm: 0600, // Default: owner read/write only
	}

	for _, opt := range opts {
		opt(c)
	}

	// Create the cache directory
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return c, nil
}

// path returns the file path for a cache key
func (c *FileCache) path(key string) string {
	return filepath.Join(c.dir, EncodeKey(key))
}

// Get retrieves a value from the file cache
func (c *FileCache) Get(key string, maxAge time.Duration) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.path(key)

	// Check if file exists
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, ErrNoCachedValue
	}
	if err != nil {
		return nil, fmt.Errorf("failed to stat cache file: %w", err)
	}

	// Check expiration
	if maxAge > 0 && time.Since(info.ModTime()) > maxAge {
		// File has expired, remove it
		_ = os.Remove(path)
		return nil, ErrNoCachedValue
	}

	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}

	return data, nil
}

// Put stores a value in the file cache
func (c *FileCache) Put(key string, value []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := c.path(key)

	// Write to a temp file first, then rename for atomicity
	tempPath := path + ".tmp"

	if err := os.WriteFile(tempPath, value, c.perm); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to rename cache file: %w", err)
	}

	return nil
}

// Remove removes a value from the file cache
func (c *FileCache) Remove(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := c.path(key)

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cache file: %w", err)
	}

	return nil
}

// Purge clears all values from the file cache
func (c *FileCache) Purge() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove all files in the cache directory
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(c.dir, entry.Name())
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("failed to remove cache file %s: %w", entry.Name(), err)
		}
	}

	return nil
}

// Exists checks if a key exists in the file cache
func (c *FileCache) Exists(key string, maxAge time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.path(key)

	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	if maxAge > 0 && time.Since(info.ModTime()) > maxAge {
		return false
	}

	return true
}

// Size returns the total size of all cached files
func (c *FileCache) Size() (int64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var totalSize int64

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return 0, fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		totalSize += info.Size()
	}

	return totalSize, nil
}

// Keys returns all keys in the cache
func (c *FileCache) Keys() ([]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache directory: %w", err)
	}

	keys := make([]string, 0, len(entries))

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		key, err := DecodeKey(entry.Name())
		if err != nil {
			continue // Skip invalid entries
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// CleanExpired removes all expired entries from the cache
func (c *FileCache) CleanExpired(maxAge time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(c.dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if time.Since(info.ModTime()) > maxAge {
			_ = os.Remove(path)
		}
	}

	return nil
}
