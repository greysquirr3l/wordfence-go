// Package cache provides caching functionality for Wordfence CLI
package cache

import (
	"encoding/hex"
	"errors"
	"time"
)

// DurationOneDay is 24 hours in duration
const DurationOneDay = 24 * time.Hour

// Errors
var (
	ErrNoCachedValue      = errors.New("no cached value")
	ErrInvalidCachedValue = errors.New("invalid cached value")
	ErrCacheDisabled      = errors.New("cache is disabled")
)

// Cache is the interface for cache implementations
type Cache interface {
	// Get retrieves a value from the cache
	// Returns ErrNoCachedValue if the key doesn't exist or has expired
	Get(key string, maxAge time.Duration) ([]byte, error)

	// Put stores a value in the cache
	Put(key string, value []byte) error

	// Remove removes a value from the cache
	Remove(key string) error

	// Purge clears all cached values
	Purge() error

	// Exists checks if a key exists and is not expired
	Exists(key string, maxAge time.Duration) bool
}

// CacheEntry represents a cached item with metadata
type CacheEntry struct {
	Key       string
	Data      []byte
	CreatedAt time.Time
}

// IsExpired checks if the entry is expired based on maxAge
func (e *CacheEntry) IsExpired(maxAge time.Duration) bool {
	if maxAge <= 0 {
		return false // No expiration
	}
	return time.Since(e.CreatedAt) > maxAge
}

// EncodeKey encodes a cache key to a safe filename
func EncodeKey(key string) string {
	return hex.EncodeToString([]byte(key))
}

// DecodeKey decodes a cache key from a filename
func DecodeKey(encoded string) (string, error) {
	data, err := hex.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// NoOpCache is a cache that does nothing (for when caching is disabled)
type NoOpCache struct{}

// Get always returns ErrCacheDisabled
func (c *NoOpCache) Get(key string, maxAge time.Duration) ([]byte, error) {
	return nil, ErrCacheDisabled
}

// Put does nothing
func (c *NoOpCache) Put(key string, value []byte) error {
	return nil
}

// Remove does nothing
func (c *NoOpCache) Remove(key string) error {
	return nil
}

// Purge does nothing
func (c *NoOpCache) Purge() error {
	return nil
}

// Exists always returns false
func (c *NoOpCache) Exists(key string, maxAge time.Duration) bool {
	return false
}

// MemoryCache is an in-memory cache implementation
type MemoryCache struct {
	items map[string]*CacheEntry
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		items: make(map[string]*CacheEntry),
	}
}

// Get retrieves a value from the memory cache
func (c *MemoryCache) Get(key string, maxAge time.Duration) ([]byte, error) {
	entry, ok := c.items[key]
	if !ok {
		return nil, ErrNoCachedValue
	}

	if entry.IsExpired(maxAge) {
		delete(c.items, key)
		return nil, ErrNoCachedValue
	}

	return entry.Data, nil
}

// Put stores a value in the memory cache
func (c *MemoryCache) Put(key string, value []byte) error {
	c.items[key] = &CacheEntry{
		Key:       key,
		Data:      value,
		CreatedAt: time.Now(),
	}
	return nil
}

// Remove removes a value from the memory cache
func (c *MemoryCache) Remove(key string) error {
	delete(c.items, key)
	return nil
}

// Purge clears all values from the memory cache
func (c *MemoryCache) Purge() error {
	c.items = make(map[string]*CacheEntry)
	return nil
}

// Exists checks if a key exists in the memory cache
func (c *MemoryCache) Exists(key string, maxAge time.Duration) bool {
	entry, ok := c.items[key]
	if !ok {
		return false
	}
	return !entry.IsExpired(maxAge)
}
