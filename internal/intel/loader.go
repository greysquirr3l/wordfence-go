//go:build !embedded_rules

// Package intel provides signature loading (fetch mode)
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/greysquirr3l/wordfence-go/internal/cache"
)

// SignatureLoader loads signatures from API or cache
type SignatureLoader struct {
	cache    cache.Cache
	cacheKey string
	maxAge   time.Duration
}

// NewSignatureLoader creates a new signature loader
func NewSignatureLoader(c cache.Cache) *SignatureLoader {
	return &SignatureLoader{
		cache:    c,
		cacheKey: "signatures",
		maxAge:   24 * time.Hour,
	}
}

// Load loads signatures from cache or returns nil if not cached
func (l *SignatureLoader) Load() (*SignatureSet, error) {
	data, err := l.cache.Get(l.cacheKey, l.maxAge)
	if err != nil {
		return nil, fmt.Errorf("getting from cache: %w", err)
	}

	var sigSet SignatureSet
	if err := json.Unmarshal(data, &sigSet); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached signatures: %w", err)
	}

	return &sigSet, nil
}

// Save saves signatures to cache
func (l *SignatureLoader) Save(sigSet *SignatureSet) error {
	data, err := json.Marshal(sigSet)
	if err != nil {
		return fmt.Errorf("failed to marshal signatures: %w", err)
	}

	if err := l.cache.Put(l.cacheKey, data); err != nil {
		return fmt.Errorf("putting to cache: %w", err)
	}
	return nil
}

// HasEmbedded returns true if rules are embedded in the binary
func HasEmbedded() bool {
	return false
}

// GetEmbedded returns embedded signatures (nil in fetch mode)
func GetEmbedded() (*SignatureSet, error) {
	return nil, fmt.Errorf("no embedded signatures in this build")
}

// LoadOrFetch loads from cache/embedded, or calls fetchFn to get fresh data
func (l *SignatureLoader) LoadOrFetch(ctx context.Context, fetchFn func(context.Context) (*SignatureSet, error)) (*SignatureSet, error) {
	// Try cache first
	sigSet, err := l.Load()
	if err == nil {
		return sigSet, nil
	}

	// Fetch from API
	sigSet, err = fetchFn(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching signatures: %w", err)
	}

	// Cache for next time
	_ = l.Save(sigSet)

	return sigSet, nil
}
