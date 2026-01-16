//go:build embedded_rules

// Package intel provides signature loading (embedded mode)
package intel

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/greysquirr3l/wordfence-go/internal/cache"
)

//go:embed rules/signatures.json
var embeddedRules embed.FS

// SignatureLoader loads signatures from embedded data or cache
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
		return nil, err
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

	return l.cache.Put(l.cacheKey, data)
}

// HasEmbedded returns true if rules are embedded in the binary
func HasEmbedded() bool {
	return true
}

// GetEmbedded returns embedded signatures
func GetEmbedded() (*SignatureSet, error) {
	data, err := embeddedRules.ReadFile("rules/signatures.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded signatures: %w", err)
	}

	// Parse the raw API response format
	return ParseRawAPIResponse(data)
}

// LoadOrFetch loads from embedded/cache, or calls fetchFn to get fresh data
func (l *SignatureLoader) LoadOrFetch(ctx context.Context, fetchFn func(context.Context) (*SignatureSet, error)) (*SignatureSet, error) {
	// Try cache first (may have fresher rules)
	sigSet, err := l.Load()
	if err == nil {
		return sigSet, nil
	}

	// Try embedded rules
	sigSet, err = GetEmbedded()
	if err == nil {
		return sigSet, nil
	}

	// Fall back to API fetch
	sigSet, err = fetchFn(ctx)
	if err != nil {
		return nil, err
	}

	// Cache for next time
	_ = l.Save(sigSet)

	return sigSet, nil
}
