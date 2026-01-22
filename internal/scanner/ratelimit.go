// Package scanner provides the malware scanner implementation
package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TokenBucketLimiter implements a token bucket rate limiter for I/O operations.
// This provides smoother rate limiting than simple byte counting.
type TokenBucketLimiter struct {
	tokens     chan struct{}
	refillRate time.Duration
	done       chan struct{}
	closeOnce  sync.Once
}

// NewTokenBucketLimiter creates a rate limiter with the specified rate and burst capacity.
// rate: duration between token refills (e.g., 1ms = 1000 tokens/sec)
// burst: maximum tokens that can accumulate (allows brief bursts)
func NewTokenBucketLimiter(rate time.Duration, burst int) *TokenBucketLimiter {
	if burst <= 0 {
		burst = 1
	}

	rl := &TokenBucketLimiter{
		tokens:     make(chan struct{}, burst),
		refillRate: rate,
		done:       make(chan struct{}),
	}

	// Fill initial tokens
	for i := 0; i < burst; i++ {
		rl.tokens <- struct{}{}
	}

	// Start refill goroutine
	go rl.refill()

	return rl
}

// refill continuously adds tokens at the specified rate
func (rl *TokenBucketLimiter) refill() {
	ticker := time.NewTicker(rl.refillRate)
	defer ticker.Stop()

	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			select {
			case rl.tokens <- struct{}{}:
				// Token added
			default:
				// Bucket full, discard
			}
		}
	}
}

// Wait blocks until a token is available or context is cancelled
func (rl *TokenBucketLimiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("rate limiter wait: %w", ctx.Err())
	case <-rl.done:
		return context.Canceled
	case <-rl.tokens:
		return nil
	}
}

// TryAcquire attempts to acquire a token without blocking
func (rl *TokenBucketLimiter) TryAcquire() bool {
	select {
	case <-rl.tokens:
		return true
	default:
		return false
	}
}

// Close stops the refill goroutine
func (rl *TokenBucketLimiter) Close() {
	rl.closeOnce.Do(func() {
		close(rl.done)
	})
}

// ByteRateLimiter limits bytes per second using token bucket
type ByteRateLimiter struct {
	limiter   *TokenBucketLimiter
	chunkSize int // bytes per token
}

// NewByteRateLimiter creates a limiter for the specified bytes per second.
// chunkSize determines granularity (smaller = smoother but more overhead)
func NewByteRateLimiter(bytesPerSecond int64, chunkSize int) *ByteRateLimiter {
	if chunkSize <= 0 {
		chunkSize = 4096 // 4KB default chunk
	}

	tokensPerSecond := int(bytesPerSecond / int64(chunkSize))
	if tokensPerSecond <= 0 {
		tokensPerSecond = 1
	}

	// Calculate refill rate
	refillRate := time.Second / time.Duration(tokensPerSecond)
	if refillRate < time.Microsecond {
		refillRate = time.Microsecond
	}

	// Burst allows for some burstiness (1 second worth of tokens)
	burst := tokensPerSecond
	if burst > 1000 {
		burst = 1000 // Cap burst size
	}
	if burst < 10 {
		burst = 10 // Minimum burst
	}

	return &ByteRateLimiter{
		limiter:   NewTokenBucketLimiter(refillRate, burst),
		chunkSize: chunkSize,
	}
}

// WaitForBytes blocks until enough tokens are available for the given byte count
func (brl *ByteRateLimiter) WaitForBytes(ctx context.Context, bytes int64) error {
	tokensNeeded := int(bytes / int64(brl.chunkSize))
	if tokensNeeded == 0 {
		tokensNeeded = 1
	}

	for i := 0; i < tokensNeeded; i++ {
		if err := brl.limiter.Wait(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Close stops the rate limiter
func (brl *ByteRateLimiter) Close() {
	brl.limiter.Close()
}
