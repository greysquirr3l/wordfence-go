// Package scanner provides the malware scanner implementation
package scanner

import (
	"sync"
)

// BufferPool provides reusable byte buffers to reduce allocations.
// This implements the sync.Pool pattern from go_concurrency.md
type BufferPool struct {
	pool    sync.Pool
	size    int
	gets    int64
	puts    int64
	news    int64
	statsmu sync.Mutex
}

// NewBufferPool creates a pool of byte buffers with the specified size
func NewBufferPool(bufferSize int) *BufferPool {
	if bufferSize <= 0 {
		bufferSize = 32 * 1024 // 32KB default
	}

	bp := &BufferPool{
		size: bufferSize,
	}

	bp.pool = sync.Pool{
		New: func() interface{} {
			bp.statsmu.Lock()
			bp.news++
			bp.statsmu.Unlock()
			return make([]byte, bufferSize)
		},
	}

	return bp
}

// Get retrieves a buffer from the pool
func (bp *BufferPool) Get() []byte {
	bp.statsmu.Lock()
	bp.gets++
	bp.statsmu.Unlock()

	buf := bp.pool.Get().([]byte)
	// Reset buffer length but keep capacity
	return buf[:bp.size]
}

// Put returns a buffer to the pool
func (bp *BufferPool) Put(buf []byte) {
	// Only pool buffers that match the pool size exactly to prevent memory waste
	if cap(buf) == bp.size {
		bp.statsmu.Lock()
		bp.puts++
		bp.statsmu.Unlock()
		bp.pool.Put(buf[:bp.size]) //nolint:staticcheck // intentional reuse
	}
}

// Stats returns pool statistics
func (bp *BufferPool) Stats() (gets, puts, news int64) {
	bp.statsmu.Lock()
	defer bp.statsmu.Unlock()
	return bp.gets, bp.puts, bp.news
}

// HitRate returns the cache hit rate (reuse rate)
func (bp *BufferPool) HitRate() float64 {
	gets, _, news := bp.Stats()
	if gets == 0 {
		return 0
	}
	reused := gets - news
	if reused < 0 {
		reused = 0
	}
	return float64(reused) / float64(gets)
}

// ContentPool provides reusable buffers for file content
// with variable sizes
type ContentPool struct {
	small  *BufferPool // 4KB
	medium *BufferPool // 64KB
	large  *BufferPool // 1MB
}

// NewContentPool creates a tiered buffer pool
func NewContentPool() *ContentPool {
	return &ContentPool{
		small:  NewBufferPool(4 * 1024),
		medium: NewBufferPool(64 * 1024),
		large:  NewBufferPool(1024 * 1024),
	}
}

// GetForSize returns an appropriately sized buffer
func (cp *ContentPool) GetForSize(size int64) []byte {
	switch {
	case size <= 4*1024:
		return cp.small.Get()
	case size <= 64*1024:
		return cp.medium.Get()
	default:
		return cp.large.Get()
	}
}

// Put returns a buffer to the appropriate pool
func (cp *ContentPool) Put(buf []byte) {
	switch cap(buf) {
	case 4 * 1024:
		cp.small.Put(buf)
	case 64 * 1024:
		cp.medium.Put(buf)
	case 1024 * 1024:
		cp.large.Put(buf)
		// Buffers of other sizes are discarded
	}
}

// PutForSize returns a buffer to the appropriate pool based on the buffer's capacity
func (cp *ContentPool) PutForSize(buf []byte) {
	c := cap(buf)
	switch {
	case c <= 4*1024:
		cp.small.Put(buf)
	case c <= 64*1024:
		cp.medium.Put(buf)
	default:
		cp.large.Put(buf)
	}
}

// TotalHitRate returns the combined hit rate across all pools
func (cp *ContentPool) TotalHitRate() float64 {
	sg, _, sn := cp.small.Stats()
	mg, _, mn := cp.medium.Stats()
	lg, _, ln := cp.large.Stats()

	totalGets := sg + mg + lg
	totalNews := sn + mn + ln

	if totalGets == 0 {
		return 0
	}

	reused := totalGets - totalNews
	if reused < 0 {
		reused = 0
	}
	return float64(reused) / float64(totalGets)
}
