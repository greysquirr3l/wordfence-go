// Package scanner provides the malware scanner implementation
package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/greysquirr3l/wordfence-go/internal/intel"
	"github.com/greysquirr3l/wordfence-go/internal/logging"
)

// PipelineStage represents a stage in the scan pipeline
type PipelineStage string

// Pipeline stages for scan processing
const (
	StageDiscover PipelineStage = "discover"
	StageFilter   PipelineStage = "filter"
	StageRead     PipelineStage = "read"
	StageMatch    PipelineStage = "match"
	StageReport   PipelineStage = "report"
)

// FileItem represents a file passing through the pipeline
type FileItem struct {
	Path         string
	Info         os.FileInfo
	Content      []byte
	ContentPool  *ContentPool // for returning buffer
	Error        *ScanError
	Matches      []*MatchResult
	Timeouts     []int
	ScanDuration time.Duration
	Stage        PipelineStage

	// Idempotency support
	ScanID      string // Unique identifier for this scan operation
	ContentHash string // SHA256 of file content for deduplication
}

// PipelineScanner implements a staged pipeline architecture for malware scanning.
// Stages: discover → filter → read → match → report
type PipelineScanner struct {
	matcher *Matcher
	sigSet  *intel.SignatureSet
	options *ScanOptions
	logger  *logging.Logger

	// Resource management
	bufferPool  *ContentPool
	rateLimiter *ByteRateLimiter
	circuit     *CircuitBreaker
	monitor     *ResourceMonitor // Dynamic resource monitoring

	// Dynamic throttling (set by ResourceMonitor)
	dynamicDelay atomic.Int64 // nanoseconds

	// Pipeline channels
	discovered chan *FileItem
	filtered   chan *FileItem
	read       chan *FileItem
	matched    chan *FileItem

	// Graceful shutdown
	wg         sync.WaitGroup
	shutdownMu sync.RWMutex
	shutdown   bool
	done       chan struct{}

	// Statistics
	stats     PipelineStats
	statsLock sync.Mutex

	// Idempotency
	scanID       string
	processedMu  sync.RWMutex
	processedSet map[string]bool // Track processed files by content hash
}

// PipelineStats holds detailed statistics for each pipeline stage
type PipelineStats struct {
	// Stage counts
	Discovered int64
	Filtered   int64
	Read       int64
	Matched    int64
	Reported   int64

	// Outcomes
	FilesWithMatches int64
	FilesSkipped     int64
	FilesErrored     int64
	BytesScanned     int64

	// Timing
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration

	// Resource usage
	BufferPoolHitRate float64
	CircuitBreaks     int64
	RateLimitWaits    int64

	// Idempotency
	DuplicatesSkipped int64
}

// PipelineOption configures a PipelineScanner
type PipelineOption func(*PipelineScanner)

// WithPipelineLogger sets the logger
func WithPipelineLogger(logger *logging.Logger) PipelineOption {
	return func(p *PipelineScanner) {
		p.logger = logger
	}
}

// WithPipelineFilter sets the file filter
func WithPipelineFilter(filter *FileFilter) PipelineOption {
	return func(p *PipelineScanner) {
		p.options.Filter = filter
	}
}

// WithPipelineWorkers sets the number of workers for parallel stages
func WithPipelineWorkers(workers int) PipelineOption {
	return func(p *PipelineScanner) {
		p.options.Workers = workers
	}
}

// WithPipelineContentLimit sets the maximum file size to scan
func WithPipelineContentLimit(limit int64) PipelineOption {
	return func(p *PipelineScanner) {
		p.options.ContentLimit = limit
	}
}

// WithPipelineMatchTimeout sets the regex match timeout
func WithPipelineMatchTimeout(timeout time.Duration) PipelineOption {
	return func(p *PipelineScanner) {
		p.options.MatchTimeout = timeout
	}
}

// WithPipelineIOLimit sets the I/O rate limit in bytes per second
func WithPipelineIOLimit(bytesPerSec int64) PipelineOption {
	return func(p *PipelineScanner) {
		p.options.IOBytesPerSec = bytesPerSec
	}
}

// WithPipelineCircuitBreaker configures circuit breaker settings
func WithPipelineCircuitBreaker(threshold int, timeout time.Duration) PipelineOption {
	return func(p *PipelineScanner) {
		p.circuit = NewCircuitBreaker(threshold, timeout, 3)
	}
}

// WithPipelineResourceMonitor enables dynamic resource monitoring
func WithPipelineResourceMonitor(interval time.Duration) PipelineOption {
	return func(p *PipelineScanner) {
		// Store interval for use when creating monitor later
		// We need to create the monitor in Scan() so we can use p.SetDynamicDelay
		p.monitor = NewResourceMonitor(
			WithMonitorInterval(interval),
			WithAdjustCallback(func(_ int, delayNS int64) {
				p.SetDynamicDelay(time.Duration(delayNS))
			}),
		)
	}
}

// WithPipelineFollowSymlinks enables following symlinks
func WithPipelineFollowSymlinks(follow bool) PipelineOption {
	return func(p *PipelineScanner) {
		p.options.FollowSymlinks = follow
	}
}

// WithPipelineAllowIOErrors continues on I/O errors
func WithPipelineAllowIOErrors(allow bool) PipelineOption {
	return func(p *PipelineScanner) {
		p.options.AllowIOErrors = allow
	}
}

// NewPipelineScanner creates a new pipeline-based scanner
func NewPipelineScanner(sigSet *intel.SignatureSet, opts ...PipelineOption) *PipelineScanner {
	p := &PipelineScanner{
		sigSet: sigSet,
		options: &ScanOptions{
			Workers:      DefaultWorkers,
			ChunkSize:    DefaultChunkSize,
			Filter:       DefaultFilter(),
			MatchTimeout: time.Second,
		},
		logger:       logging.New(logging.LevelInfo),
		bufferPool:   NewContentPool(),
		done:         make(chan struct{}),
		processedSet: make(map[string]bool),
	}

	for _, opt := range opts {
		opt(p)
	}

	// Initialize matcher
	matcherOpts := []MatcherOption{WithMatcherLogger(p.logger)}
	if p.options.MatchTimeout > 0 {
		matcherOpts = append(matcherOpts, WithMatchTimeout(p.options.MatchTimeout))
	}
	p.matcher = NewMatcher(sigSet, matcherOpts...)

	// Initialize rate limiter if configured
	if p.options.IOBytesPerSec > 0 {
		p.rateLimiter = NewByteRateLimiter(p.options.IOBytesPerSec, 64*1024)
	}

	// Default circuit breaker
	if p.circuit == nil {
		p.circuit = NewCircuitBreaker(10, 30*time.Second, 3)
	}

	return p
}

// GenerateScanID creates a unique, deterministic scan ID based on inputs
func GenerateScanID(paths []string, timestamp time.Time) string {
	h := sha256.New()
	// Sort paths for determinism
	sorted := make([]string, len(paths))
	copy(sorted, paths)
	sort.Strings(sorted)

	for _, p := range sorted {
		h.Write([]byte(p))
	}
	h.Write([]byte(timestamp.Format(time.RFC3339)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Scan starts the pipeline scan and returns a channel of results
func (p *PipelineScanner) Scan(ctx context.Context, paths ...string) (<-chan *ScanResult, error) {
	if len(paths) == 0 {
		return nil, NewScanError(ErrCodeValidation, "", "scan", "no paths to scan", nil)
	}

	p.shutdownMu.Lock()
	if p.shutdown {
		p.shutdownMu.Unlock()
		return nil, NewScanError(ErrCodeValidation, "", "scan", "scanner is shut down", nil)
	}
	p.shutdownMu.Unlock()

	// Generate idempotent scan ID
	p.scanID = GenerateScanID(paths, time.Now())
	p.logger.Debug("Starting pipeline scan with ID: %s", p.scanID)

	// Start resource monitor if configured
	if p.monitor != nil {
		p.monitor.Start(ctx)
		p.logger.Debug("Resource monitor started for adaptive throttling")
	}

	// Initialize stats
	p.statsLock.Lock()
	p.stats = PipelineStats{StartTime: time.Now()}
	p.statsLock.Unlock()

	// Create pipeline channels with buffering
	bufSize := 100
	p.discovered = make(chan *FileItem, bufSize)
	p.filtered = make(chan *FileItem, bufSize)
	p.read = make(chan *FileItem, bufSize)
	p.matched = make(chan *FileItem, bufSize)

	results := make(chan *ScanResult, bufSize)

	// Start pipeline stages
	p.startDiscoverStage(ctx, paths)
	p.startFilterStage(ctx)
	p.startReadStage(ctx)
	p.startMatchStage(ctx)
	p.startReportStage(ctx, results)

	return results, nil
}

// startDiscoverStage walks the filesystem and discovers files
func (p *PipelineScanner) startDiscoverStage(ctx context.Context, paths []string) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer close(p.discovered)

		visited := make(map[string]bool)

		for _, path := range paths {
			if p.isShutdown() {
				return
			}

			select {
			case <-ctx.Done():
				return
			default:
			}

			info, err := os.Stat(path)
			if err != nil {
				p.logger.Warning("Cannot access path %s: %v", path, err)
				continue
			}

			if info.IsDir() {
				p.walkDirectory(ctx, path, visited)
			} else {
				p.sendDiscovered(ctx, path, info, visited)
			}
		}
	}()
}

// walkDirectory recursively walks a directory
func (p *PipelineScanner) walkDirectory(ctx context.Context, dir string, visited map[string]bool) {
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if p.isShutdown() {
			return context.Canceled
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			if p.options.AllowIOErrors {
				p.logger.Warning("Error accessing %s: %v", path, err)
				return nil
			}
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Handle symlinks
		if d.Type()&fs.ModeSymlink != 0 {
			if !p.options.FollowSymlinks {
				atomic.AddInt64(&p.stats.FilesSkipped, 1)
				return nil
			}

			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				p.logger.Debug("Cannot resolve symlink %s: %v", path, err)
				return nil
			}

			if visited[resolved] {
				return nil
			}

			info, err := os.Stat(resolved)
			if err != nil {
				return nil
			}

			if info.IsDir() {
				p.walkDirectory(ctx, resolved, visited)
				return nil
			}

			p.sendDiscovered(ctx, resolved, info, visited)
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		p.sendDiscovered(ctx, path, info, visited)
		return nil
	})

	if err != nil && !errors.Is(err, context.Canceled) {
		p.logger.Warning("Error walking directory %s: %v", dir, err)
	}
}

// sendDiscovered sends a file to the discovered channel
func (p *PipelineScanner) sendDiscovered(ctx context.Context, path string, info os.FileInfo, visited map[string]bool) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	if visited[absPath] {
		return
	}
	visited[absPath] = true

	atomic.AddInt64(&p.stats.Discovered, 1)

	item := &FileItem{
		Path:   path,
		Info:   info,
		ScanID: p.scanID,
		Stage:  StageDiscover,
	}

	select {
	case <-ctx.Done():
		return
	case p.discovered <- item:
	}
}

// startFilterStage filters files based on configured rules
func (p *PipelineScanner) startFilterStage(ctx context.Context) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer close(p.filtered)

		for item := range p.discovered {
			if p.isShutdown() {
				return
			}

			select {
			case <-ctx.Done():
				return
			default:
			}

			// Apply filter
			if p.options.Filter != nil && !p.options.Filter.Filter(item.Path) {
				atomic.AddInt64(&p.stats.FilesSkipped, 1)
				continue
			}

			// Check file size limit
			if p.options.ContentLimit > 0 && item.Info.Size() > p.options.ContentLimit {
				item.Error = ErrFileTooLarge(item.Path, item.Info.Size(), p.options.ContentLimit)
				atomic.AddInt64(&p.stats.FilesSkipped, 1)
				continue
			}

			atomic.AddInt64(&p.stats.Filtered, 1)
			item.Stage = StageFilter

			select {
			case <-ctx.Done():
				return
			case p.filtered <- item:
			}
		}
	}()
}

// startReadStage reads file contents with rate limiting and buffer pooling
func (p *PipelineScanner) startReadStage(ctx context.Context) {
	// Use multiple readers for parallelism
	numReaders := p.options.Workers
	if numReaders < 1 {
		numReaders = 1
	}

	var readWg sync.WaitGroup
	for i := 0; i < numReaders; i++ {
		readWg.Add(1)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer readWg.Done()

			for item := range p.filtered {
				if p.isShutdown() {
					return
				}

				select {
				case <-ctx.Done():
					return
				default:
				}

				// Apply rate limiting
				if p.rateLimiter != nil {
					if err := p.rateLimiter.WaitForBytes(ctx, item.Info.Size()); err != nil {
						item.Error = NewScanError(ErrCodeRateLimited, item.Path, "read", "rate limit wait failed", err)
						atomic.AddInt64(&p.stats.FilesErrored, 1)
						atomic.AddInt64(&p.stats.RateLimitWaits, 1)
						continue
					}
				}

				// Apply dynamic delay from resource monitor
				if delay := p.getDynamicDelay(); delay > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(delay):
					}
				}

				// Read file with circuit breaker
				err := p.circuit.Execute(func() error {
					return p.readFileContent(item)
				})

				if errors.Is(err, ErrCircuitOpen) {
					item.Error = NewScanError(ErrCodeCircuitOpen, item.Path, "read", "circuit breaker open", err)
					atomic.AddInt64(&p.stats.FilesErrored, 1)
					atomic.AddInt64(&p.stats.CircuitBreaks, 1)
					continue
				}

				if item.Error != nil {
					atomic.AddInt64(&p.stats.FilesErrored, 1)
					continue
				}

				// Generate content hash for idempotency
				h := sha256.Sum256(item.Content)
				item.ContentHash = hex.EncodeToString(h[:])

				// Check for duplicate content
				if p.isDuplicate(item.ContentHash) {
					atomic.AddInt64(&p.stats.DuplicatesSkipped, 1)
					p.returnBuffer(item)
					continue
				}
				p.markProcessed(item.ContentHash)

				atomic.AddInt64(&p.stats.Read, 1)
				atomic.AddInt64(&p.stats.BytesScanned, int64(len(item.Content)))
				item.Stage = StageRead

				select {
				case <-ctx.Done():
					p.returnBuffer(item)
					return
				case p.read <- item:
				}
			}
		}()
	}

	// Close read channel when all readers are done
	go func() {
		readWg.Wait()
		close(p.read)
	}()
}

// readFileContent reads file content using pooled buffers
func (p *PipelineScanner) readFileContent(item *FileItem) error {
	file, err := os.Open(item.Path) // #nosec G304 -- scanning user-specified paths
	if err != nil {
		item.Error = ErrFileAccess(item.Path, err)
		return fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	size := item.Info.Size()
	if p.options.ContentLimit > 0 && size > p.options.ContentLimit {
		size = p.options.ContentLimit
	}

	// Get pooled buffer
	item.Content = p.bufferPool.GetForSize(size)
	item.ContentPool = p.bufferPool

	n, err := io.ReadFull(file, item.Content[:size])
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		p.returnBuffer(item)
		item.Error = ErrFileRead(item.Path, err)
		return fmt.Errorf("read file: %w", err)
	}

	// Trim to actual read size
	item.Content = item.Content[:n]
	return nil
}

// returnBuffer returns a buffer to the pool
func (p *PipelineScanner) returnBuffer(item *FileItem) {
	if item.ContentPool != nil && item.Content != nil {
		item.ContentPool.PutForSize(item.Content)
		item.Content = nil
		item.ContentPool = nil
	}
}

// startMatchStage performs pattern matching on file contents
func (p *PipelineScanner) startMatchStage(ctx context.Context) {
	// Use multiple matchers for parallelism
	numMatchers := p.options.Workers
	if numMatchers < 1 {
		numMatchers = 1
	}

	var matchWg sync.WaitGroup
	for i := 0; i < numMatchers; i++ {
		matchWg.Add(1)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer matchWg.Done()

			for item := range p.read {
				if p.isShutdown() {
					p.returnBuffer(item)
					return
				}

				start := time.Now()

				select {
				case <-ctx.Done():
					p.returnBuffer(item)
					return
				default:
				}

				// Apply dynamic delay from resource monitor
				if delay := p.getDynamicDelay(); delay > 0 {
					select {
					case <-ctx.Done():
						p.returnBuffer(item)
						return
					case <-time.After(delay):
					}
				}

				// Match against signatures
				matchCtx := p.matcher.NewMatchContext()
				if err := matchCtx.Match(ctx, item.Content); err != nil {
					if !errors.Is(err, context.Canceled) {
						p.logger.Debug("Match error for %s: %v", item.Path, err)
					}
				}

				item.Matches = matchCtx.GetMatches()
				item.Timeouts = matchCtx.GetTimeouts()
				item.ScanDuration = time.Since(start)
				item.Stage = StageMatch

				// Return buffer after matching
				p.returnBuffer(item)

				if len(item.Matches) > 0 {
					atomic.AddInt64(&p.stats.FilesWithMatches, 1)
				}

				atomic.AddInt64(&p.stats.Matched, 1)

				select {
				case <-ctx.Done():
					return
				case p.matched <- item:
				}
			}
		}()
	}

	// Close matched channel when all matchers are done
	go func() {
		matchWg.Wait()
		close(p.matched)
	}()
}

// startReportStage converts pipeline items to results
func (p *PipelineScanner) startReportStage(ctx context.Context, results chan<- *ScanResult) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer func() {
			p.statsLock.Lock()
			p.stats.EndTime = time.Now()
			p.stats.Duration = p.stats.EndTime.Sub(p.stats.StartTime)
			p.stats.BufferPoolHitRate = p.bufferPool.HitRate()
			p.statsLock.Unlock()
			close(results)
		}()

		for item := range p.matched {
			if p.isShutdown() {
				return
			}

			result := &ScanResult{
				Path:         item.Path,
				Matches:      item.Matches,
				Timeouts:     item.Timeouts,
				ScannedBytes: int64(len(item.Content)),
				ScanDuration: item.ScanDuration,
			}

			if item.Error != nil {
				result.Error = item.Error
			}

			atomic.AddInt64(&p.stats.Reported, 1)

			select {
			case <-ctx.Done():
				return
			case results <- result:
			}
		}
	}()
}

// isDuplicate checks if a content hash has been processed
func (p *PipelineScanner) isDuplicate(hash string) bool {
	p.processedMu.RLock()
	defer p.processedMu.RUnlock()
	return p.processedSet[hash]
}

// markProcessed marks a content hash as processed
func (p *PipelineScanner) markProcessed(hash string) {
	p.processedMu.Lock()
	defer p.processedMu.Unlock()
	p.processedSet[hash] = true
}

// isShutdown checks if shutdown has been initiated
func (p *PipelineScanner) isShutdown() bool {
	p.shutdownMu.RLock()
	defer p.shutdownMu.RUnlock()
	return p.shutdown
}

// SetDynamicDelay sets a dynamic delay from resource monitoring
func (p *PipelineScanner) SetDynamicDelay(d time.Duration) {
	p.dynamicDelay.Store(int64(d))
	if d > 0 {
		p.logger.Debug("Dynamic delay adjusted to %v", d)
	}
}

// getDynamicDelay returns the current dynamic delay
func (p *PipelineScanner) getDynamicDelay() time.Duration {
	return time.Duration(p.dynamicDelay.Load())
}

// Shutdown gracefully stops the pipeline
func (p *PipelineScanner) Shutdown(ctx context.Context) error {
	p.shutdownMu.Lock()
	if p.shutdown {
		p.shutdownMu.Unlock()
		return nil
	}
	p.shutdown = true
	p.shutdownMu.Unlock()

	p.logger.Info("Initiating graceful shutdown...")

	// Signal done
	close(p.done)

	// Stop resource monitor
	if p.monitor != nil {
		p.monitor.Stop()
	}

	// Close rate limiter
	if p.rateLimiter != nil {
		p.rateLimiter.Close()
	}

	// Wait for all goroutines with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		p.logger.Info("Graceful shutdown complete")
		return nil
	case <-ctx.Done():
		p.logger.Warning("Shutdown timeout, some goroutines may still be running")
		return fmt.Errorf("shutdown: %w", ctx.Err())
	}
}

// GetStats returns the current pipeline statistics
func (p *PipelineScanner) GetStats() PipelineStats {
	p.statsLock.Lock()
	defer p.statsLock.Unlock()
	return p.stats
}

// GetScanID returns the current scan's idempotency key
func (p *PipelineScanner) GetScanID() string {
	return p.scanID
}

// DrainResults reads all remaining results from a channel
// Useful for cleanup when cancelling a scan
func DrainResults(results <-chan *ScanResult) int {
	count := 0
	for range results {
		count++
	}
	return count
}

// HitRate returns the buffer pool hit rate
func (p *ContentPool) HitRate() float64 {
	// Average of all pool hit rates
	smallHit := p.small.HitRate()
	medHit := p.medium.HitRate()
	largeHit := p.large.HitRate()
	return (smallHit + medHit + largeHit) / 3.0
}
