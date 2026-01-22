// Package scanner provides the malware scanner implementation
package scanner

import (
	"context"
	"runtime"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"

	"github.com/greysquirr3l/wordfence-go/internal/intel"
	"github.com/greysquirr3l/wordfence-go/internal/logging"
)

// Profile represents a scanning performance profile
type Profile string

const (
	// ProfileGentle minimizes resource usage - slow but safe for production
	ProfileGentle Profile = "gentle"
	// ProfileBalanced provides reasonable speed with moderate resources
	ProfileBalanced Profile = "balanced"
	// ProfileAggressive uses maximum resources for fastest scanning
	ProfileAggressive Profile = "aggressive"
	// ProfileAdaptive dynamically adjusts based on system conditions
	ProfileAdaptive Profile = "adaptive"
)

// ProfileSettings contains the scanner settings for a profile
type ProfileSettings struct {
	Workers       int
	ScanDelayMS   int
	ChunkSizeKB   int
	MaxFileSizeMB int
	BatchSize     int
	BatchPauseMS  int
	MaxLoadAvg    float64
	MemoryLimitMB int
	IOLimitMBps   int64
}

// DefaultProfiles returns the predefined performance profiles
func DefaultProfiles() map[Profile]ProfileSettings {
	numCPU := runtime.NumCPU()

	return map[Profile]ProfileSettings{
		ProfileGentle: {
			Workers:       1,
			ScanDelayMS:   100,
			ChunkSizeKB:   256,
			MaxFileSizeMB: 10,
			BatchSize:     50,
			BatchPauseMS:  1000,
			MaxLoadAvg:    2.0,
			MemoryLimitMB: 256,
			IOLimitMBps:   5,
		},
		ProfileBalanced: {
			Workers:       max(1, numCPU/2),
			ScanDelayMS:   25,
			ChunkSizeKB:   512,
			MaxFileSizeMB: 50,
			BatchSize:     100,
			BatchPauseMS:  500,
			MaxLoadAvg:    float64(numCPU) * 0.75,
			MemoryLimitMB: 512,
			IOLimitMBps:   20,
		},
		ProfileAggressive: {
			Workers:       numCPU,
			ScanDelayMS:   0,
			ChunkSizeKB:   1024,
			MaxFileSizeMB: 0, // unlimited
			BatchSize:     0, // no batching
			BatchPauseMS:  0,
			MaxLoadAvg:    0, // no limit
			MemoryLimitMB: 0, // no limit
			IOLimitMBps:   0, // no limit
		},
		ProfileAdaptive: {
			// Base settings - will be adjusted dynamically
			Workers:       max(1, numCPU/2),
			ScanDelayMS:   10,
			ChunkSizeKB:   512,
			MaxFileSizeMB: 100,
			BatchSize:     0,
			BatchPauseMS:  0,
			MaxLoadAvg:    0, // Handled by adaptive monitor
			MemoryLimitMB: 0, // Handled by adaptive monitor
			IOLimitMBps:   0, // Handled by adaptive monitor
		},
	}
}

// ResourceMetrics contains current system resource measurements
type ResourceMetrics struct {
	// Memory metrics
	HeapAllocMB   float64
	HeapInUseMB   float64
	TotalAllocMB  float64
	GCPauseNS     uint64
	NumGC         uint32
	GCCPUFraction float64
	HeapGoalMB    float64
	LiveObjectsMB float64

	// Goroutine metrics
	NumGoroutines  int
	SchedLatencyNS float64

	// System metrics (where available)
	LoadAvg1  float64
	LoadAvg5  float64
	LoadAvg15 float64

	// I/O metrics (tracked internally)
	BytesReadSec int64

	// Timestamps
	CollectedAt time.Time
}

// ResourceMonitor provides dynamic resource monitoring and adjustment
type ResourceMonitor struct {
	logger        *logging.Logger
	metrics       atomic.Pointer[ResourceMetrics]
	targetWorkers atomic.Int32
	targetDelay   atomic.Int64 // nanoseconds
	throttleLevel atomic.Int32 // 0=none, 1=light, 2=medium, 3=heavy

	// Configuration
	maxMemoryMB     int
	maxLoadAvg      float64
	targetGCPercent float64
	interval        time.Duration // monitoring interval

	// Control
	running atomic.Bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Callbacks for dynamic adjustment
	onAdjust func(workers int, delayNS int64)
}

// MonitorOption configures a ResourceMonitor
type MonitorOption func(*ResourceMonitor)

// WithMonitorLogger sets the logger for the monitor
func WithMonitorLogger(logger *logging.Logger) MonitorOption {
	return func(m *ResourceMonitor) {
		m.logger = logger
	}
}

// WithMaxMemoryMB sets the maximum memory threshold for throttling
func WithMaxMemoryMB(mb int) MonitorOption {
	return func(m *ResourceMonitor) {
		m.maxMemoryMB = mb
	}
}

// WithMaxLoadAverage sets the maximum load average for throttling
func WithMaxLoadAverage(load float64) MonitorOption {
	return func(m *ResourceMonitor) {
		m.maxLoadAvg = load
	}
}

// WithTargetGCPercent sets the target GC CPU percentage (0-1)
func WithTargetGCPercent(percent float64) MonitorOption {
	return func(m *ResourceMonitor) {
		m.targetGCPercent = percent
	}
}

// WithAdjustCallback sets a callback for when resources are adjusted
func WithAdjustCallback(fn func(workers int, delayNS int64)) MonitorOption {
	return func(m *ResourceMonitor) {
		m.onAdjust = fn
	}
}

// WithMonitorInterval sets the monitoring interval
func WithMonitorInterval(d time.Duration) MonitorOption {
	return func(m *ResourceMonitor) {
		if d > 0 {
			m.interval = d
		}
	}
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor(opts ...MonitorOption) *ResourceMonitor {
	m := &ResourceMonitor{
		logger:          logging.New(logging.LevelInfo),
		maxMemoryMB:     0,                      // unlimited by default
		maxLoadAvg:      0,                      // unlimited by default
		targetGCPercent: 0.10,                   // 10% GC CPU is acceptable
		interval:        500 * time.Millisecond, // default monitoring interval
		stopCh:          make(chan struct{}),
	}

	// Set defaults
	numCPU := runtime.NumCPU()
	// int32 max is 2^31-1 (2,147,483,647), but realistically no system has that many CPUs
	if numCPU > 0 && numCPU <= (1<<31-1) {
		m.targetWorkers.Store(int32(numCPU)) //#nosec G115 -- validated range
	} else {
		m.targetWorkers.Store(4) // fallback
	}
	m.targetDelay.Store(0)
	m.throttleLevel.Store(0)

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Start begins the monitoring goroutine
func (m *ResourceMonitor) Start(ctx context.Context) {
	if m.running.Swap(true) {
		return // Already running
	}

	m.wg.Add(1)
	go m.monitorLoop(ctx)
}

// Stop halts the monitoring goroutine
func (m *ResourceMonitor) Stop() {
	if !m.running.Swap(false) {
		return // Not running
	}

	close(m.stopCh)
	m.wg.Wait()
}

// GetMetrics returns the most recent metrics snapshot
func (m *ResourceMonitor) GetMetrics() *ResourceMetrics {
	return m.metrics.Load()
}

// GetRecommendedWorkers returns the current recommended worker count
func (m *ResourceMonitor) GetRecommendedWorkers() int {
	return int(m.targetWorkers.Load())
}

// GetRecommendedDelay returns the current recommended delay between files
func (m *ResourceMonitor) GetRecommendedDelay() time.Duration {
	return time.Duration(m.targetDelay.Load())
}

// GetThrottleLevel returns the current throttle level (0-3)
func (m *ResourceMonitor) GetThrottleLevel() int {
	return int(m.throttleLevel.Load())
}

// ShouldThrottle returns true if the system is under pressure
func (m *ResourceMonitor) ShouldThrottle() bool {
	return m.throttleLevel.Load() > 0
}

// monitorLoop runs the monitoring cycle
func (m *ResourceMonitor) monitorLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.collectMetrics()
			m.adjustResources()
		}
	}
}

// collectMetrics gathers current system metrics
func (m *ResourceMonitor) collectMetrics() {
	rm := &ResourceMetrics{
		CollectedAt:   time.Now(),
		NumGoroutines: runtime.NumGoroutine(),
	}

	// Collect runtime.MemStats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	rm.HeapAllocMB = float64(memStats.HeapAlloc) / (1024 * 1024)
	rm.HeapInUseMB = float64(memStats.HeapInuse) / (1024 * 1024)
	rm.TotalAllocMB = float64(memStats.TotalAlloc) / (1024 * 1024)
	rm.GCPauseNS = memStats.PauseNs[(memStats.NumGC+255)%256]
	rm.NumGC = memStats.NumGC
	rm.GCCPUFraction = memStats.GCCPUFraction

	// Use runtime/metrics for more detailed data (Go 1.16+)
	m.collectRuntimeMetrics(rm)

	// Collect system metrics (platform-specific)
	m.collectSystemMetrics(rm)

	m.metrics.Store(rm)
}

// collectRuntimeMetrics uses the runtime/metrics package for detailed metrics
func (m *ResourceMonitor) collectRuntimeMetrics(rm *ResourceMetrics) {
	// Define the metrics we want to read
	descs := []metrics.Description{
		{Name: "/gc/heap/goal:bytes", Kind: metrics.KindUint64},
		{Name: "/gc/heap/live:bytes", Kind: metrics.KindUint64},
		{Name: "/sched/latencies:seconds", Kind: metrics.KindFloat64Histogram},
	}

	// Read the metrics
	samples := make([]metrics.Sample, len(descs))
	for i, desc := range descs {
		samples[i].Name = desc.Name
	}
	metrics.Read(samples)

	// Process the samples
	for _, sample := range samples {
		switch sample.Name {
		case "/gc/heap/goal:bytes":
			if sample.Value.Kind() == metrics.KindUint64 {
				rm.HeapGoalMB = float64(sample.Value.Uint64()) / (1024 * 1024)
			}
		case "/gc/heap/live:bytes":
			if sample.Value.Kind() == metrics.KindUint64 {
				rm.LiveObjectsMB = float64(sample.Value.Uint64()) / (1024 * 1024)
			}
		case "/sched/latencies:seconds":
			if sample.Value.Kind() == metrics.KindFloat64Histogram {
				hist := sample.Value.Float64Histogram()
				if len(hist.Counts) > 0 && len(hist.Buckets) > 1 {
					// Calculate approximate median latency
					rm.SchedLatencyNS = m.histogramMedian(hist) * 1e9
				}
			}
		}
	}
}

// histogramMedian calculates the approximate median from a histogram
func (m *ResourceMonitor) histogramMedian(hist *metrics.Float64Histogram) float64 {
	var total uint64
	for _, c := range hist.Counts {
		total += c
	}
	if total == 0 {
		return 0
	}

	target := total / 2
	var cumulative uint64
	for i, c := range hist.Counts {
		cumulative += c
		if cumulative >= target {
			if i < len(hist.Buckets)-1 {
				return (hist.Buckets[i] + hist.Buckets[i+1]) / 2
			}
			return hist.Buckets[i]
		}
	}
	return 0
}

// collectSystemMetrics gathers OS-level metrics
func (m *ResourceMonitor) collectSystemMetrics(rm *ResourceMetrics) {
	// Load average (Unix only)
	if load, err := getLoadAvg(); err == nil {
		rm.LoadAvg1 = load
	}

	// Additional load averages could be collected from /proc/loadavg fields 2 and 3
}

// adjustResources calculates and applies resource adjustments
func (m *ResourceMonitor) adjustResources() {
	rm := m.metrics.Load()
	if rm == nil {
		return
	}

	numCPU := runtime.NumCPU()
	oldLevel := m.throttleLevel.Load()
	newLevel := int32(0)
	workers := numCPU
	delayNS := int64(0)

	// Check memory pressure
	if m.maxMemoryMB > 0 {
		memUsagePercent := rm.HeapAllocMB / float64(m.maxMemoryMB)
		if memUsagePercent > 0.9 {
			newLevel = max(newLevel, 3)
			workers = 1
			delayNS = int64(200 * time.Millisecond)
		} else if memUsagePercent > 0.75 {
			newLevel = max(newLevel, 2)
			workers = max(1, numCPU/4)
			delayNS = int64(100 * time.Millisecond)
		} else if memUsagePercent > 0.5 {
			newLevel = max(newLevel, 1)
			workers = max(1, numCPU/2)
			delayNS = int64(50 * time.Millisecond)
		}
	}

	// Check GC pressure
	if rm.GCCPUFraction > m.targetGCPercent*2 {
		newLevel = max(newLevel, 2)
		workers = min(workers, max(1, numCPU/4))
		delayNS = max(delayNS, int64(100*time.Millisecond))
	} else if rm.GCCPUFraction > m.targetGCPercent {
		newLevel = max(newLevel, 1)
		workers = min(workers, max(1, numCPU/2))
		delayNS = max(delayNS, int64(50*time.Millisecond))
	}

	// Check system load (Unix)
	if m.maxLoadAvg > 0 && rm.LoadAvg1 > 0 {
		loadPercent := rm.LoadAvg1 / m.maxLoadAvg
		if loadPercent > 1.5 {
			newLevel = max(newLevel, 3)
			workers = 1
			delayNS = max(delayNS, int64(200*time.Millisecond))
		} else if loadPercent > 1.2 {
			newLevel = max(newLevel, 2)
			workers = min(workers, max(1, numCPU/4))
			delayNS = max(delayNS, int64(100*time.Millisecond))
		} else if loadPercent > 1.0 {
			newLevel = max(newLevel, 1)
			workers = min(workers, max(1, numCPU/2))
			delayNS = max(delayNS, int64(50*time.Millisecond))
		}
	}

	// Check scheduler latency (indicates goroutine contention)
	if rm.SchedLatencyNS > 10e6 { // > 10ms
		newLevel = max(newLevel, 2)
		workers = min(workers, max(1, numCPU/2))
		delayNS = max(delayNS, int64(50*time.Millisecond))
	}

	// Check goroutine count (too many can cause issues)
	if rm.NumGoroutines > numCPU*100 {
		newLevel = max(newLevel, 1)
		workers = min(workers, max(1, numCPU/2))
	}

	// Apply changes
	m.throttleLevel.Store(newLevel)
	// int32 max is 2^31-1 (2,147,483,647)
	if workers > 0 && workers <= (1<<31-1) {
		m.targetWorkers.Store(int32(workers)) //#nosec G115 -- validated range
	}
	m.targetDelay.Store(delayNS)

	// Log level changes
	if newLevel != oldLevel {
		levelNames := []string{"none", "light", "medium", "heavy"}
		m.logger.Debug("Throttle level changed: %s -> %s (workers=%d, delay=%v)",
			levelNames[oldLevel], levelNames[newLevel], workers, time.Duration(delayNS))
	}

	// Notify callback if set
	if m.onAdjust != nil && (newLevel != oldLevel) {
		m.onAdjust(workers, delayNS)
	}
}

// AdaptiveScanner wraps a Scanner with dynamic resource adjustment
type AdaptiveScanner struct {
	*Scanner
	monitor *ResourceMonitor
}

// NewAdaptiveScanner creates a scanner with adaptive resource management
func NewAdaptiveScanner(sigSet *intel.SignatureSet, profile Profile, opts ...Option) *AdaptiveScanner {
	profiles := DefaultProfiles()
	settings, ok := profiles[profile]
	if !ok {
		settings = profiles[ProfileBalanced]
	}

	// Build scanner options from profile
	scannerOpts := []Option{
		WithScanWorkers(settings.Workers),
	}

	if settings.ScanDelayMS > 0 {
		scannerOpts = append(scannerOpts, WithScanDelay(time.Duration(settings.ScanDelayMS)*time.Millisecond))
	}
	if settings.ChunkSizeKB > 0 {
		scannerOpts = append(scannerOpts, WithChunkSize(settings.ChunkSizeKB*1024))
	}
	if settings.MaxFileSizeMB > 0 {
		scannerOpts = append(scannerOpts, WithContentLimit(int64(settings.MaxFileSizeMB)*1024*1024))
	}
	if settings.BatchSize > 0 {
		scannerOpts = append(scannerOpts, WithBatchSize(settings.BatchSize))
	}
	if settings.BatchPauseMS > 0 {
		scannerOpts = append(scannerOpts, WithBatchPause(settings.BatchPauseMS))
	}
	if settings.MaxLoadAvg > 0 {
		scannerOpts = append(scannerOpts, WithMaxLoadAvg(settings.MaxLoadAvg))
	}
	if settings.MemoryLimitMB > 0 {
		scannerOpts = append(scannerOpts, WithMemoryLimit(settings.MemoryLimitMB))
	}
	if settings.IOLimitMBps > 0 {
		scannerOpts = append(scannerOpts, WithIOBytesPerSec(settings.IOLimitMBps*1024*1024))
	}

	// Append user-provided options (can override profile settings)
	scannerOpts = append(scannerOpts, opts...)

	scanner := NewScanner(sigSet, scannerOpts...)

	as := &AdaptiveScanner{
		Scanner: scanner,
	}

	// Set up adaptive monitor if using adaptive profile
	if profile == ProfileAdaptive {
		as.monitor = NewResourceMonitor(
			WithMonitorLogger(scanner.logger),
			WithMaxMemoryMB(512),
			WithMaxLoadAverage(float64(runtime.NumCPU())),
			WithTargetGCPercent(0.10),
		)
	}

	return as
}

// Scan scans the given paths with adaptive resource management
func (as *AdaptiveScanner) Scan(ctx context.Context, paths ...string) (<-chan *ScanResult, error) {
	if as.monitor != nil {
		// Wire monitor adjustments to scanner's dynamic delay
		as.monitor.onAdjust = func(_ int, delayNS int64) {
			as.SetDynamicDelay(time.Duration(delayNS))
		}
		as.monitor.Start(ctx)
	}

	results, err := as.Scanner.Scan(ctx, paths...)
	if err != nil {
		if as.monitor != nil {
			as.monitor.Stop()
		}
		return nil, err
	}

	// Wrap results to stop monitor when done
	wrappedResults := make(chan *ScanResult, 100)
	go func() {
		defer func() {
			if as.monitor != nil {
				as.monitor.Stop()
			}
			close(wrappedResults)
		}()
		for result := range results {
			wrappedResults <- result
		}
	}()

	return wrappedResults, nil
}

// GetMonitor returns the resource monitor (if adaptive mode)
func (as *AdaptiveScanner) GetMonitor() *ResourceMonitor {
	return as.monitor
}
