// Package metricsd provides metrics collection for HTCondor daemons
// This is inspired by condor_gangliad but designed for more general metric export
package metricsd

import (
	"context"
	"sync"
	"time"
)

// MetricType represents the type of metric
type MetricType int

const (
	// MetricTypeGauge represents a gauge metric (current value)
	MetricTypeGauge MetricType = iota
	// MetricTypeCounter represents a counter metric (monotonically increasing)
	MetricTypeCounter
	// MetricTypeHistogram represents a histogram metric
	MetricTypeHistogram
)

// Metric represents a single metric
type Metric struct {
	Name      string            // Metric name
	Type      MetricType        // Metric type
	Value     float64           // Current value
	Labels    map[string]string // Metric labels
	Timestamp time.Time         // When the metric was collected
	Help      string            // Description of the metric
}

// Collector is an interface for components that collect metrics
type Collector interface {
	// Collect gathers metrics and returns them
	Collect(ctx context.Context) ([]Metric, error)
}

// Registry manages a collection of metric collectors
type Registry struct {
	collectors      []Collector
	mu              sync.RWMutex
	cache           []Metric
	cacheTime       time.Time
	cacheTTL        time.Duration
	queryInterval   time.Duration
	backgroundQuery bool
	stopCh          chan struct{}
	collectOnce     sync.Once
	collecting      bool
}

// NewRegistry creates a new metric registry
func NewRegistry() *Registry {
	return &Registry{
		collectors:    make([]Collector, 0),
		cache:         make([]Metric, 0),
		cacheTTL:      10 * time.Second, // Default 10 second cache
		queryInterval: 60 * time.Second, // Default 60 second query interval
		stopCh:        make(chan struct{}),
	}
}

// Register adds a collector to the registry
func (r *Registry) Register(collector Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors = append(r.collectors, collector)
}

// SetCacheTTL sets the cache time-to-live duration
func (r *Registry) SetCacheTTL(ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cacheTTL = ttl
}

// SetQueryInterval sets the interval for background metric collection
// This controls how often the collectors query HTCondor for updated metrics.
// Default is 60 seconds. Set to 0 to disable background collection.
func (r *Registry) SetQueryInterval(interval time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queryInterval = interval
}

// Stop stops the background collection goroutine if running
func (r *Registry) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.backgroundQuery {
		close(r.stopCh)
		r.backgroundQuery = false
	}
}

// Collect gathers all metrics from registered collectors
// On the first call, it starts a background goroutine for periodic collection
// if queryInterval > 0. Subsequent calls return pre-calculated results from cache.
func (r *Registry) Collect(ctx context.Context) ([]Metric, error) {
	r.mu.RLock()
	// Check if cache is still valid
	if time.Since(r.cacheTime) < r.cacheTTL && len(r.cache) > 0 {
		metrics := make([]Metric, len(r.cache))
		copy(metrics, r.cache)
		r.mu.RUnlock()
		return metrics, nil
	}
	queryInterval := r.queryInterval
	collecting := r.collecting
	r.mu.RUnlock()

	// Start background collection on first query if not already collecting
	if queryInterval > 0 && !collecting {
		r.collectOnce.Do(func() {
			r.mu.Lock()
			r.collecting = true
			r.backgroundQuery = true
			r.mu.Unlock()
			go r.backgroundCollect(context.Background())
		})
	}

	// Collect metrics immediately for the first request or if background is disabled
	return r.collectMetrics(ctx)
}

// collectMetrics performs the actual metric collection from all collectors
func (r *Registry) collectMetrics(ctx context.Context) ([]Metric, error) {
	r.mu.RLock()
	collectors := make([]Collector, len(r.collectors))
	copy(collectors, r.collectors)
	r.mu.RUnlock()

	// Collect metrics from all collectors
	allMetrics := make([]Metric, 0)
	for _, collector := range collectors {
		metrics, err := collector.Collect(ctx)
		if err != nil {
			// Log error but continue with other collectors
			// In production, you might want to use a proper logger
			continue
		}
		allMetrics = append(allMetrics, metrics...)
	}

	// Update cache
	r.mu.Lock()
	r.cache = allMetrics
	r.cacheTime = time.Now()
	r.mu.Unlock()

	return allMetrics, nil
}

// backgroundCollect runs periodic metric collection in the background
func (r *Registry) backgroundCollect(ctx context.Context) {
	r.mu.RLock()
	interval := r.queryInterval
	r.mu.RUnlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Collect metrics and update cache
			_, _ = r.collectMetrics(ctx)
		case <-r.stopCh:
			return
		}
	}
}
