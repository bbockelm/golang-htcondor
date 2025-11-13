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
	collectors []Collector
	mu         sync.RWMutex
	cache      []Metric
	cacheTime  time.Time
	cacheTTL   time.Duration
}

// NewRegistry creates a new metric registry
func NewRegistry() *Registry {
	return &Registry{
		collectors: make([]Collector, 0),
		cache:      make([]Metric, 0),
		cacheTTL:   10 * time.Second, // Default 10 second cache
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

// Collect gathers all metrics from registered collectors
func (r *Registry) Collect(ctx context.Context) ([]Metric, error) {
	r.mu.RLock()
	// Check if cache is still valid
	if time.Since(r.cacheTime) < r.cacheTTL && len(r.cache) > 0 {
		metrics := make([]Metric, len(r.cache))
		copy(metrics, r.cache)
		r.mu.RUnlock()
		return metrics, nil
	}
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
