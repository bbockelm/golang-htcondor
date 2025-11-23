package metricsd

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// callCountingCollector wraps a collector and counts calls
type callCountingCollector struct {
	collector Collector
	callCount *int32
}

func (c *callCountingCollector) Collect(ctx context.Context) ([]Metric, error) {
	atomic.AddInt32(c.callCount, 1)
	return c.collector.Collect(ctx)
}

// dynamicCollector returns metrics with changing values
type dynamicCollector struct {
	name     string
	getValue func() float64
}

func (c *dynamicCollector) Collect(_ context.Context) ([]Metric, error) {
	return []Metric{
		{
			Name:      c.name,
			Type:      MetricTypeGauge,
			Value:     c.getValue(),
			Timestamp: time.Now(),
		},
	}, nil
}

// TestSetQueryInterval tests the query interval configuration
func TestSetQueryInterval(t *testing.T) {
	registry := NewRegistry()

	// Default should be 60 seconds
	if registry.queryInterval != 60*time.Second {
		t.Errorf("Default query interval = %v, expected 60s", registry.queryInterval)
	}

	// Set custom interval
	registry.SetQueryInterval(30 * time.Second)
	if registry.queryInterval != 30*time.Second {
		t.Errorf("Query interval = %v, expected 30s", registry.queryInterval)
	}

	// Test zero interval (background collection disabled)
	registry.SetQueryInterval(0)
	if registry.queryInterval != 0 {
		t.Errorf("Query interval = %v, expected 0", registry.queryInterval)
	}
}

// TestBackgroundCollection tests that background collection is started on first Collect
func TestBackgroundCollection(t *testing.T) {
	registry := NewRegistry()
	registry.SetQueryInterval(100 * time.Millisecond)
	registry.SetCacheTTL(50 * time.Millisecond)

	var callCount int32
	baseCollector := &mockCollector{
		metrics: []Metric{
			{
				Name:      "test_metric",
				Type:      MetricTypeGauge,
				Value:     42.0,
				Timestamp: time.Now(),
			},
		},
	}

	collector := &callCountingCollector{
		collector: baseCollector,
		callCount: &callCount,
	}

	registry.Register(collector)

	ctx := context.Background()

	// First call - should trigger background collection
	metrics1, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(metrics1) != 1 {
		t.Fatalf("Expected 1 metric, got %d", len(metrics1))
	}

	// Wait for background collection to run at least once
	time.Sleep(250 * time.Millisecond)

	// Verify background collection is running
	count := atomic.LoadInt32(&callCount)
	if count < 2 {
		t.Errorf("Expected at least 2 calls (initial + background), got %d", count)
	}

	// Stop background collection
	registry.Stop()

	// Wait a bit and verify no more collections happen
	beforeStopCount := atomic.LoadInt32(&callCount)
	time.Sleep(200 * time.Millisecond)
	afterStopCount := atomic.LoadInt32(&callCount)
	if afterStopCount != beforeStopCount {
		t.Errorf("Expected no more collections after Stop(), but got %d more", afterStopCount-beforeStopCount)
	}
}

// TestBackgroundCollectionDisabled tests that background collection can be disabled
func TestBackgroundCollectionDisabled(t *testing.T) {
	registry := NewRegistry()
	registry.SetQueryInterval(0) // Disable background collection
	registry.SetCacheTTL(50 * time.Millisecond)

	var callCount int32
	baseCollector := &mockCollector{
		metrics: []Metric{
			{
				Name:  "test_metric",
				Type:  MetricTypeGauge,
				Value: 42.0,
			},
		},
	}

	collector := &callCountingCollector{
		collector: baseCollector,
		callCount: &callCount,
	}

	registry.Register(collector)

	ctx := context.Background()

	// First call
	_, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Wait to see if background collection happens
	time.Sleep(200 * time.Millisecond)

	// Should only have been called once (no background collection)
	count := atomic.LoadInt32(&callCount)
	if count != 1 {
		t.Errorf("Expected exactly 1 call with background disabled, got %d", count)
	}
}

// TestCacheReturnsPreCalculatedResults tests that cache returns pre-calculated results
func TestCacheReturnsPreCalculatedResults(t *testing.T) {
	registry := NewRegistry()
	registry.SetCacheTTL(500 * time.Millisecond)
	registry.SetQueryInterval(0) // Disable background for this test

	var callCount int32
	collector := &dynamicCollector{
		name: "changing_metric",
		getValue: func() float64 {
			return float64(atomic.AddInt32(&callCount, 1))
		},
	}

	registry.Register(collector)

	ctx := context.Background()

	// First call - should collect
	metrics1, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if metrics1[0].Value != 1.0 {
		t.Errorf("First call: expected value 1.0, got %v", metrics1[0].Value)
	}
	count1 := atomic.LoadInt32(&callCount)
	if count1 != 1 {
		t.Errorf("Expected 1 collection call, got %d", count1)
	}

	// Second call within cache TTL - should use cache
	metrics2, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if metrics2[0].Value != 1.0 {
		t.Errorf("Second call (cached): expected value 1.0, got %v", metrics2[0].Value)
	}
	count2 := atomic.LoadInt32(&callCount)
	if count2 != 1 {
		t.Errorf("Expected still 1 collection call (cached), got %d", count2)
	}

	// Wait for cache to expire
	time.Sleep(550 * time.Millisecond)

	// Third call after cache expired - should collect again
	metrics3, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if metrics3[0].Value != 2.0 {
		t.Errorf("Third call (cache expired): expected value 2.0, got %v", metrics3[0].Value)
	}
	count3 := atomic.LoadInt32(&callCount)
	if count3 != 2 {
		t.Errorf("Expected 2 collection calls after cache expiry, got %d", count3)
	}
}

// TestBackgroundCollectionUpdatesCache tests that background collection updates the cache
func TestBackgroundCollectionUpdatesCache(t *testing.T) {
	registry := NewRegistry()
	registry.SetQueryInterval(100 * time.Millisecond)
	registry.SetCacheTTL(5 * time.Second) // Long cache so we can verify background updates

	var counter int32
	collector := &dynamicCollector{
		name: "dynamic_metric",
		getValue: func() float64 {
			return float64(atomic.AddInt32(&counter, 1))
		},
	}

	registry.Register(collector)

	ctx := context.Background()

	// First call - starts background collection
	metrics1, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	initialValue := metrics1[0].Value

	// Wait for background collection to run
	time.Sleep(250 * time.Millisecond)

	// Get cached metrics - should have updated value from background
	metrics2, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if metrics2[0].Value <= initialValue {
		t.Errorf("Expected value to increase from background collection, got %v (initial: %v)",
			metrics2[0].Value, initialValue)
	}

	registry.Stop()
}

// TestMultipleCollectorsBackgroundCollection tests background collection with multiple collectors
func TestMultipleCollectorsBackgroundCollection(t *testing.T) {
	registry := NewRegistry()
	registry.SetQueryInterval(100 * time.Millisecond)
	registry.SetCacheTTL(5 * time.Second)

	var collector1CallCount, collector2CallCount int32

	collector1 := &callCountingCollector{
		collector: &mockCollector{
			metrics: []Metric{{Name: "metric1", Type: MetricTypeGauge, Value: 1.0}},
		},
		callCount: &collector1CallCount,
	}

	collector2 := &callCountingCollector{
		collector: &mockCollector{
			metrics: []Metric{{Name: "metric2", Type: MetricTypeGauge, Value: 2.0}},
		},
		callCount: &collector2CallCount,
	}

	registry.Register(collector1)
	registry.Register(collector2)

	ctx := context.Background()

	// First call
	metrics, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("Expected 2 metrics, got %d", len(metrics))
	}

	// Wait for background collection
	time.Sleep(250 * time.Millisecond)

	// Both collectors should have been called multiple times
	count1 := atomic.LoadInt32(&collector1CallCount)
	count2 := atomic.LoadInt32(&collector2CallCount)

	if count1 < 2 {
		t.Errorf("Expected collector1 called at least 2 times, got %d", count1)
	}
	if count2 < 2 {
		t.Errorf("Expected collector2 called at least 2 times, got %d", count2)
	}

	registry.Stop()
}

// TestStopBeforeStart tests that Stop is safe to call before any collection
func TestStopBeforeStart(t *testing.T) {
	registry := NewRegistry()

	// Should not panic
	registry.Stop()

	// Should still work after Stop
	collector := &mockCollector{
		metrics: []Metric{{Name: "test", Type: MetricTypeGauge, Value: 1.0}},
	}
	registry.Register(collector)

	ctx := context.Background()
	metrics, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(metrics) != 1 {
		t.Fatalf("Expected 1 metric, got %d", len(metrics))
	}
}
