package metricsd

import (
	"context"
	"strings"
	"testing"
	"time"
)

// mockCollector is a mock collector for testing
type mockCollector struct {
	metrics []Metric
	err     error
}

func (m *mockCollector) Collect(_ context.Context) ([]Metric, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.metrics, nil
}

func TestRegistry(t *testing.T) {
	registry := NewRegistry()

	// Create mock collectors
	collector1 := &mockCollector{
		metrics: []Metric{
			{
				Name:      "test_metric_1",
				Type:      MetricTypeGauge,
				Value:     42.0,
				Timestamp: time.Now(),
				Help:      "Test metric 1",
			},
		},
	}

	collector2 := &mockCollector{
		metrics: []Metric{
			{
				Name:      "test_metric_2",
				Type:      MetricTypeCounter,
				Value:     100.0,
				Labels:    map[string]string{"label": "value"},
				Timestamp: time.Now(),
				Help:      "Test metric 2",
			},
		},
	}

	// Register collectors
	registry.Register(collector1)
	registry.Register(collector2)

	// Collect metrics
	ctx := context.Background()
	metrics, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(metrics) != 2 {
		t.Fatalf("Expected 2 metrics, got %d", len(metrics))
	}

	// Verify metrics
	foundMetric1 := false
	foundMetric2 := false
	for _, m := range metrics {
		if m.Name == "test_metric_1" {
			foundMetric1 = true
			if m.Value != 42.0 {
				t.Errorf("Expected value 42.0, got %v", m.Value)
			}
		}
		if m.Name == "test_metric_2" {
			foundMetric2 = true
			if m.Value != 100.0 {
				t.Errorf("Expected value 100.0, got %v", m.Value)
			}
		}
	}

	if !foundMetric1 {
		t.Error("test_metric_1 not found")
	}
	if !foundMetric2 {
		t.Error("test_metric_2 not found")
	}
}

func TestRegistryCache(t *testing.T) {
	registry := NewRegistry()
	registry.SetCacheTTL(100 * time.Millisecond)

	collector := &mockCollector{
		metrics: []Metric{
			{
				Name:      "cached_metric",
				Type:      MetricTypeGauge,
				Value:     1.0,
				Timestamp: time.Now(),
			},
		},
	}

	registry.Register(collector)

	ctx := context.Background()

	// First call - should collect
	metrics1, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Change the collector's value
	collector.metrics[0].Value = 2.0

	// Second call - should use cache (value should still be 1.0)
	metrics2, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if metrics2[0].Value != 1.0 {
		t.Errorf("Expected cached value 1.0, got %v", metrics2[0].Value)
	}

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Third call - should collect again (value should be 2.0)
	metrics3, err := registry.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if metrics3[0].Value != 2.0 {
		t.Errorf("Expected new value 2.0, got %v", metrics3[0].Value)
	}

	// Verify first call metrics unchanged
	if metrics1[0].Value != 1.0 {
		t.Errorf("Original metrics should not be modified")
	}
}

func TestPrometheusExporter(t *testing.T) {
	registry := NewRegistry()

	collector := &mockCollector{
		metrics: []Metric{
			{
				Name:      "test_gauge",
				Type:      MetricTypeGauge,
				Value:     42.5,
				Timestamp: time.Unix(1234567890, 0),
				Help:      "A test gauge metric",
			},
			{
				Name:      "test_counter",
				Type:      MetricTypeCounter,
				Value:     100.0,
				Labels:    map[string]string{"method": "GET", "status": "200"},
				Timestamp: time.Unix(1234567890, 0),
				Help:      "A test counter metric",
			},
		},
	}

	registry.Register(collector)

	exporter := NewPrometheusExporter(registry)
	ctx := context.Background()

	output, err := exporter.Export(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify output contains expected content
	if !strings.Contains(output, "# HELP test_gauge A test gauge metric") {
		t.Error("Output missing HELP for test_gauge")
	}
	if !strings.Contains(output, "# TYPE test_gauge gauge") {
		t.Error("Output missing TYPE for test_gauge")
	}
	if !strings.Contains(output, "test_gauge 42.5") {
		t.Error("Output missing value for test_gauge")
	}

	if !strings.Contains(output, "# HELP test_counter A test counter metric") {
		t.Error("Output missing HELP for test_counter")
	}
	if !strings.Contains(output, "# TYPE test_counter counter") {
		t.Error("Output missing TYPE for test_counter")
	}
	if !strings.Contains(output, `test_counter{method="GET",status="200"} 100`) {
		t.Error("Output missing value and labels for test_counter")
	}
}

func TestPrometheusLabelEscaping(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{`simple`, `simple`},
		{`with"quote`, `with\"quote`},
		{`with\backslash`, `with\\backslash`},
		{"with\nNewline", `with\nNewline`},
		{"complex\\\"test\n", `complex\\\"test\n`},
	}

	for _, tc := range testCases {
		result := escapeLabelValue(tc.input)
		if result != tc.expected {
			t.Errorf("escapeLabelValue(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestProcessCollector(t *testing.T) {
	collector := NewProcessCollector()
	ctx := context.Background()

	metrics, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should have at least memory and goroutine metrics
	if len(metrics) < 2 {
		t.Fatalf("Expected at least 2 metrics, got %d", len(metrics))
	}

	// Verify metric names
	foundMemory := false
	foundGoroutines := false

	for _, m := range metrics {
		switch m.Name {
		case "process_resident_memory_bytes", "process_heap_bytes":
			foundMemory = true
			if m.Type != MetricTypeGauge {
				t.Errorf("Expected gauge type for %s", m.Name)
			}
			if m.Value <= 0 {
				t.Errorf("Expected positive value for %s, got %v", m.Name, m.Value)
			}
		case "process_goroutines":
			foundGoroutines = true
			if m.Type != MetricTypeGauge {
				t.Errorf("Expected gauge type for %s", m.Name)
			}
			if m.Value <= 0 {
				t.Errorf("Expected positive value for %s, got %v", m.Name, m.Value)
			}
		}
	}

	if !foundMemory {
		t.Error("Memory metrics not found")
	}
	if !foundGoroutines {
		t.Error("Goroutines metric not found")
	}
}
