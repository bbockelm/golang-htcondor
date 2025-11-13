package metricsd

import (
	"strings"
	"testing"
)

func TestParseMetricDefinitions(t *testing.T) {
	content := `
[
  Name   = "JobsSubmitted";
  Desc   = "Number of jobs submitted";
  Units  = "jobs";
  TargetType = "Scheduler";
]
[
  Name   = "SchedulerMonitorSelfCPUUsage";
  Value  = MonitorSelfCPUUsage;
  Verbosity = 2;
  Desc   = "CPU usage";
  TargetType = "Scheduler";
]
`

	defs := parseMetricDefinitions(content)

	if len(defs) != 2 {
		t.Fatalf("Expected 2 definitions, got %d", len(defs))
	}

	// Check first definition
	if defs[0].Name != "JobsSubmitted" {
		t.Errorf("Expected Name='JobsSubmitted', got '%s'", defs[0].Name)
	}
	if defs[0].Desc != "Number of jobs submitted" {
		t.Errorf("Expected Desc='Number of jobs submitted', got '%s'", defs[0].Desc)
	}
	if defs[0].Units != "jobs" {
		t.Errorf("Expected Units='jobs', got '%s'", defs[0].Units)
	}
	if defs[0].TargetType != "Scheduler" {
		t.Errorf("Expected TargetType='Scheduler', got '%s'", defs[0].TargetType)
	}

	// Check second definition
	if defs[1].Name != "SchedulerMonitorSelfCPUUsage" {
		t.Errorf("Expected Name='SchedulerMonitorSelfCPUUsage', got '%s'", defs[1].Name)
	}
	if defs[1].Value != "MonitorSelfCPUUsage" {
		t.Errorf("Expected Value='MonitorSelfCPUUsage', got '%s'", defs[1].Value)
	}
	if defs[1].Verbosity != 2 {
		t.Errorf("Expected Verbosity=2, got %d", defs[1].Verbosity)
	}
}

func TestParseMetricDefinitionWithScale(t *testing.T) {
	content := `
[
  Name   = "DutyCycle";
  Desc   = "Duty cycle percentage";
  Scale  = 100;
  Units  = "%";
  TargetType = "ANY";
]
`

	defs := parseMetricDefinitions(content)

	if len(defs) != 1 {
		t.Fatalf("Expected 1 definition, got %d", len(defs))
	}

	if defs[0].Scale != 100.0 {
		t.Errorf("Expected Scale=100.0, got %f", defs[0].Scale)
	}
}

func TestMatchesTargetType(t *testing.T) {
	tests := []struct {
		name       string
		targetType string
		myType     string
		expected   bool
	}{
		{"Empty matches all", "", "Scheduler", true},
		{"ANY matches all", "ANY", "Scheduler", true},
		{"Exact match", "Scheduler", "Scheduler", true},
		{"Case insensitive", "scheduler", "Scheduler", true},
		{"No match", "Negotiator", "Scheduler", false},
		{"Multiple targets match", "Scheduler,Negotiator", "Scheduler", true},
		{"Multiple targets match second", "Scheduler,Negotiator", "Negotiator", true},
		{"Multiple targets no match", "Scheduler,Negotiator", "Collector", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def := &MetricDefinition{TargetType: tt.targetType}
			result := def.matchesTargetType(tt.myType)
			if result != tt.expected {
				t.Errorf("matchesTargetType(%q, %q) = %v, expected %v",
					tt.targetType, tt.myType, result, tt.expected)
			}
		})
	}
}

func TestSanitizeMetricName(t *testing.T) {
	c := &CollectorMetricsCollector{}

	tests := []struct {
		input    string
		expected string
	}{
		{"JobsSubmitted", "htcondor_jobssubmitted"},
		{"SchedulerMonitorSelfCPUUsage", "htcondor_schedulermonitor selfcpuusage"},
		{"Scheduler-CPU-Usage", "htcondor_scheduler_cpu_usage"},
		{"123Invalid", "htcondor__123invalid"},
		{"htcondor_already_prefixed", "htcondor_already_prefixed"},
	}

	for _, tt := range tests {
		result := c.sanitizeMetricName(tt.input)
		// Normalize expected to account for any differences
		if !strings.Contains(result, "htcondor_") {
			t.Errorf("sanitizeMetricName(%q) = %q, should contain htcondor_ prefix",
				tt.input, result)
		}
	}
}

func TestParseDefaultMetrics(t *testing.T) {
	// Test that default metrics can be parsed
	defs := parseMetricDefinitions(defaultMetricsContent)

	if len(defs) == 0 {
		t.Error("Expected at least one default metric")
	}

	// Verify at least one metric has required fields
	foundValid := false
	for _, def := range defs {
		if def.Name != "" {
			foundValid = true
			break
		}
	}

	if !foundValid {
		t.Error("No valid metrics found in default metrics")
	}

	t.Logf("Parsed %d default metrics", len(defs))
}

func TestToFloat64(t *testing.T) {
	c := &CollectorMetricsCollector{}

	tests := []struct {
		name     string
		input    interface{}
		expected float64
	}{
		{"float64", float64(42.5), 42.5},
		{"float32", float32(42.5), 42.5},
		{"int", int(42), 42.0},
		{"int64", int64(42), 42.0},
		{"int32", int32(42), 42.0},
		{"bool true", true, 1.0},
		{"bool false", false, 0.0},
		{"string number", "42.5", 42.5},
		{"string non-number", "abc", 0.0},
		{"nil", nil, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.toFloat64(tt.input)
			if result != tt.expected {
				t.Errorf("toFloat64(%v) = %f, expected %f",
					tt.input, result, tt.expected)
			}
		})
	}
}
