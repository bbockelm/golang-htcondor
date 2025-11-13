package metricsd

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

//go:embed ganglia_default_metrics
var defaultMetricsContent string

// MetricDefinition represents a metric configuration from a ClassAd
type MetricDefinition struct {
	Name           string            // Metric name
	Value          string            // ClassAd expression to evaluate (defaults to attribute with same name)
	Desc           string            // Description
	Verbosity      int               // Verbosity level (0=default)
	TargetType     string            // Comma-separated list of daemon types to monitor
	Requirements   string            // Boolean expression for filtering
	Title          string            // Graph title
	Group          string            // Metric group name
	Cluster        string            // Cluster name
	Units          string            // Units description
	Scale          float64           // Scaling factor (default 1.0)
	Derivative     bool              // Whether to graph derivative
	Type           string            // Metric type (int32, float, double, etc.)
	Regex          string            // Regular expression for dynamic attributes
	Aggregate      string            // Aggregation function (sum, avg, max, min)
	AggregateGroup string            // Aggregation grouping expression
	Machine        string            // Override machine name
	IP             string            // Override IP address
	Lifetime       int               // Max seconds to keep metric
	Labels         map[string]string // Additional labels for this metric
}

// parseMetricDefinitions parses metric definitions from ClassAd format
func parseMetricDefinitions(content string) []*MetricDefinition {
	// Parse as a list of ClassAds
	content = strings.TrimSpace(content)
	if !strings.HasPrefix(content, "[") {
		// Wrap in list if not already
		content = "[" + content + "]"
	}

	// Simple parser for ClassAd lists
	definitions := make([]*MetricDefinition, 0)

	// Split by "]\n[" pattern to separate individual ClassAds
	ads := splitClassAdList(content)

	for _, adText := range ads {
		if strings.TrimSpace(adText) == "" {
			continue
		}

		def, err := parseMetricDefinition(adText)
		if err != nil {
			// Log error but continue with other definitions
			continue
		}
		if def != nil {
			definitions = append(definitions, def)
		}
	}

	return definitions
}

// splitClassAdList splits a string containing multiple ClassAds in list format
func splitClassAdList(content string) []string {
	ads := make([]string, 0)
	depth := 0
	start := -1

	for i, ch := range content {
		switch ch {
		case '[':
			if depth == 0 {
				start = i
			}
			depth++
		case ']':
			depth--
			if depth == 0 && start >= 0 {
				ads = append(ads, content[start+1:i])
				start = -1
			}
		}
	}

	return ads
}

// parseMetricDefinition parses a single metric definition ClassAd
func parseMetricDefinition(adText string) (*MetricDefinition, error) {
	def := &MetricDefinition{
		Scale:     1.0,
		Verbosity: 0,
		Labels:    make(map[string]string),
	}

	// Simple key-value parser
	lines := strings.Split(adText, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "//") {
			continue
		}

		// Remove trailing semicolon
		line = strings.TrimSuffix(line, ";")

		// Split on first '='
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
			value = strings.Trim(value, "\"")
		}

		parseMetricAttribute(def, key, value)
	}

	// Name is required
	if def.Name == "" {
		return nil, fmt.Errorf("metric definition missing Name")
	}

	// Default Value to Name if not specified
	if def.Value == "" {
		def.Value = def.Name
	}

	return def, nil
}

// parseMetricAttribute sets a field on the MetricDefinition based on key-value pair
func parseMetricAttribute(def *MetricDefinition, key, value string) {
	switch key {
	case "Name":
		def.Name = value
	case "Value":
		def.Value = value
	case "Desc":
		def.Desc = value
	case "Verbosity":
		if v, err := strconv.Atoi(value); err == nil {
			def.Verbosity = v
		}
	case "TargetType":
		def.TargetType = value
	case "Requirements":
		def.Requirements = value
	case "Title":
		def.Title = value
	case "Group":
		def.Group = value
	case "Cluster":
		def.Cluster = value
	case "Units":
		def.Units = value
	case "Scale":
		if v, err := strconv.ParseFloat(value, 64); err == nil {
			def.Scale = v
		}
	case "Derivative":
		def.Derivative = strings.ToLower(value) == "true"
	case "Type":
		def.Type = value
	case "Regex":
		def.Regex = value
	case "Aggregate":
		def.Aggregate = value
	case "AggregateGroup":
		def.AggregateGroup = value
	case "Machine":
		def.Machine = value
	case "IP":
		def.IP = value
	case "Lifetime":
		if v, err := strconv.Atoi(value); err == nil {
			def.Lifetime = v
		}
	}
}

// matchesTargetType checks if a daemon type matches the TargetType specification
func (d *MetricDefinition) matchesTargetType(myType string) bool {
	if d.TargetType == "" || d.TargetType == "ANY" {
		return true
	}

	targets := strings.Split(d.TargetType, ",")
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "ANY" {
			return true
		}
		if strings.EqualFold(target, myType) {
			return true
		}
		// Handle special case: "Scheduler" matches "Scheduler"
		if target == "Scheduler" && myType == "Scheduler" {
			return true
		}
		// Handle special case: "Machine_slot1" for slot 1 ads
		if target == "Machine_slot1" && myType == "Machine" {
			return true // We'll filter by slot later
		}
	}

	return false
}

// CollectorMetricsCollector collects metrics from collector based on metric definitions
type CollectorMetricsCollector struct {
	collector   *htcondor.Collector
	definitions []*MetricDefinition
	verbosity   int
}

// NewCollectorMetricsCollector creates a collector that uses metric definitions
func NewCollectorMetricsCollector(collector *htcondor.Collector, configDir string, verbosity int) (*CollectorMetricsCollector, error) {
	// Start with default metrics
	defaultDefs := parseMetricDefinitions(defaultMetricsContent)

	definitions := defaultDefs

	// Load additional metrics from config directory if specified
	if configDir != "" {
		files, err := os.ReadDir(configDir)
		if err == nil {
			for _, file := range files {
				if file.IsDir() {
					continue
				}

				filePath := filepath.Join(configDir, file.Name())
				// #nosec G304 - configDir is a controlled configuration directory path
				content, err := os.ReadFile(filePath)
				if err != nil {
					continue
				}

				defs := parseMetricDefinitions(string(content))
				definitions = append(definitions, defs...)
			}
		}
	}

	return &CollectorMetricsCollector{
		collector:   collector,
		definitions: definitions,
		verbosity:   verbosity,
	}, nil
}

// Collect gathers metrics based on the metric definitions
func (c *CollectorMetricsCollector) Collect(ctx context.Context) ([]Metric, error) {
	metrics := make([]Metric, 0)

	// Group definitions by TargetType
	defsByType := make(map[string][]*MetricDefinition)
	for _, def := range c.definitions {
		if def.Verbosity > c.verbosity {
			continue
		}

		// Parse TargetType
		if def.TargetType == "" || def.TargetType == "ANY" {
			defsByType["ANY"] = append(defsByType["ANY"], def)
		} else {
			targets := strings.Split(def.TargetType, ",")
			for _, target := range targets {
				target = strings.TrimSpace(target)
				defsByType[target] = append(defsByType[target], def)
			}
		}
	}

	// Query for each type
	adTypes := []string{"Scheduler", "Negotiator", "Collector", "Startd"}

	for _, adType := range adTypes {
		relevantDefs := defsByType[adType]
		relevantDefs = append(relevantDefs, defsByType["ANY"]...)
		relevantDefs = append(relevantDefs, defsByType["Machine_slot1"]...)

		if len(relevantDefs) == 0 {
			continue
		}

		// Query collector for this type
		ads, err := c.collector.QueryAds(ctx, adType, "")
		if err != nil {
			// Continue with other types
			continue
		}

		// Process each ad
		for _, ad := range ads {
			myType, _ := ad.EvaluateAttrString("MyType")
			name, _ := ad.EvaluateAttrString("Name")
			machine, _ := ad.EvaluateAttrString("Machine")

			// Process each metric definition
			for _, def := range relevantDefs {
				if !def.matchesTargetType(myType) {
					continue
				}

				// Handle aggregation
				if def.Aggregate != "" {
					// Aggregation will be handled in a separate pass
					continue
				}

				// Evaluate the value expression
				metricValue := c.evaluateMetricValue(ad, def)
				if metricValue == nil {
					continue
				}

				// Create labels
				labels := make(map[string]string)
				if name != "" {
					labels["daemon"] = name
				}
				if machine != "" {
					labels["machine"] = machine
				}
				labels["type"] = myType

				// Determine metric type
				metricType := MetricTypeGauge
				if def.Derivative {
					metricType = MetricTypeCounter
				}

				// Create the metric
				metric := Metric{
					Name:      c.sanitizeMetricName(def.Name),
					Type:      metricType,
					Value:     metricValue.(float64),
					Labels:    labels,
					Timestamp: time.Now(), // Use current time
					Help:      def.Desc,
				}

				metrics = append(metrics, metric)
			}
		}
	}

	return metrics, nil
}

// evaluateMetricValue evaluates a metric value from a ClassAd
func (c *CollectorMetricsCollector) evaluateMetricValue(ad *classad.ClassAd, def *MetricDefinition) interface{} {
	// If Regex is specified, handle dynamic attributes
	if def.Regex != "" {
		return c.evaluateRegexMetric(ad, def)
	}

	// Evaluate the Value expression
	var rawValue interface{}

	// Try to evaluate as expression first
	result := ad.EvaluateAttr(def.Value)
	if result.IsError() {
		// If Value is just an attribute name, try direct lookup
		if expr, ok := ad.Lookup(def.Value); ok {
			rawValue = expr
		} else {
			return nil
		}
	} else {
		rawValue = result
	}

	// Convert to float64
	floatValue := c.toFloat64(rawValue)

	// Apply scaling
	if def.Scale != 1.0 {
		floatValue *= def.Scale
	}

	return floatValue
}

// evaluateRegexMetric handles metrics with Regex attribute
func (c *CollectorMetricsCollector) evaluateRegexMetric(ad *classad.ClassAd, def *MetricDefinition) interface{} {
	// Regex support would require iterating through ClassAd attributes
	// For now, just try to evaluate the Value expression directly
	// This feature can be enhanced when ClassAd supports attribute iteration
	result := ad.EvaluateAttr(def.Value)
	if !result.IsError() {
		return c.toFloat64(result)
	}
	return nil
}

// toFloat64 converts various types to float64
func (c *CollectorMetricsCollector) toFloat64(value interface{}) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case int32:
		return float64(v)
	case bool:
		if v {
			return 1.0
		}
		return 0.0
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0.0
}

// sanitizeMetricName converts a metric name to Prometheus-compatible format
func (c *CollectorMetricsCollector) sanitizeMetricName(name string) string {
	// Convert to lowercase
	name = strings.ToLower(name)

	// Replace invalid characters with underscores
	re := regexp.MustCompile(`[^a-z0-9_:]`)
	name = re.ReplaceAllString(name, "_")

	// Ensure it starts with a letter or underscore
	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		name = "_" + name
	}

	// Add htcondor prefix if not already present
	if !strings.HasPrefix(name, "htcondor_") {
		name = "htcondor_" + name
	}

	return name
}
