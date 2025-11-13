package metricsd

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
)

// PrometheusExporter exports metrics in Prometheus text format
type PrometheusExporter struct {
	registry *Registry
}

// NewPrometheusExporter creates a new Prometheus exporter
func NewPrometheusExporter(registry *Registry) *PrometheusExporter {
	return &PrometheusExporter{
		registry: registry,
	}
}

// Export generates Prometheus-formatted metrics text
func (e *PrometheusExporter) Export(ctx context.Context) (string, error) {
	metrics, err := e.registry.Collect(ctx)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer

	// Group metrics by name
	metricsByName := make(map[string][]Metric)
	for _, m := range metrics {
		metricsByName[m.Name] = append(metricsByName[m.Name], m)
	}

	// Sort metric names for consistent output
	names := make([]string, 0, len(metricsByName))
	for name := range metricsByName {
		names = append(names, name)
	}
	sort.Strings(names)

	// Write each metric group
	for _, name := range names {
		group := metricsByName[name]
		if len(group) == 0 {
			continue
		}

		// Write HELP line (use first metric's help text)
		if group[0].Help != "" {
			fmt.Fprintf(&buf, "# HELP %s %s\n", name, group[0].Help)
		}

		// Write TYPE line
		var metricType string
		switch group[0].Type {
		case MetricTypeGauge:
			metricType = "gauge"
		case MetricTypeCounter:
			metricType = "counter"
		case MetricTypeHistogram:
			metricType = "histogram"
		default:
			metricType = "untyped"
		}
		fmt.Fprintf(&buf, "# TYPE %s %s\n", name, metricType)

		// Write metric values
		for _, m := range group {
			if len(m.Labels) > 0 {
				// Sort labels for consistent output
				labelKeys := make([]string, 0, len(m.Labels))
				for k := range m.Labels {
					labelKeys = append(labelKeys, k)
				}
				sort.Strings(labelKeys)

				labelPairs := make([]string, 0, len(labelKeys))
				for _, k := range labelKeys {
					// Escape label values
					v := escapeLabelValue(m.Labels[k])
					labelPairs = append(labelPairs, fmt.Sprintf(`%s="%s"`, k, v))
				}

				fmt.Fprintf(&buf, "%s{%s} %v %d\n",
					m.Name,
					strings.Join(labelPairs, ","),
					m.Value,
					m.Timestamp.UnixMilli())
			} else {
				fmt.Fprintf(&buf, "%s %v %d\n",
					m.Name,
					m.Value,
					m.Timestamp.UnixMilli())
			}
		}
	}

	return buf.String(), nil
}

// escapeLabelValue escapes special characters in label values
func escapeLabelValue(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}
