// Package main demonstrates using the metricsd package to collect and export HTCondor metrics
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/metricsd"
)

func main() {
	fmt.Println("HTCondor Metrics Collection Example")
	fmt.Println("====================================")

	// Example 1: Collect process metrics
	fmt.Println("Example 1: Process Metrics")
	fmt.Println("--------------------------")

	processCollector := metricsd.NewProcessCollector()
	ctx := context.Background()

	metrics, err := processCollector.Collect(ctx)
	if err != nil {
		log.Printf("Error collecting process metrics: %v\n", err)
	} else {
		for _, m := range metrics {
			fmt.Printf("  %s = %.2f (%s)\n", m.Name, m.Value, m.Help)
		}
	}

	// Example 2: Setup full metrics registry with Prometheus export
	fmt.Println("\n\nExample 2: Full Metrics Setup with Prometheus Export")
	fmt.Println("----------------------------------------------------")

	// Create a collector client (use OSG collector for testing)
	collector := htcondor.NewCollector("cm-1.ospool.osg-htc.org:9618")

	// Create metrics registry
	registry := metricsd.NewRegistry()
	registry.SetCacheTTL(10 * time.Second)

	// Register collectors
	poolCollector := metricsd.NewPoolCollector(collector)
	registry.Register(poolCollector)
	registry.Register(processCollector)

	fmt.Println("✓ Created metrics registry with 2 collectors")

	// Create Prometheus exporter
	exporter := metricsd.NewPrometheusExporter(registry)
	fmt.Println("✓ Created Prometheus exporter")

	// Collect and export metrics
	fmt.Println("\nCollecting metrics from HTCondor pool...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	metricsText, err := exporter.Export(ctx)
	if err != nil {
		log.Printf("Error exporting metrics: %v\n", err)
		log.Println("Note: This requires network access to the collector")
	} else {
		// Print first few lines as sample
		lines := 0
		for i, ch := range metricsText {
			if ch == '\n' {
				lines++
				if lines >= 20 {
					fmt.Printf("\n... (%d more bytes of metrics)\n", len(metricsText)-i)
					break
				}
			}
			if lines < 20 {
				fmt.Printf("%c", ch)
			}
		}
	}

	// Example 3: Cache demonstration
	fmt.Println("\n\nExample 3: Metrics Caching")
	fmt.Println("-------------------------")

	start := time.Now()
	_, err = registry.Collect(context.Background())
	firstDuration := time.Since(start)
	if err != nil {
		log.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("First collection took: %v\n", firstDuration)
	}

	start = time.Now()
	_, err = registry.Collect(context.Background())
	cachedDuration := time.Since(start)
	if err != nil {
		log.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Cached collection took: %v (speedup: %.1fx)\n",
			cachedDuration,
			float64(firstDuration)/float64(cachedDuration))
	}

	fmt.Println("\n✓ Examples complete!")
	fmt.Println("\nTo use metrics in production:")
	fmt.Println("  1. Configure httpserver with a Collector")
	fmt.Println("  2. Metrics will be available at /metrics")
	fmt.Println("  3. Configure Prometheus to scrape the endpoint")
	fmt.Println("\nSee metricsd/README.md for more details.")
}
