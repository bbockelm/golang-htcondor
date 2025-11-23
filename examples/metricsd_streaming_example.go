// Example demonstrating metricsd streaming API usage with background collection
//
// This example shows how the metricsd package uses streaming APIs to efficiently
// collect metrics from HTCondor without buffering large result sets.
//
// Build: go build -o metricsd_streaming_example examples/metricsd_streaming_example.go
// Run: ./metricsd_streaming_example
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
	// Create a collector client
	// In a real deployment, this would point to your HTCondor collector
	collectorAddr := "collector.example.com:9618"
	collector := htcondor.NewCollector(collectorAddr)

	fmt.Println("Metricsd Streaming API Example")
	fmt.Println("===============================")
	fmt.Printf("Collector: %s\n\n", collectorAddr)

	// Create metrics registry with optimized settings
	registry := metricsd.NewRegistry()

	// Configure background collection
	// Query HTCondor every 60 seconds (default)
	registry.SetQueryInterval(60 * time.Second)

	// Cache results for 10 seconds
	// This should be less than your Prometheus scrape interval
	registry.SetCacheTTL(10 * time.Second)

	// Always stop background collection when done
	defer registry.Stop()

	// Register collectors that use streaming API
	// PoolCollector uses QueryAdsStream to process ads one at a time
	poolCollector := metricsd.NewPoolCollector(collector)
	registry.Register(poolCollector)

	// ProcessCollector provides process-level metrics
	processCollector := metricsd.NewProcessCollector()
	registry.Register(processCollector)

	// Create Prometheus exporter
	exporter := metricsd.NewPrometheusExporter(registry)

	ctx := context.Background()

	fmt.Println("Architecture:")
	fmt.Println("- Uses streaming API (QueryAdsStream)")
	fmt.Println("- Processes one ClassAd at a time")
	fmt.Println("- Never buffers more than one ad in memory")
	fmt.Println("- Background goroutine queries HTCondor every 60s")
	fmt.Println("- Subsequent scrapes return pre-calculated results")
	fmt.Println()

	// First call - starts background collection and returns initial metrics
	fmt.Println("1. First Collect() - starts background goroutine...")
	startTime := time.Now()
	metricsText, err := exporter.Export(ctx)
	duration := time.Since(startTime)
	if err != nil {
		log.Printf("Error collecting metrics: %v", err)
		return
	}

	fmt.Printf("   Collected in %v\n", duration)
	fmt.Printf("   Background collection started (will run every 60s)\n")
	fmt.Printf("   Metrics size: %d bytes\n\n", len(metricsText))

	// Show sample of metrics
	lines := 0
	for i, ch := range metricsText {
		if ch == '\n' {
			lines++
		}
		if lines >= 10 { // Show first 10 lines
			fmt.Printf("   ... (%d more lines)\n\n", countLines(metricsText[i:]))
			break
		}
		fmt.Printf("   %c", ch)
	}

	// Second call - returns cached results (fast)
	fmt.Println("2. Second Collect() within cache TTL...")
	startTime = time.Now()
	metricsText2, err := exporter.Export(ctx)
	duration2 := time.Since(startTime)
	if err != nil {
		log.Printf("Error collecting metrics: %v", err)
		return
	}

	fmt.Printf("   Returned cached results in %v (much faster!)\n", duration2)
	fmt.Printf("   Same metrics: %v\n\n", metricsText == metricsText2)

	// Wait for background collection to run
	fmt.Println("3. Waiting for background collection cycle...")
	time.Sleep(1 * time.Second) // In practice, this would be 60s

	// Third call - still returns cached results
	startTime = time.Now()
	_, err = exporter.Export(ctx)
	duration3 := time.Since(startTime)
	if err != nil {
		log.Printf("Error collecting metrics: %v", err)
		return
	}

	fmt.Printf("   Returned in %v\n", duration3)
	fmt.Printf("   Cache may have been updated by background goroutine\n\n")

	fmt.Println("Summary:")
	fmt.Println("- First call takes longer (queries HTCondor)")
	fmt.Println("- Subsequent calls are fast (return cached results)")
	fmt.Println("- Background goroutine updates cache periodically")
	fmt.Println("- Memory efficient: processes ads one at a time")
	fmt.Println("- Each ad type queried only once per cycle")
	fmt.Println()

	fmt.Printf("Metric collection times:\n")
	fmt.Printf("  First:  %v (initial query + start background)\n", duration)
	fmt.Printf("  Second: %v (cached)\n", duration2)
	fmt.Printf("  Third:  %v (cached)\n", duration3)
	fmt.Printf("  Speedup: %.1fx faster\n\n", float64(duration)/float64(duration2))

	// registry.Stop() will be called by defer
	fmt.Println("Stopping background collection (via defer)...")
}

func countLines(s string) int {
	count := 0
	for _, ch := range s {
		if ch == '\n' {
			count++
		}
	}
	return count
}
