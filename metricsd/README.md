# metricsd

The `metricsd` package provides a flexible metrics collection and export system for HTCondor daemons, inspired by `condor_gangliad` but designed for modern observability platforms.

## Features

- **Streaming API**: Uses HTCondor's streaming APIs to process ClassAds one at a time without buffering large result sets in memory
- **Background Collection**: Automatically launches a background goroutine for periodic metric collection after the first query
- **Configurable Query Interval**: Control how often metrics are collected from HTCondor (default: 60 seconds)
- **Pre-calculated Results**: Subsequent metric scrapes return cached results, avoiding expensive collector queries
- **Flexible Collector Interface**: Implement custom collectors to gather any metrics
- **Built-in Collectors**:
  - `PoolCollector`: Collects HTCondor pool-wide metrics (machines, jobs, resources) using streaming API
  - `ProcessCollector`: Collects process-level metrics (memory, goroutines)
  - `CollectorMetricsCollector`: Configuration-driven collector using HTCondor ClassAd metric definitions with streaming API
- **HTCondor-Compatible Configuration**:
  - ClassAd-based metric definitions (compatible with condor_gangliad)
  - Embedded default metrics (136 metrics)
  - Admin-provided metric directories
  - Per-daemon labels and filtering
  - Aggregation support (sum, avg, max, min)
- **Prometheus Export**: Native Prometheus text format export
- **Metric Caching**: Configurable TTL-based caching to reduce collection overhead
- **Thread-Safe**: Safe for concurrent access from multiple goroutines

## Architecture

The metricsd package uses a two-tier caching architecture:

1. **Query Interval** (default 60s): Controls how often background collection queries HTCondor
2. **Cache TTL** (default 10s): Controls how long results are served before triggering a new query

On the first call to `Collect()`, if query interval > 0, a background goroutine is launched that:
- Queries HTCondor at the configured interval
- Processes ClassAds one at a time using streaming APIs
- Updates the cache with aggregated metrics
- Each ad type (Startd, Schedd, etc.) is queried only once per cycle

Subsequent calls to `Collect()` return the pre-calculated cached results without querying HTCondor again until the cache expires.

## Usage

### Basic Setup with Background Collection

```go
package main

import (
    "context"
    "log"
    "time"

    htcondor "github.com/bbockelm/golang-htcondor"
    "github.com/bbockelm/golang-htcondor/metricsd"
)

func main() {
    // Create a collector client
    collector := htcondor.NewCollector("collector.example.com:9618")

    // Create metrics registry
    registry := metricsd.NewRegistry()
    registry.SetCacheTTL(10 * time.Second)       // How long to serve cached results
    registry.SetQueryInterval(60 * time.Second)  // How often to query HTCondor
    defer registry.Stop()  // Stop background collection on exit

    // Register collectors
    poolCollector := metricsd.NewPoolCollector(collector)
    registry.Register(poolCollector)

    processCollector := metricsd.NewProcessCollector()
    registry.Register(processCollector)

    // Create Prometheus exporter
    exporter := metricsd.NewPrometheusExporter(registry)

    // First call starts background collection
    ctx := context.Background()
    metricsText, err := exporter.Export(ctx)
    if err != nil {
        log.Fatal(err)
    }

    log.Println(metricsText)

    // Subsequent calls will return pre-calculated results from cache
}
```

### Configuration-Based Detailed Metrics

The `CollectorMetricsCollector` provides detailed per-daemon metrics using ClassAd-based configuration files:

```go
package main

import (
    "context"
    "log"

    htcondor "github.com/bbockelm/golang-htcondor"
    "github.com/bbockelm/golang-htcondor/metricsd"
)

func main() {
    collector := htcondor.NewCollector("collector.example.com", 9618)

    // Create configuration-based collector
    // Uses embedded default metrics + any metrics from config directory
    configCollector, err := metricsd.NewCollectorMetricsCollector(
        collector,
        "/etc/condor/ganglia.d", // Config dir (or "" for defaults only)
        1,                        // Verbosity level (0=all, higher=fewer)
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create registry
    registry := metricsd.NewRegistry()
    registry.Register(configCollector)
    registry.Register(metricsd.NewProcessCollector())

    // Export
    exporter := metricsd.NewPrometheusExporter(registry)
    ctx := context.Background()
    metricsText, err := exporter.Export(ctx)
    if err != nil {
        log.Fatal(err)
    }

    log.Println(metricsText)
}
```

### Integration with HTTP Server

The `httpserver` package automatically integrates with `metricsd` to provide a `/metrics` endpoint:

```go
package main

import (
    "log"

    htcondor "github.com/bbockelm/golang-htcondor"
    "github.com/bbockelm/golang-htcondor/httpserver"
)

func main() {
    collector := htcondor.NewCollector("collector.example.com", 9618)

    cfg := httpserver.Config{
        ListenAddr:  ":8080",
        ScheddName:  "my_schedd",
        ScheddAddr:  "schedd.example.com",
        ScheddPort:  9618,
        Collector:   collector,        // Enable metrics
        EnableMetrics: true,            // Optional - enabled by default if Collector is set
        MetricsCacheTTL: 10 * time.Second,
    }

    server, err := httpserver.NewServer(cfg)
    if err != nil {
        log.Fatal(err)
    }

    // Server will expose metrics at http://localhost:8080/metrics
    log.Fatal(server.Start())
}
```

### Prometheus Scraping

Configure Prometheus to scrape the metrics endpoint:

```yaml
scrape_configs:
  - job_name: 'htcondor-api'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 30s
```

## Metrics

### Pool Metrics (from PoolCollector)

- `htcondor_pool_machines_total`: Total number of machines in the pool
- `htcondor_pool_machines_state{state="..."}`: Number of machines by state (Claimed, Unclaimed, Owner, etc.)
- `htcondor_pool_cpus_total`: Total CPU cores in the pool
- `htcondor_pool_cpus_used`: Used CPU cores in the pool
- `htcondor_pool_memory_mb_total`: Total memory in MB in the pool
- `htcondor_pool_memory_mb_used`: Used memory in MB in the pool
- `htcondor_pool_schedds_total`: Total number of schedd daemons
- `htcondor_pool_jobs_total`: Total number of jobs in the pool

### Process Metrics (from ProcessCollector)

- `process_resident_memory_bytes`: Process resident memory in bytes
- `process_heap_bytes`: Process heap size in bytes
- `process_goroutines`: Number of goroutines

### Detailed Daemon Metrics (from CollectorMetricsCollector)

When using the configuration-based collector with default metrics, 136 metrics are available including:

**Scheduler (Schedd) Metrics** - with labels `daemon`, `machine`, `type`:
- `htcondor_jobssubmitted`: Number of jobs submitted
- `htcondor_jobscompleted`: Number of jobs completed
- `htcondor_jobsaccumrunningtime`: Total job runtime in hours
- `htcondor_schedulermonitorselfimagesizeit`: Memory usage in KB
- `htcondor_schedulerrecentdaemoncoredutyc`: CPU duty cycle percentage

**Negotiator Metrics** - with labels `daemon`, `machine`, `type`:
- `htcondor_negotiatormonitorselfimagesizeit`: Memory usage in KB
- `htcondor_negotiatorrecentdaemoncoredutyc`: CPU duty cycle percentage
- `htcondor_negotiatorupdateslost`: Lost collector updates
- `htcondor_negotiatorupdatestotal`: Total collector updates

**Machine (Startd) Metrics** - with labels `daemon`, `machine`, `type`:
- `htcondor_machinecondorloadavg`: Load average
- `htcondor_machinemonitorselfimagesizeit`: Memory usage in KB
- `htcondor_machinerecentdaemoncoredutyc`: CPU duty cycle percentage

All detailed metrics include these labels:
- `daemon`: Daemon name (e.g., "schedd@submit-1.example.com")
- `machine`: Machine hostname
- `type`: HTCondor daemon type (Scheduler, Negotiator, Collector, Machine)

See `SAMPLE_METRICS_OUTPUT.md` for complete example outputs.

## Custom Collectors

Implement the `Collector` interface to create custom metric collectors:

```go
type MyCollector struct {
    // your fields
}

func (c *MyCollector) Collect(ctx context.Context) ([]metricsd.Metric, error) {
    metrics := []metricsd.Metric{
        {
            Name:      "my_custom_metric",
            Type:      metricsd.MetricTypeGauge,
            Value:     123.45,
            Labels:    map[string]string{"label": "value"},
            Timestamp: time.Now(),
            Help:      "Description of my custom metric",
        },
    }
    return metrics, nil
}

// Register it
registry.Register(&MyCollector{})
```

## Comparison with condor_gangliad

| Feature | condor_gangliad | metricsd |
|---------|----------------|----------|
| Export Format | Ganglia | Prometheus |
| Language | C++ | Go |
| Extensibility | Limited | Pluggable collectors |
| Integration | Separate daemon | Embedded in services |
| Caching | Fixed | Configurable TTL |
| Query Method | Buffered | Streaming (one ad at a time) |
| Background Collection | N/A | Configurable (default 60s) |
| Memory Efficiency | Buffers all ads | Processes ads one at a time |

## Performance

- **Streaming API**: ClassAds are processed one at a time, never buffering more than one ad in memory
- **Background Collection**: After first query, metrics are collected in background goroutine at configurable interval (default 60s)
- **Pre-calculated Results**: Subsequent scrapes return cached results without querying HTCondor
- **Query Efficiency**: Each ad type (Startd, Schedd, etc.) is queried only once per collection cycle
- **Caching**: Metrics are cached with configurable TTL (default 10s) to reduce overhead
- **Concurrent**: Safe for concurrent scraping from multiple Prometheus instances
- **Memory Efficient**: Streaming approach avoids buffering large datasets, suitable for large HTCondor pools

### Tuning

For optimal performance:

1. **Query Interval**: Set to match your monitoring needs
   - Smaller pools: 30-60 seconds is usually sufficient
   - Larger pools: Consider 60-120 seconds to reduce collector load
   - `registry.SetQueryInterval(60 * time.Second)`

2. **Cache TTL**: Set based on Prometheus scrape interval
   - Should be less than your Prometheus scrape interval
   - Typical: 5-15 seconds for 30s scrape interval
   - `registry.SetCacheTTL(10 * time.Second)`

3. **Prometheus Scraping**:
   - Set scrape interval to match your monitoring requirements
   - Recommended: 30-60 seconds for most use cases
   - Cache TTL should be shorter than scrape interval

## Testing

### Unit Tests

```bash
go test ./metricsd
```

### Integration Tests

The package includes integration tests that verify the metrics collection against a real HTCondor instance. These tests:

- Set up a mini HTCondor instance with collector, schedd, negotiator, and startd
- Test the PoolCollector against real HTCondor daemon ads
- Verify Prometheus export format
- Test metrics caching functionality
- Validate combined collectors (pool + process)

To run integration tests (requires HTCondor to be installed):

```bash
# Using make
make test-integration

# Or directly with go test
go test -tags=integration -v -timeout=5m ./metricsd/
```

The integration tests will automatically skip if HTCondor is not installed on the system.

## Future Enhancements

Potential additions:

- Histogram metrics for request latencies
- Additional collectors (negotiator metrics, file transfer stats, etc.)
- OpenMetrics format support
- Metric filtering/selection
- Push gateway support
