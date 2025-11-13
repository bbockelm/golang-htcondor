# metricsd

The `metricsd` package provides a flexible metrics collection and export system for HTCondor daemons, inspired by `condor_gangliad` but designed for modern observability platforms.

## Features

- **Flexible Collector Interface**: Implement custom collectors to gather any metrics
- **Built-in Collectors**:
  - `PoolCollector`: Collects HTCondor pool-wide metrics (machines, jobs, resources)
  - `ProcessCollector`: Collects process-level metrics (memory, goroutines)
  - `CollectorMetricsCollector`: Configuration-driven collector using HTCondor ClassAd metric definitions
- **HTCondor-Compatible Configuration**:
  - ClassAd-based metric definitions (compatible with condor_gangliad)
  - Embedded default metrics (136 metrics)
  - Admin-provided metric directories
  - Per-daemon labels and filtering
  - Aggregation support (sum, avg, max, min)
- **Prometheus Export**: Native Prometheus text format export
- **Metric Caching**: Configurable TTL-based caching to reduce collection overhead
- **Thread-Safe**: Safe for concurrent access from multiple goroutines

## Usage

### Basic Setup

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
    collector := htcondor.NewCollector("collector.example.com", 9618)

    // Create metrics registry
    registry := metricsd.NewRegistry()
    registry.SetCacheTTL(10 * time.Second)

    // Register collectors
    poolCollector := metricsd.NewPoolCollector(collector)
    registry.Register(poolCollector)

    processCollector := metricsd.NewProcessCollector()
    registry.Register(processCollector)

    // Create Prometheus exporter
    exporter := metricsd.NewPrometheusExporter(registry)

    // Export metrics
    ctx := context.Background()
    metricsText, err := exporter.Export(ctx)
    if err != nil {
        log.Fatal(err)
    }

    log.Println(metricsText)
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

## Architecture

The `metricsd` package is inspired by HTCondor's `condor_gangliad` daemon, which historically collected metrics and published them to Ganglia. This implementation modernizes that concept:

- **Pluggable collectors**: Like `condor_gangliad` polling different subsystems
- **Prometheus format**: Industry-standard observability format
- **Cloud-native**: Works with modern monitoring stacks (Prometheus, Grafana, etc.)
- **Go-native**: Efficient and concurrent metric collection

## Comparison with condor_gangliad

| Feature | condor_gangliad | metricsd |
|---------|----------------|----------|
| Export Format | Ganglia | Prometheus |
| Language | C++ | Go |
| Extensibility | Limited | Pluggable collectors |
| Integration | Separate daemon | Embedded in services |
| Caching | Fixed | Configurable TTL |

## Performance

- **Caching**: Metrics are cached with configurable TTL (default 10s) to reduce collector overhead
- **Concurrent**: Safe for concurrent scraping from multiple Prometheus instances
- **Efficient**: Only queries HTCondor when cache expires

## Testing

```bash
go test ./metricsd
```

## Future Enhancements

Potential additions:

- Histogram metrics for request latencies
- Additional collectors (negotiator metrics, file transfer stats, etc.)
- OpenMetrics format support
- Metric filtering/selection
- Push gateway support
