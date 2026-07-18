# Metricsd Module Implementation Summary

## Overview

Implemented a new `metricsd` module that provides HTCondor metrics collection and export functionality, inspired by `condor_gangliad` but designed for modern Prometheus-based monitoring.

## What Was Created

### Core Module (`metricsd/`)

1. **metricsd.go** - Core types and interfaces
   - `Metric` - Represents a single metric with name, type, value, labels, timestamp, and help text
   - `MetricType` - Enum for gauge, counter, and histogram types
   - `Collector` - Interface for metric collectors
   - `Registry` - Manages multiple collectors with caching support

2. **collectors.go** - Built-in metric collectors
   - `PoolCollector` - Collects HTCondor pool-wide metrics:
     - Machine counts and states
     - CPU and memory resources (total and used)
     - Schedd and job counts
   - `ProcessCollector` - Collects process-level metrics:
     - Memory usage (resident, heap)
     - Goroutine counts

3. **config.go** - HTCondor-style metric configuration system
   - `MetricDefinition` - Represents a metric from ClassAd configuration
   - `parseMetricDefinitions` - Parses ClassAd format metric definitions
   - `CollectorMetricsCollector` - Advanced collector using metric definitions
   - Embedded default metrics from `ganglia_default_metrics`
   - Support for admin-provided metric directories
   - Features:
     - Per-daemon metric collection with labels
     - TargetType filtering (Scheduler, Negotiator, Machine, etc.)
     - Value expressions and scaling
     - Aggregation support (sum, avg, max, min)
     - Requirements expressions for filtering
     - Regex support for dynamic attributes

4. **prometheus.go** - Prometheus format exporter
   - `PrometheusExporter` - Exports metrics in Prometheus text format
   - Proper label escaping and formatting
   - Metric grouping and sorting for consistent output

5. **metricsd_test.go** - Comprehensive test suite
   - Registry tests with mock collectors
   - Cache behavior verification
   - Prometheus export format validation
   - Label escaping tests
   - Process collector functional tests

6. **config_test.go** - Configuration parser tests
   - ClassAd parsing validation
   - TargetType matching logic
   - Scale factor handling
   - Default metrics validation (136 metrics parsed)

7. **ganglia_default_metrics** - Default metric definitions
   - Embedded file with 136 default metrics
   - Compatible with HTCondor's ganglia configuration
   - Covers Scheduler, Negotiator, Collector, and Machine metrics

8. **README.md** - Complete documentation
   - Usage examples
   - API reference
   - Metrics catalog
   - Integration guide
   - Comparison with condor_gangliad

9. **SAMPLE_METRICS_OUTPUT.md** - Example /metrics output
   - Real-world output examples
   - Pool metrics, daemon metrics, aggregations
   - Prometheus query examples
   - Label structure documentation

### HTTP Server Integration

Updated `httpserver/` module:

1. **server.go** - Added metrics support
   - New `Config` fields: `Collector`, `EnableMetrics`, `MetricsCacheTTL`
   - Automatic metrics registry setup when collector is provided
   - Registers both pool and process collectors

2. **routes.go** - Added `/metrics` endpoint
   - Conditionally registered based on metrics availability

3. **handlers.go** - New handler
   - `handleMetrics()` - Serves Prometheus-formatted metrics
   - Proper content-type headers
   - Error handling

4. **README.md** - Updated documentation
   - Added `/metrics` endpoint documentation
   - Collector configuration section
   - Example metrics output

### Examples

Created `examples/metrics_demo/`:

1. **main.go** - Demonstration program
   - Process metrics collection
   - Full metrics stack setup
   - Prometheus export
   - Cache performance demonstration

2. **README.md** - Example documentation
   - Build and run instructions
   - Expected output
   - Production usage guide

3. **prometheus.yml** - Example Prometheus configuration
   - Scrape configuration
   - Multiple target examples
   - TLS configuration template

### Documentation Updates

1. **Main README.md**
   - Added "Metrics Collection (metricsd)" section
   - Updated API endpoints list to include `/metrics`
   - Example curl command for metrics endpoint

2. **httpserver/README.md**
   - Added Prometheus Metrics section
   - Example metrics list
   - Collector configuration documentation

## Key Features

### 1. Flexible Architecture
- Interface-based design allows custom collectors
- Registry pattern for managing multiple collectors
- Thread-safe concurrent access
- **HTCondor-compatible configuration system** using ClassAd format

### 2. Prometheus Native
- Standard Prometheus text format
- Proper metric types (gauge, counter, histogram)
- Label support with proper escaping
- Timestamps included
- **Per-daemon labels** for detailed monitoring

### 3. Performance Optimized
- Configurable TTL-based caching (default 10s)
- Reduces collector overhead on repeated scrapes
- Can handle multiple concurrent scrape requests

### 4. HTCondor Integration
- **Configuration-driven metrics** from ClassAd definitions
- Embedded default metrics (136 metrics from ganglia_default_metrics)
- Admin-provided metric directories via `GANGLIAD_METRICS_CONFIG_DIR`
- Collects pool-wide statistics from collector
- **Per-daemon metrics** with machine, daemon, and type labels
- Machine state distribution
- Resource utilization (CPUs, memory)
- Job counts across schedds
- Process-level metrics for the server itself
- **TargetType filtering** (Scheduler, Negotiator, Machine, etc.)
- **Aggregation support** (sum, avg, max, min)
- **Value expressions and scaling**
- **Requirements expressions** for filtering

### 5. Easy Integration
- Automatic setup when collector is configured
- Zero-configuration for httpserver users with default metrics
- Drop-in replacement for condor_gangliad workflows
- Custom metric definitions via config files

## Metrics Exported

### Pool Metrics (from PoolCollector)
- `htcondor_pool_machines_total` - Total machines
- `htcondor_pool_machines_state{state="..."}` - Machines by state
- `htcondor_pool_cpus_total` - Total CPU cores
- `htcondor_pool_cpus_used` - Used CPU cores
- `htcondor_pool_memory_mb_total` - Total memory (MB)
- `htcondor_pool_memory_mb_used` - Used memory (MB)
- `htcondor_pool_schedds_total` - Number of schedds
- `htcondor_pool_jobs_total` - Total jobs

### Process Metrics (from ProcessCollector)
- `process_resident_memory_bytes` - Process memory
- `process_heap_bytes` - Heap size
- `process_goroutines` - Active goroutines

### Detailed Daemon Metrics (from CollectorMetricsCollector with default metrics)

When using the configuration-based collector, 136 default metrics are available including:

#### Scheduler (Schedd) Metrics
- `htcondor_jobssubmitted{daemon="...",machine="...",type="Scheduler"}` - Jobs submitted
- `htcondor_jobscompleted{daemon="...",machine="...",type="Scheduler"}` - Jobs completed
- `htcondor_jobsaccumrunningtime{daemon="...",machine="...",type="Scheduler"}` - Runtime (hours)
- `htcondor_schedulermonitorselfimagesizeit{daemon="...",machine="...",type="Scheduler"}` - Memory (KB)
- `htcondor_schedulerrecentdaemoncoredutyc{daemon="...",machine="...",type="Scheduler"}` - Duty cycle (%)

#### Negotiator Metrics
- `htcondor_negotiatormonitorselfimagesizeit{daemon="...",machine="...",type="Negotiator"}` - Memory (KB)
- `htcondor_negotiatorrecentdaemoncoredutyc{daemon="...",machine="...",type="Negotiator"}` - Duty cycle (%)
- `htcondor_negotiatorupdateslost{daemon="...",machine="...",type="Negotiator"}` - Lost updates
- `htcondor_negotiatorupdatestotal{daemon="...",machine="...",type="Negotiator"}` - Total updates

#### Machine (Startd) Metrics
- `htcondor_machinecondorloadavg{daemon="...",machine="...",type="Machine"}` - Load average
- `htcondor_machinemonitorselfimagesizeit{daemon="...",machine="...",type="Machine"}` - Memory (KB)
- `htcondor_machinerecentdaemoncoredutyc{daemon="...",machine="...",type="Machine"}` - Duty cycle (%)

All daemon metrics include labels:
- `daemon` - Daemon name (e.g., "schedd@submit-1.example.com")
- `machine` - Machine hostname
- `type` - HTCondor daemon type (Scheduler, Negotiator, Collector, Machine)

See `metricsd/SAMPLE_METRICS_OUTPUT.md` for complete examples.

## Testing

All tests passing:
- Unit tests for registry, caching, collectors
- Prometheus export format validation
- Label escaping edge cases
- Process collector functional tests

```bash
go test ./metricsd
# PASS
# ok  	github.com/bbockelm/golang-htcondor/metricsd    0.389s
```

## Usage Example

### Basic Pool Metrics

```go
// Create collector
collector := htcondor.NewCollector("collector.example.com", 9618)

// Create and configure registry
registry := metricsd.NewRegistry()
registry.SetCacheTTL(10 * time.Second)

// Register collectors
registry.Register(metricsd.NewPoolCollector(collector))
registry.Register(metricsd.NewProcessCollector())

// Export to Prometheus
exporter := metricsd.NewPrometheusExporter(registry)
metricsText, err := exporter.Export(ctx)
```

### Configuration-Based Detailed Metrics

```go
// Create collector
collector := htcondor.NewCollector("collector.example.com", 9618)

// Create configuration-based collector with default metrics
// Optionally specify a config directory for additional metrics
configCollector, err := metricsd.NewCollectorMetricsCollector(
    collector,
    "/etc/condor/ganglia.d", // or "" for defaults only
    1,                        // verbosity level
)

// Create registry and register
registry := metricsd.NewRegistry()
registry.Register(configCollector)
registry.Register(metricsd.NewProcessCollector())

// Export
exporter := metricsd.NewPrometheusExporter(registry)
metricsText, err := exporter.Export(ctx)
```

### HTTP Server Integration

Or simply enable in httpserver:

```go
cfg := httpserver.Config{
    Collector: htcondor.NewCollector("collector.example.com", 9618),
    EnableMetrics: true,  // Optional, enabled by default when Collector is set
    // ... other config
}
server, _ := httpserver.NewServer(cfg)
// Metrics available at http://localhost:8080/metrics
```

### Custom Metric Definitions

Create a file in `/etc/condor/ganglia.d/custom_metrics`:

```classad
[
  Name   = "CustomGPUUtilization";
  Value  = GPUUtilization;
  Desc   = "GPU utilization percentage";
  Units  = "%";
  TargetType = "Machine";
  Verbosity = 0;
]
[
  Name   = "CustomJobWaitTime";
  Value  = (CurrentTime - QDate) / 3600;
  Desc   = "Job wait time in hours";
  Units  = "hours";
  Scale  = 0.000277778;
  Type   = "float";
  TargetType = "Scheduler";
]
```

Then configure HTCondor to use this directory:

```bash
GANGLIAD_METRICS_CONFIG_DIR = /etc/condor/ganglia.d
```

## Comparison with condor_gangliad

| Aspect | condor_gangliad | metricsd |
|--------|----------------|----------|
| **Purpose** | Publish HTCondor metrics to Ganglia | Export HTCondor metrics in Prometheus format |
| **Language** | C++ | Go |
| **Deployment** | Standalone daemon | Embedded in services |
| **Export Format** | Ganglia protocol | Prometheus text format |
| **Extensibility** | Hard-coded metrics | Pluggable collector interface |
| **Caching** | Fixed intervals | Configurable TTL |
| **Integration** | Requires Ganglia setup | Works with any Prometheus-compatible system |

## Future Enhancements

Potential additions:
- Histogram metrics for latencies
- Additional collectors (negotiator stats, file transfer metrics)
- OpenMetrics format support
- Metric filtering/selection
- Push gateway support
- StatsD export option
