# Metrics Demo

This example demonstrates how to use the `metricsd` package to collect and export HTCondor metrics in Prometheus format.

## Building

```bash
cd examples/metrics_demo
go build
```

## Running

```bash
./metrics_demo
```

## What It Does

1. **Collects Process Metrics**: Demonstrates basic metrics collection for the current process (memory, goroutines)

2. **Sets Up Full Metrics Stack**: Shows how to:
   - Create a metrics registry
   - Register multiple collectors (pool and process)
   - Configure caching
   - Export to Prometheus format

3. **Demonstrates Caching**: Shows the performance benefit of the built-in metrics cache

## Example Output

```
HTCondor Metrics Collection Example
====================================

Example 1: Process Metrics
--------------------------
  process_resident_memory_bytes = 2147483.00 (Process resident memory in bytes)
  process_heap_bytes = 1835008.00 (Process heap size in bytes)
  process_goroutines = 2.00 (Number of goroutines)


Example 2: Full Metrics Setup with Prometheus Export
----------------------------------------------------
✓ Created metrics registry with 2 collectors
✓ Created Prometheus exporter

Collecting metrics from HTCondor pool...
# HELP htcondor_pool_cpus_total Total CPU cores in the pool
# TYPE htcondor_pool_cpus_total gauge
htcondor_pool_cpus_total 15000 1699876543000
# HELP htcondor_pool_machines_total Total number of machines in the pool
# TYPE htcondor_pool_machines_total gauge
htcondor_pool_machines_total 450 1699876543000
...

Example 3: Metrics Caching
-------------------------
First collection took: 234ms
Cached collection took: 12µs (speedup: 19500.0x)

✓ Examples complete!
```

## Using in Production

In production, you would typically:

1. Configure the HTTP server with metrics enabled:

```go
cfg := httpserver.Config{
    ListenAddr: ":8080",
    Collector:  htcondor.NewCollector("collector.example.com", 9618),
    EnableMetrics: true,
    MetricsCacheTTL: 10 * time.Second,
}

server, _ := httpserver.NewServer(cfg)
server.Start()
```

2. Configure Prometheus to scrape the endpoint:

```yaml
scrape_configs:
  - job_name: 'htcondor'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 30s
```

3. Create dashboards in Grafana to visualize the metrics

## See Also

- [metricsd/README.md](../../metricsd/README.md) - Full metricsd documentation
- [httpserver/README.md](../../httpserver/README.md) - HTTP server with metrics endpoint
