# Sample /metrics Endpoint Output

This document shows sample output from the `/metrics` endpoint with the HTCondor metrics collection system.

## Basic Pool Metrics

These are the foundational metrics collected from a small HTCondor pool:

```prometheus
# HELP htcondor_pool_cpus_total Total CPU cores in the pool
# TYPE htcondor_pool_cpus_total gauge
htcondor_pool_cpus_total 48 1699876543000

# HELP htcondor_pool_cpus_used Used CPU cores in the pool
# TYPE htcondor_pool_cpus_used gauge
htcondor_pool_cpus_used 24 1699876543000

# HELP htcondor_pool_jobs_total Total number of jobs in the pool
# TYPE htcondor_pool_jobs_total gauge
htcondor_pool_jobs_total 150 1699876543000

# HELP htcondor_pool_machines_state Number of machines by state
# TYPE htcondor_pool_machines_state gauge
htcondor_pool_machines_state{state="Claimed"} 12 1699876543000
htcondor_pool_machines_state{state="Unclaimed"} 8 1699876543000

# HELP htcondor_pool_machines_total Total number of machines in the pool
# TYPE htcondor_pool_machines_total gauge
htcondor_pool_machines_total 20 1699876543000

# HELP htcondor_pool_memory_mb_total Total memory in MB in the pool
# TYPE htcondor_pool_memory_mb_total gauge
htcondor_pool_memory_mb_total 196608 1699876543000

# HELP htcondor_pool_memory_mb_used Used memory in MB in the pool
# TYPE htcondor_pool_memory_mb_used gauge
htcondor_pool_memory_mb_used 98304 1699876543000

# HELP htcondor_pool_schedds_total Total number of schedd daemons in the pool
# TYPE htcondor_pool_schedds_total gauge
htcondor_pool_schedds_total 3 1699876543000
```

## Process Metrics

Metrics about the metricsd process itself:

```prometheus
# HELP process_goroutines Number of goroutines
# TYPE process_goroutines gauge
process_goroutines 15 1699876543000

# HELP process_heap_bytes Process heap size in bytes
# TYPE process_heap_bytes gauge
process_heap_bytes 8388608 1699876543000

# HELP process_resident_memory_bytes Process resident memory in bytes
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 16777216 1699876543000
```

## Detailed Daemon Metrics (from ganglia_default_metrics)

When using the CollectorMetricsCollector with default metrics configuration, you'll get detailed per-daemon metrics:

### Schedd (Scheduler) Metrics

```prometheus
# HELP htcondor_jobssubmitted Number of jobs submitted
# TYPE htcondor_jobssubmitted gauge
htcondor_jobssubmitted{daemon="schedd@submit-1.example.com",machine="submit-1.example.com",type="Scheduler"} 5420 1699876543000
htcondor_jobssubmitted{daemon="schedd@submit-2.example.com",machine="submit-2.example.com",type="Scheduler"} 3180 1699876543000
htcondor_jobssubmitted{daemon="schedd@submit-3.example.com",machine="submit-3.example.com",type="Scheduler"} 2100 1699876543000

# HELP htcondor_jobscompleted Number of jobs that terminated normally
# TYPE htcondor_jobscompleted gauge
htcondor_jobscompleted{daemon="schedd@submit-1.example.com",machine="submit-1.example.com",type="Scheduler"} 5200 1699876543000
htcondor_jobscompleted{daemon="schedd@submit-2.example.com",machine="submit-2.example.com",type="Scheduler"} 3050 1699876543000
htcondor_jobscompleted{daemon="schedd@submit-3.example.com",machine="submit-3.example.com",type="Scheduler"} 1980 1699876543000

# HELP htcondor_jobsaccumrunningtime Time spent running jobs (hours)
# TYPE htcondor_jobsaccumrunningtime gauge
htcondor_jobsaccumrunningtime{daemon="schedd@submit-1.example.com",machine="submit-1.example.com",type="Scheduler"} 48250.5 1699876543000
htcondor_jobsaccumrunningtime{daemon="schedd@submit-2.example.com",machine="submit-2.example.com",type="Scheduler"} 28150.2 1699876543000
htcondor_jobsaccumrunningtime{daemon="schedd@submit-3.example.com",machine="submit-3.example.com",type="Scheduler"} 18200.8 1699876543000

# HELP htcondor_schedulermonitorselfimagesizeit Memory allocated to this daemon (KB)
# TYPE htcondor_schedulermonitorselfimagesizeit gauge
htcondor_schedulermonitorselfimagesizeit{daemon="schedd@submit-1.example.com",machine="submit-1.example.com",type="Scheduler"} 524288 1699876543000
htcondor_schedulermonitorselfimagesizeit{daemon="schedd@submit-2.example.com",machine="submit-2.example.com",type="Scheduler"} 448512 1699876543000
htcondor_schedulermonitorselfimagesizeit{daemon="schedd@submit-3.example.com",machine="submit-3.example.com",type="Scheduler"} 389120 1699876543000

# HELP htcondor_schedulerrecentdaemoncoredutyc Recent fraction of busy time (percentage)
# TYPE htcondor_schedulerrecentdaemoncoredutyc gauge
htcondor_schedulerrecentdaemoncoredutyc{daemon="schedd@submit-1.example.com",machine="submit-1.example.com",type="Scheduler"} 45.2 1699876543000
htcondor_schedulerrecentdaemoncoredutyc{daemon="schedd@submit-2.example.com",machine="submit-2.example.com",type="Scheduler"} 32.8 1699876543000
htcondor_schedulerrecentdaemoncoredutyc{daemon="schedd@submit-3.example.com",machine="submit-3.example.com",type="Scheduler"} 28.5 1699876543000
```

### Negotiator Metrics

```prometheus
# HELP htcondor_negotiatormonitorselfimagesizeit Memory allocated to negotiator daemon (KB)
# TYPE htcondor_negotiatormonitorselfimagesizeit gauge
htcondor_negotiatormonitorselfimagesizeit{daemon="negotiator",machine="cm.example.com",type="Negotiator"} 98304 1699876543000

# HELP htcondor_negotiatorrecentdaemoncoredutyc Recent fraction of busy time (percentage)
# TYPE htcondor_negotiatorrecentdaemoncoredutyc gauge
htcondor_negotiatorrecentdaemoncoredutyc{daemon="negotiator",machine="cm.example.com",type="Negotiator"} 15.3 1699876543000

# HELP htcondor_negotiatorupdateslost Updates lost by collector
# TYPE htcondor_negotiatorupdateslost gauge
htcondor_negotiatorupdateslost{daemon="negotiator",machine="cm.example.com",type="Negotiator"} 0 1699876543000

# HELP htcondor_negotiatorupdatestotal Total updates sent to collector
# TYPE htcondor_negotiatorupdatestotal gauge
htcondor_negotiatorupdatestotal{daemon="negotiator",machine="cm.example.com",type="Negotiator"} 15420 1699876543000
```

### Machine (Startd) Metrics

For slot-level metrics, each slot gets its own labels:

```prometheus
# HELP htcondor_machinecondorloadavg HTCondor load average
# TYPE htcondor_machinecondorloadavg gauge
htcondor_machinecondorloadavg{daemon="slot1@exec-1.example.com",machine="exec-1.example.com",type="Machine"} 0.85 1699876543000
htcondor_machinecondorloadavg{daemon="slot1@exec-2.example.com",machine="exec-2.example.com",type="Machine"} 1.20 1699876543000
htcondor_machinecondorloadavg{daemon="slot1@exec-3.example.com",machine="exec-3.example.com",type="Machine"} 0.42 1699876543000

# HELP htcondor_machinemonitorselfimagesizeit Memory allocated to startd daemon (KB)
# TYPE htcondor_machinemonitorselfimagesizeit gauge
htcondor_machinemonitorselfimagesizeit{daemon="slot1@exec-1.example.com",machine="exec-1.example.com",type="Machine"} 65536 1699876543000
htcondor_machinemonitorselfimagesizeit{daemon="slot1@exec-2.example.com",machine="exec-2.example.com",type="Machine"} 65536 1699876543000
htcondor_machinemonitorselfimagesizeit{daemon="slot1@exec-3.example.com",machine="exec-3.example.com",type="Machine"} 65536 1699876543000

# HELP htcondor_machinerecentdaemoncoredutyc Recent startd daemon duty cycle (percentage)
# TYPE htcondor_machinerecentdaemoncoredutyc gauge
htcondor_machinerecentdaemoncoredutyc{daemon="slot1@exec-1.example.com",machine="exec-1.example.com",type="Machine"} 5.2 1699876543000
htcondor_machinerecentdaemoncoredutyc{daemon="slot1@exec-2.example.com",machine="exec-2.example.com",type="Machine"} 4.8 1699876543000
htcondor_machinerecentdaemoncoredutyc{daemon="slot1@exec-3.example.com",machine="exec-3.example.com",type="Machine"} 6.1 1699876543000
```

## Aggregated Metrics

When using aggregate functions in metric definitions, you get pool-wide sums/averages:

```prometheus
# HELP htcondor_total_running_jobs Total running jobs across all schedds
# TYPE htcondor_total_running_jobs gauge
htcondor_total_running_jobs 142 1699876543000

# HELP htcondor_total_idle_jobs Total idle jobs across all schedds
# TYPE htcondor_total_idle_jobs gauge
htcondor_total_idle_jobs 58 1699876543000

# HELP htcondor_avg_cpu_load Average CPU load across all machines
# TYPE htcondor_avg_cpu_load gauge
htcondor_avg_cpu_load 0.82 1699876543000
```

## Custom Metrics

Example of custom metrics defined by admin in config directory:

```prometheus
# HELP htcondor_gpu_utilization GPU utilization percentage
# TYPE htcondor_gpu_utilization gauge
htcondor_gpu_utilization{daemon="slot1_1@gpu-1.example.com",gpu="0",machine="gpu-1.example.com",type="Machine"} 95.2 1699876543000
htcondor_gpu_utilization{daemon="slot1_2@gpu-1.example.com",gpu="1",machine="gpu-1.example.com",type="Machine"} 87.5 1699876543000

# HELP htcondor_custom_fair_share_usage Fair share usage by group
# TYPE htcondor_custom_fair_share_usage gauge
htcondor_custom_fair_share_usage{group="physics"} 0.45 1699876543000
htcondor_custom_fair_share_usage{group="chemistry"} 0.32 1699876543000
htcondor_custom_fair_share_usage{group="biology"} 0.23 1699876543000
```

## Complete Example Output

Here's what a full scrape might look like with all metric types combined:

```prometheus
# HELP htcondor_jobscompleted Number of jobs that terminated normally
# TYPE htcondor_jobscompleted gauge
htcondor_jobscompleted{daemon="schedd@submit-1.example.com",machine="submit-1.example.com",type="Scheduler"} 5200 1699876543000
htcondor_jobscompleted{daemon="schedd@submit-2.example.com",machine="submit-2.example.com",type="Scheduler"} 3050 1699876543000
# HELP htcondor_jobssubmitted Number of jobs submitted
# TYPE htcondor_jobssubmitted gauge
htcondor_jobssubmitted{daemon="schedd@submit-1.example.com",machine="submit-1.example.com",type="Scheduler"} 5420 1699876543000
htcondor_jobssubmitted{daemon="schedd@submit-2.example.com",machine="submit-2.example.com",type="Scheduler"} 3180 1699876543000
# HELP htcondor_negotiatorrecentdaemoncoredutyc Recent fraction of busy time (percentage)
# TYPE htcondor_negotiatorrecentdaemoncoredutyc gauge
htcondor_negotiatorrecentdaemoncoredutyc{daemon="negotiator",machine="cm.example.com",type="Negotiator"} 15.3 1699876543000
# HELP htcondor_pool_cpus_total Total CPU cores in the pool
# TYPE htcondor_pool_cpus_total gauge
htcondor_pool_cpus_total 48 1699876543000
# HELP htcondor_pool_cpus_used Used CPU cores in the pool
# TYPE htcondor_pool_cpus_used gauge
htcondor_pool_cpus_used 24 1699876543000
# HELP htcondor_pool_machines_state Number of machines by state
# TYPE htcondor_pool_machines_state gauge
htcondor_pool_machines_state{state="Claimed"} 12 1699876543000
htcondor_pool_machines_state{state="Unclaimed"} 8 1699876543000
# HELP htcondor_pool_machines_total Total number of machines in the pool
# TYPE htcondor_pool_machines_total gauge
htcondor_pool_machines_total 20 1699876543000
# HELP htcondor_pool_memory_mb_total Total memory in MB in the pool
# TYPE htcondor_pool_memory_mb_total gauge
htcondor_pool_memory_mb_total 196608 1699876543000
# HELP htcondor_pool_memory_mb_used Used memory in MB in the pool
# TYPE htcondor_pool_memory_mb_used gauge
htcondor_pool_memory_mb_used 98304 1699876543000
# HELP process_goroutines Number of goroutines
# TYPE process_goroutines gauge
process_goroutines 15 1699876543000
# HELP process_heap_bytes Process heap size in bytes
# TYPE process_heap_bytes gauge
process_heap_bytes 8388608 1699876543000
# HELP process_resident_memory_bytes Process resident memory in bytes
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 16777216 1699876543000
```

## Label Dimensions

All metrics from specific daemons include these labels:

- `daemon`: The daemon name (e.g., "schedd@submit-1.example.com", "slot1@exec-1.example.com")
- `machine`: The machine hostname
- `type`: The HTCondor daemon type (Scheduler, Negotiator, Collector, Machine)

Additional labels may be added based on:
- Metric definitions (via `AggregateGroup` or custom label attributes)
- Machine state, activity, universe
- Custom ClassAd attributes specified in metric configuration

## Prometheus Query Examples

Once metrics are being collected, you can query them:

```promql
# Total jobs submitted across all schedds
sum(htcondor_jobssubmitted)

# Job completion rate (jobs/hour)
rate(htcondor_jobscompleted[1h])

# CPU utilization percentage
100 * (htcondor_pool_cpus_used / htcondor_pool_cpus_total)

# Jobs per schedd
sum by (daemon) (htcondor_jobssubmitted)

# Memory utilization by machine
htcondor_pool_memory_mb_used / htcondor_pool_memory_mb_total

# Duty cycle alerts (when schedulers are overloaded)
htcondor_schedulerrecentdaemoncoredutyc > 90
```

## Configuration

To enable these metrics in your deployment:

1. **Basic pool metrics** - Just provide a Collector to httpserver
2. **Detailed daemon metrics** - Use `CollectorMetricsCollector` with default metrics
3. **Custom metrics** - Add metric definition files to `GANGLIAD_METRICS_CONFIG_DIR`
4. **Adjust verbosity** - Set verbosity level to filter metrics (0=all, higher=fewer)

See `metricsd/README.md` for full configuration documentation.
