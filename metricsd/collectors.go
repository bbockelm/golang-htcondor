package metricsd

import (
	"context"
	"fmt"
	"runtime"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// PoolCollector collects metrics about the HTCondor pool
type PoolCollector struct {
	collector *htcondor.Collector
}

// NewPoolCollector creates a new pool metrics collector
func NewPoolCollector(collector *htcondor.Collector) *PoolCollector {
	return &PoolCollector{
		collector: collector,
	}
}

// Collect gathers pool-wide metrics from the collector using streaming API
func (c *PoolCollector) Collect(ctx context.Context) ([]Metric, error) {
	metrics := make([]Metric, 0)
	now := time.Now()

	// Query for startd (machine) ads using streaming API
	startdCh, err := c.collector.QueryAdsStream(ctx, "Startd", "", nil, -1, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to query startd ads: %w", err)
	}

	// Process startd ads one at a time - no buffering
	totalMachines := 0
	stateCount := make(map[string]int)
	totalCPUs := int64(0)
	totalMemory := int64(0)
	usedCPUs := int64(0)
	usedMemory := int64(0)

	for result := range startdCh {
		if result.Err != nil {
			return nil, fmt.Errorf("error streaming startd ads: %w", result.Err)
		}
		ad := result.Ad
		totalMachines++

		// Get state
		if state := ad.EvaluateAttr("State"); !state.IsError() {
			if stateStr, err := state.StringValue(); err == nil {
				stateCount[stateStr]++
			}
		}

		// Get CPU count
		if cpus := ad.EvaluateAttr("Cpus"); !cpus.IsError() {
			if cpuCount, err := cpus.IntValue(); err == nil {
				totalCPUs += cpuCount
			}
		}

		// Get memory
		if memory := ad.EvaluateAttr("Memory"); !memory.IsError() {
			if memoryVal, err := memory.IntValue(); err == nil {
				totalMemory += memoryVal
			}
		}

		// Get activity
		if activity := ad.EvaluateAttr("Activity"); !activity.IsError() {
			if activityStr, err := activity.StringValue(); err == nil {
				if activityStr == "Busy" {
					// Count busy CPUs
					if cpus := ad.EvaluateAttr("Cpus"); !cpus.IsError() {
						if cpuCount, err := cpus.IntValue(); err == nil {
							usedCPUs += cpuCount
						}
					}
					// Count busy memory
					if memory := ad.EvaluateAttr("Memory"); !memory.IsError() {
						if memoryVal, err := memory.IntValue(); err == nil {
							usedMemory += memoryVal
						}
					}
				}
			}
		}
	}

	// Add machine count metric
	metrics = append(metrics, Metric{
		Name:      "htcondor_pool_machines_total",
		Type:      MetricTypeGauge,
		Value:     float64(totalMachines),
		Timestamp: now,
		Help:      "Total number of machines in the pool",
	})

	// Add state metrics
	for state, count := range stateCount {
		metrics = append(metrics, Metric{
			Name:      "htcondor_pool_machines_state",
			Type:      MetricTypeGauge,
			Value:     float64(count),
			Labels:    map[string]string{"state": state},
			Timestamp: now,
			Help:      "Number of machines by state",
		})
	}

	// Add resource metrics
	metrics = append(metrics, Metric{
		Name:      "htcondor_pool_cpus_total",
		Type:      MetricTypeGauge,
		Value:     float64(totalCPUs),
		Timestamp: now,
		Help:      "Total CPU cores in the pool",
	})

	metrics = append(metrics, Metric{
		Name:      "htcondor_pool_cpus_used",
		Type:      MetricTypeGauge,
		Value:     float64(usedCPUs),
		Timestamp: now,
		Help:      "Used CPU cores in the pool",
	})

	metrics = append(metrics, Metric{
		Name:      "htcondor_pool_memory_mb_total",
		Type:      MetricTypeGauge,
		Value:     float64(totalMemory),
		Timestamp: now,
		Help:      "Total memory in MB in the pool",
	})

	metrics = append(metrics, Metric{
		Name:      "htcondor_pool_memory_mb_used",
		Type:      MetricTypeGauge,
		Value:     float64(usedMemory),
		Timestamp: now,
		Help:      "Used memory in MB in the pool",
	})

	// Query for schedd ads using streaming API
	scheddCh, err := c.collector.QueryAdsStream(ctx, "Schedd", "", nil, -1, nil)
	if err == nil {
		totalSchedds := 0
		totalJobs := int64(0)

		for result := range scheddCh {
			if result.Err != nil {
				// Log error but continue
				break
			}
			ad := result.Ad
			totalSchedds++

			if jobs := ad.EvaluateAttr("TotalIdleJobs"); !jobs.IsError() {
				if count, err := jobs.IntValue(); err == nil {
					totalJobs += count
				}
			}
			if jobs := ad.EvaluateAttr("TotalRunningJobs"); !jobs.IsError() {
				if count, err := jobs.IntValue(); err == nil {
					totalJobs += count
				}
			}
			if jobs := ad.EvaluateAttr("TotalHeldJobs"); !jobs.IsError() {
				if count, err := jobs.IntValue(); err == nil {
					totalJobs += count
				}
			}
		}

		metrics = append(metrics, Metric{
			Name:      "htcondor_pool_schedds_total",
			Type:      MetricTypeGauge,
			Value:     float64(totalSchedds),
			Timestamp: now,
			Help:      "Total number of schedd daemons in the pool",
		})

		metrics = append(metrics, Metric{
			Name:      "htcondor_pool_jobs_total",
			Type:      MetricTypeGauge,
			Value:     float64(totalJobs),
			Timestamp: now,
			Help:      "Total number of jobs in the pool",
		})
	}

	return metrics, nil
}

// ProcessCollector collects metrics about the current process
type ProcessCollector struct{}

// NewProcessCollector creates a new process metrics collector
func NewProcessCollector() *ProcessCollector {
	return &ProcessCollector{}
}

// Collect gathers process-level metrics
func (c *ProcessCollector) Collect(_ context.Context) ([]Metric, error) {
	metrics := make([]Metric, 0)
	now := time.Now()

	// Get memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	metrics = append(metrics, Metric{
		Name:      "process_resident_memory_bytes",
		Type:      MetricTypeGauge,
		Value:     float64(m.Alloc),
		Timestamp: now,
		Help:      "Process resident memory in bytes",
	})

	metrics = append(metrics, Metric{
		Name:      "process_heap_bytes",
		Type:      MetricTypeGauge,
		Value:     float64(m.HeapAlloc),
		Timestamp: now,
		Help:      "Process heap size in bytes",
	})

	metrics = append(metrics, Metric{
		Name:      "process_goroutines",
		Type:      MetricTypeGauge,
		Value:     float64(runtime.NumGoroutine()),
		Timestamp: now,
		Help:      "Number of goroutines",
	})

	return metrics, nil
}
