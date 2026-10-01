package httpserver

import (
	"context"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/toolstats"
)

// DefaultToolStatsFlushInterval is how often the tool-call counters are
// written to SQLite.
//
// Five minutes, because the flush exists to bound what a crash loses,
// not to keep the table current for a reader: /metrics is always exact,
// and the table is a durable backstop. A shorter interval would write
// the same rows more often for no extra fidelity anywhere a human
// looks; a longer one would lose more counting to a kill -9.
//
// A flush on an idle server does no writes at all -- the store tracks
// whether anything was recorded since the last one.
const DefaultToolStatsFlushInterval = 5 * time.Minute

// startToolStats loads the persisted tool-call totals, registers them
// on the metrics registry, and starts the periodic flush.
//
// Failure is logged and not returned. These are statistics: a server
// that will not boot because it could not read its own call counters
// is worse than one that boots having lost them.
func (h *Handler) startToolStats() {
	if h.toolStats == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.toolStats.LoadFrom(ctx, h.db); err != nil {
		h.logger.Warn(logging.DestinationHTTP,
			"Could not load persisted MCP tool statistics; counters start from zero",
			"error", err)
	} else if n := len(h.toolStats.Snapshot()); n > 0 {
		h.logger.Info(logging.DestinationMetrics,
			"Resumed MCP tool statistics from the application database", "series", n)
	}

	if h.httpMetricsState != nil {
		h.httpMetricsState.registry.MustRegister(toolstats.NewCollector(h.toolStats))
	}

	interval := h.toolStatsFlushInterval
	if interval <= 0 {
		interval = DefaultToolStatsFlushInterval
	}
	h.toolStatsStop = make(chan struct{})
	go h.flushToolStatsLoop(interval)
}

func (h *Handler) flushToolStatsLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.toolStatsStop:
			return
		case <-ticker.C:
			h.flushToolStatsOnce("periodic")
		}
	}
}

func (h *Handler) flushToolStatsOnce(reason string) {
	if h.toolStats == nil || h.db == nil {
		return
	}
	// Deliberately NOT derived from a request context. This runs on a
	// timer and at shutdown, and a flush that inherited a cancelled
	// context would drop the very write that shutdown exists to make.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := h.toolStats.Flush(ctx, h.db); err != nil {
		h.logger.Warn(logging.DestinationHTTP,
			"Could not persist MCP tool statistics", "reason", reason, "error", err)
	}
}

// StopToolStats halts the periodic flush and writes once more, so the
// counters a clean shutdown leaves behind are complete rather than up
// to one interval stale.
//
// Safe to call on a Handler that never started the loop, and safe to
// call twice: Server.Shutdown can run from more than one signal path.
func (h *Handler) StopToolStats() {
	if h.toolStatsStop != nil {
		h.toolStatsStopOnce.Do(func() { close(h.toolStatsStop) })
	}
	h.flushToolStatsOnce("shutdown")
}
