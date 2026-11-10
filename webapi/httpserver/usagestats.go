package httpserver

import (
	"context"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/usagestats"
)

// DefaultUsageStatsFlushInterval is how often the call counters are
// written to SQLite.
//
// Five minutes, because the flush exists to bound what a crash loses,
// not to keep the table current for a reader: /metrics is always exact,
// and the table is a durable backstop. A shorter interval would write
// the same rows more often for no extra fidelity anywhere a human
// looks; a longer one would lose more counting to a kill -9.
//
// A flush on an idle server does no writes at all -- each store tracks
// whether anything was recorded since the last one.
const DefaultUsageStatsFlushInterval = 5 * time.Minute

// usageStores returns every store this handler keeps, so the load,
// register, flush and shutdown paths cannot drift apart as kinds are
// added. A nil store is skipped rather than panicking: partial test
// setups build a Handler without them.
func (h *Handler) usageStores() []*usagestats.Store {
	var out []*usagestats.Store
	for _, s := range []*usagestats.Store{h.toolStats, h.restStats} {
		if s != nil {
			out = append(out, s)
		}
	}
	return out
}

// startUsageStats loads the persisted totals, registers them on the
// metrics registry, and starts the periodic flush.
//
// Failure is logged and not returned. These are statistics: a server
// that will not boot because it could not read its own call counters
// is worse than one that boots having lost them.
func (h *Handler) startUsageStats() {
	stores := h.usageStores()
	if len(stores) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, store := range stores {
		spec := store.Spec()
		if err := store.LoadFrom(ctx, h.db); err != nil {
			// Not fatal, but not harmless either: until a load succeeds
			// the store refuses to flush, because writing absolute
			// totals from an empty store would destroy the record it
			// could not read. Counting continues in memory and the next
			// flush tick retries the load.
			h.logger.Warn(logging.DestinationHTTP,
				"Could not load persisted usage statistics; counting continues but "+
					"nothing will be persisted until the stored totals can be read",
				"kind", spec.Kind, "error", err)
		} else if n := len(store.Snapshot()); n > 0 {
			h.logger.Info(logging.DestinationMetrics,
				"Resumed usage statistics from the application database",
				"kind", spec.Kind, "series", n)
		}

		if h.httpMetricsState != nil {
			h.httpMetricsState.registry.MustRegister(
				usagestats.NewCollectorWithOptions(store, h.usageStatsOmitUser))
		}
	}

	interval := h.usageStatsFlushInterval
	if interval <= 0 {
		interval = DefaultUsageStatsFlushInterval
	}
	h.usageStatsStop = make(chan struct{})
	go h.flushUsageStatsLoop(interval)
}

func (h *Handler) flushUsageStatsLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.usageStatsStop:
			return
		case <-ticker.C:
			h.flushUsageStatsOnce("periodic")
		}
	}
}

func (h *Handler) flushUsageStatsOnce(reason string) {
	if h.db == nil {
		return
	}
	// Deliberately NOT derived from a request context. This runs on a
	// timer and at shutdown, and a flush that inherited a cancelled
	// context would drop the very write that shutdown exists to make.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	for _, store := range h.usageStores() {
		kind := store.Spec().Kind

		// A store that failed to load cannot safely be written. Retry
		// the read first: a load that failed on a contended connection
		// or a slow disk usually succeeds later, and without this the
		// process would count for days and persist none of it.
		if store.LoadFailed() {
			// ReloadFrom, not LoadFrom: the store holds the calls
			// counted since the failure, and a replacing load would
			// discard them.
			if err := store.ReloadFrom(ctx, h.db); err != nil {
				h.logger.Warn(logging.DestinationHTTP,
					"Still cannot read the persisted usage statistics; not persisting, "+
						"because writing would replace them with this process's counts alone",
					"kind", kind, "reason", reason, "error", err)
				continue
			}
			h.logger.Info(logging.DestinationMetrics,
				"Re-read the persisted usage statistics; persistence resumes", "kind", kind)
		}

		if err := store.Flush(ctx, h.db); err != nil {
			h.logger.Warn(logging.DestinationHTTP,
				"Could not persist usage statistics",
				"kind", kind, "reason", reason, "error", err)
		}
	}
}

// StopUsageStats halts the periodic flush and writes once more, so the
// counters a clean shutdown leaves behind are complete rather than up
// to one interval stale.
//
// Safe to call on a Handler that never started the loop, and safe to
// call twice: Server.Shutdown can run from more than one signal path.
func (h *Handler) StopUsageStats() {
	if h.usageStatsStop != nil {
		h.usageStatsStopOnce.Do(func() { close(h.usageStatsStop) })
	}
	h.flushUsageStatsOnce("shutdown")
}
