package httpserver

import (
	"context"
	"net/http"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// mirrorProbeTimeout bounds the fallback discovery this endpoint can
// force. It is a single collector query, and the page it serves
// refreshes on a timer, so a hung collector must not hold the request
// open.
const mirrorProbeTimeout = 5 * time.Second

// The htcondordb mirror answers job and history reads that would
// otherwise hit the schedd, and it does so silently: a correctly
// configured mirror looks exactly like a fast schedd from the outside.
// That is the right default -- routing is an optimization and a
// fallback must not be alarming -- but it leaves an operator unable to
// tell whether the deployment they configured is doing anything.
//
// /readyz and /metrics already carry this, but both answer the
// monitoring system rather than the person looking at the admin UI. This
// endpoint is the same data shaped for the Info page, plus the counts
// that turn "a mirror exists" into "a mirror is answering queries".

// dbMirrorStatusResponse is the admin view of mirror routing.
type dbMirrorStatusResponse struct {
	// Enabled is whether routing can run at all: it needs both a
	// collector to discover through and the HTCondor config whose SEC_*
	// knobs authenticate the connection. False means the remaining
	// fields are unset and every read goes to the schedd.
	Enabled bool `json:"enabled"`
	// Health is the discovery and freshness view, nil when routing is
	// not enabled. Same shape /readyz reports.
	Health *dbMirrorHealthStatus `json:"health,omitempty"`
	// Routing counts every decision since this process started, by table
	// and outcome. This is what answers "is the mirror actually serving
	// my queries" -- a discovered, fresh mirror that never gets used
	// still shows zero served here.
	Routing []mirrorRoutingCount `json:"routing,omitempty"`
	// ServedTotal and DeclinedTotal summarize Routing so the UI can lead
	// with the answer instead of a table.
	ServedTotal   int64 `json:"served_total"`
	DeclinedTotal int64 `json:"declined_total"`
}

// handleDBMirrorStatus serves the admin view of htcondordb routing.
//
// Admin-gated: it names an internal daemon's address and exposes how the
// deployment is wired, neither of which belongs in a general user's
// hands.
func (s *Handler) handleDBMirrorStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}

	resp := dbMirrorStatusResponse{Enabled: s.dbMirror.Enabled()}
	if resp.Enabled {
		// The background poller normally keeps this current, so the
		// usual case does nothing here. Probe only when it has not run
		// recently -- a handler built without Start having run it, or a
		// wedged loop -- because the worst thing this page can say is
		// "not reachable" about a mirror nothing ever tried to reach.
		// The result is discarded; mirrorHealth reads the same state
		// back.
		if h := s.dbMirror.Health(); h.LastAttempt.IsZero() || time.Since(h.LastAttempt) > dbmirror.PollInterval {
			ctx, cancel := context.WithTimeout(r.Context(), mirrorProbeTimeout)
			_, _ = s.dbMirror.Discover(ctx)
			cancel()
		}
		resp.Health = mirrorHealth(s.dbMirror, time.Now())
	}
	resp.Routing = s.httpMetricsState.mirrorRoutingCounts()
	for _, row := range resp.Routing {
		if row.Decision == "served" {
			resp.ServedTotal += row.Count
			continue
		}
		resp.DeclinedTotal += row.Count
	}

	s.writeJSON(w, http.StatusOK, resp)
}
