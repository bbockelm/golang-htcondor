package httpserver

import (
	"sync"
	"time"
)

// pingHealth tracks recent ping outcomes for the collector and schedd so
// /readyz can report a degraded state without each handler having to recompute
// it. The key invariant: a successful ping resets the recorded error and
// timestamps the success; a failed ping records the error and *does not*
// touch the lastSuccess timestamp, so /readyz can compute "time since last
// good ping" to drive a warning vs. ok decision.
type pingHealth struct {
	mu sync.RWMutex

	// pingInterval is the operator-configured cadence. If a daemon hasn't
	// pinged successfully in stalenessMultiplier * pingInterval, /readyz
	// flags it. Zero means "we don't ping at all" and health reporting is
	// disabled.
	pingInterval time.Duration

	collectorEnabled    bool
	collectorLastOK     time.Time
	collectorLastErr    error
	collectorLastErrAt  time.Time
	collectorLastErrCls connErrorClass

	scheddEnabled    bool
	scheddLastOK     time.Time
	scheddLastErr    error
	scheddLastErrAt  time.Time
	scheddLastErrCls connErrorClass
}

// stalenessMultiplier controls how many ping intervals must pass without a
// successful ping before we flag the daemon as stale. Two ticks gives one
// missed-ping grace period, which keeps a single transient hiccup from
// flapping /readyz from ok → warning → ok.
const stalenessMultiplier = 2

// newPingHealth constructs a tracker. pingInterval may be zero, in which case
// recordSuccess/recordFailure become no-ops and snapshot reports "disabled".
func newPingHealth(pingInterval time.Duration) *pingHealth {
	return &pingHealth{pingInterval: pingInterval}
}

// markCollectorEnabled / markScheddEnabled flip the per-daemon flags so that
// snapshot() knows whether to include the daemon in the health view at all.
// We can't infer this from "has it ever succeeded" because the daemon might
// be enabled but currently unreachable.
func (p *pingHealth) markCollectorEnabled() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.collectorEnabled = true
	p.mu.Unlock()
}

func (p *pingHealth) markScheddEnabled() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.scheddEnabled = true
	p.mu.Unlock()
}

func (p *pingHealth) recordCollectorSuccess() {
	if p == nil || p.pingInterval == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.collectorLastOK = time.Now()
	p.collectorLastErr = nil
	p.collectorLastErrAt = time.Time{}
	p.collectorLastErrCls = ""
}

func (p *pingHealth) recordScheddSuccess() {
	if p == nil || p.pingInterval == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.scheddLastOK = time.Now()
	p.scheddLastErr = nil
	p.scheddLastErrAt = time.Time{}
	p.scheddLastErrCls = ""
}

func (p *pingHealth) recordCollectorFailure(err error, cls connErrorClass) {
	if p == nil || p.pingInterval == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.collectorLastErr = err
	p.collectorLastErrAt = time.Now()
	p.collectorLastErrCls = cls
}

func (p *pingHealth) recordScheddFailure(err error, cls connErrorClass) {
	if p == nil || p.pingInterval == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.scheddLastErr = err
	p.scheddLastErrAt = time.Now()
	p.scheddLastErrCls = cls
}

// daemonHealthStatus is the per-daemon view returned to /readyz.
type daemonHealthStatus struct {
	Status        string `json:"status"`                    // "ok" | "warning" | "down" | "disabled" | "unknown"
	LastOK        string `json:"last_ok,omitempty"`         // RFC3339 timestamp; omitted if never
	LastError     string `json:"last_error,omitempty"`      // human-readable error text from the most recent failure
	LastErrorAt   string `json:"last_error_at,omitempty"`   // RFC3339 timestamp of the most recent failure
	LastErrorKind string `json:"last_error_kind,omitempty"` // connErrorClass string; helps operators triage
}

// healthSnapshot is the combined view returned to /readyz.
type healthSnapshot struct {
	Status    string             `json:"status"` // overall: "ok" | "warning" | "down"
	Collector daemonHealthStatus `json:"collector"`
	Schedd    daemonHealthStatus `json:"schedd"`
}

// snapshot computes the current health view at this moment. Reading is
// lock-light: a single RLock plus copies of the recorded times.
//
// Status decision:
//   - daemon never pinged successfully (and is enabled) → "down"
//     (this catches startup before the first tick fires, but more importantly
//     it catches "configured but never reachable")
//   - lastOK older than stalenessMultiplier * pingInterval → "warning"
//   - lastErr more recent than lastOK → "warning"
//   - otherwise → "ok"
//
// Overall status is the worst of the per-daemon statuses, with "warning" and
// "down" outranking "ok".
func (p *pingHealth) snapshot() healthSnapshot {
	if p == nil {
		return healthSnapshot{
			Status:    "ok",
			Collector: daemonHealthStatus{Status: "disabled"},
			Schedd:    daemonHealthStatus{Status: "disabled"},
		}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	collector := p.computeStatusLocked(p.collectorEnabled, p.collectorLastOK, p.collectorLastErr, p.collectorLastErrAt, p.collectorLastErrCls, now)
	schedd := p.computeStatusLocked(p.scheddEnabled, p.scheddLastOK, p.scheddLastErr, p.scheddLastErrAt, p.scheddLastErrCls, now)

	return healthSnapshot{
		Status:    worseStatus(collector.Status, schedd.Status),
		Collector: collector,
		Schedd:    schedd,
	}
}

func (p *pingHealth) computeStatusLocked(enabled bool, lastOK time.Time, lastErr error, lastErrAt time.Time, cls connErrorClass, now time.Time) daemonHealthStatus {
	if !enabled || p.pingInterval == 0 {
		return daemonHealthStatus{Status: "disabled"}
	}

	out := daemonHealthStatus{}
	if !lastOK.IsZero() {
		out.LastOK = lastOK.UTC().Format(time.RFC3339)
	}
	if lastErr != nil {
		out.LastError = lastErr.Error()
		if !lastErrAt.IsZero() {
			out.LastErrorAt = lastErrAt.UTC().Format(time.RFC3339)
		}
		if cls != "" {
			out.LastErrorKind = string(cls)
		}
	}

	switch {
	case lastOK.IsZero() && lastErr != nil:
		out.Status = "down"
	case lastOK.IsZero():
		out.Status = "unknown"
	case now.Sub(lastOK) > stalenessMultiplier*p.pingInterval:
		out.Status = "warning"
	case lastErr != nil && lastErrAt.After(lastOK):
		out.Status = "warning"
	default:
		out.Status = "ok"
	}
	return out
}

// worseStatus returns the more pessimistic of two daemon statuses for the
// overall report. Order: down > warning > unknown > ok > disabled.
func worseStatus(a, b string) string {
	rank := func(s string) int {
		switch s {
		case "down":
			return 4
		case "warning":
			return 3
		case "unknown":
			return 2
		case "ok":
			return 1
		case "disabled":
			return 0
		default:
			return 0
		}
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}
