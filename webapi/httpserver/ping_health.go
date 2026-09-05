package httpserver

import (
	"sync"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
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

// collectorLastSuccess returns the timestamp of the most recent
// successful collector ping. Zero time if none has succeeded yet.
// Used by the periodic ping logger to include "how long since
// things last worked" in failure log lines.
func (p *pingHealth) collectorLastSuccess() time.Time {
	if p == nil {
		return time.Time{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.collectorLastOK
}

// scheddLastSuccess is the schedd counterpart of collectorLastSuccess.
func (p *pingHealth) scheddLastSuccess() time.Time {
	if p == nil {
		return time.Time{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.scheddLastOK
}

// daemonHealthStatus is the per-daemon view returned to /readyz.
type daemonHealthStatus struct {
	Status        string `json:"status"`                    // "ok" | "warning" | "down" | "disabled" | "unknown"
	LastOK        string `json:"last_ok,omitempty"`         // RFC3339 timestamp; omitted if never
	LastError     string `json:"last_error,omitempty"`      // human-readable error text from the most recent failure
	LastErrorAt   string `json:"last_error_at,omitempty"`   // RFC3339 timestamp of the most recent failure
	LastErrorKind string `json:"last_error_kind,omitempty"` // connErrorClass string; helps operators triage

	// AddressAge is how long the current address has been in use ("12m3s").
	// AddressLastConfirmedAge is how long since a successful collector query
	// vouched for the address (may be much shorter when the address itself
	// is stable). Only populated for daemons whose addresses we discover
	// from the collector — i.e., schedd, not collector itself. Intended to
	// catch the failure mode where the address looks stable but is actually
	// stale because the collector queries have been failing for a while.
	AddressAge              string `json:"address_age,omitempty"`
	AddressLastConfirmedAge string `json:"address_last_confirmed_age,omitempty"`
}

// healthSnapshot is the combined view returned to /readyz.
type healthSnapshot struct {
	Status    string             `json:"status"` // overall: "ok" | "warning" | "down"
	Collector daemonHealthStatus `json:"collector"`
	Schedd    daemonHealthStatus `json:"schedd"`

	// DBMirror is present only when htcondordb routing is configured, so
	// a deployment that does not use it sees no change.
	DBMirror *dbMirrorHealthStatus `json:"dbmirror,omitempty"`
}

// dbMirrorHealthStatus answers "is the htcondordb integration working?"
// in one place. A Prometheus scrape answers it over time (see
// mirrorCollector); this is the version an operator can curl on one host
// while setting the integration up, which is when the question is
// hardest to answer and the metrics have no history yet.
type dbMirrorHealthStatus struct {
	// Status is "ok" when a mirror was discovered and is fresh enough to
	// serve, "warning" when it was discovered but reads are currently
	// falling back (stale, behind, or a history gap), "down" when
	// discovery is failing, "unknown" when routing is configured but
	// discovery has not run yet, and "disabled" when routing is not
	// configured. Required routing turns everything but "ok" into errors
	// for callers, so they are worth alerting on there.
	//
	// "unknown" is separate from "down" because discovery is lazy --
	// it runs on a routed read, not on a timer -- so an idle daemon has
	// not failed to reach the mirror, it has not looked. Reporting that
	// as "down" sends an operator hunting for a network problem that
	// does not exist.
	Status string `json:"status"`
	// Required reflects HTTP_API_DBMIRROR_REQUIRED: when true, a read
	// this mirror cannot serve fails instead of using the schedd.
	Required bool `json:"required"`
	// Name and Address are the mirror actually in use, which is what an
	// operator needs when several advertise or when an address override
	// is configured.
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
	// PinnedName / PinnedAddress echo the configured targeting so a typo
	// in either is visible next to the empty result it produced.
	PinnedName    string `json:"pinned_name,omitempty"`
	PinnedAddress string `json:"pinned_address,omitempty"`

	// Discovered says whether the freshness fields below describe a real
	// advertisement. When it is false there is no ad, and the staleness
	// fields are omitted rather than sent as zero -- a literal 0 reads as
	// "perfectly caught up", which is the opposite of "we have no idea".
	Discovered bool `json:"discovered"`
	// AdAgeSeconds is how long ago the ad being described was
	// discovered, which is the age of the INFORMATION below rather than
	// of the mirror's data. Everything the mirror reports about itself
	// -- both staleness figures, caught-up, the gap flag -- was measured
	// when it built that ad, so this says how long ago that was. It is
	// reported next to those figures rather than folded into them,
	// because a mirror that keeps syncing between advertisements is
	// current even when our copy of its self-report is not.
	AdAgeSeconds int64 `json:"ad_age_seconds,omitempty"`

	// The two staleness figures are the mirror's own lag as of that
	// measurement, in seconds, and are what routing gates on.
	JobQueueCaughtUp      bool   `json:"job_queue_caught_up"`
	JobQueueStalenessSecs *int64 `json:"job_queue_staleness_seconds,omitempty"`
	HistoryStalenessSecs  *int64 `json:"history_staleness_seconds,omitempty"`
	HistoryGap            bool   `json:"history_gap"`
	JobsToleranceSecs     int64  `json:"jobs_tolerance_seconds"`
	HistoryToleranceSecs  int64  `json:"history_tolerance_seconds"`

	LastError string `json:"last_error,omitempty"`
	// DialError is why the last attempt to connect to the mirror failed,
	// with DialLastAttempt / DialLastSuccess around it (RFC3339). Kept
	// apart from LastError because discovery and dialing fail
	// independently: the collector can hand back a good ad for a database
	// this daemon cannot authenticate to, and then every read declines
	// with dial_failed while discovery reports no error at all.
	DialError string `json:"dial_error,omitempty"`
	// TokenError is why no IDTOKEN was offered on that attempt, empty
	// when one was. Separate again, because a dial error naming FS,
	// Kerberos and SSL looks exhaustive while omitting the method that
	// was skipped before it was tried.
	TokenError      string `json:"token_error,omitempty"`
	DialLastAttempt string `json:"dial_last_attempt,omitempty"`
	DialLastSuccess string `json:"dial_last_success,omitempty"`
	// LastAttempt is when discovery last queried the collector, and
	// LastSuccess when it last found a mirror. Both RFC3339, omitted when
	// they have never happened. LastAttempt absent is the whole
	// explanation for a status of "unknown".
	LastAttempt string `json:"last_attempt,omitempty"`
	LastSuccess string `json:"last_success,omitempty"`
}

// mirrorHealth renders the Locator's view for /readyz. Returns nil when
// routing is not configured at all.
func mirrorHealth(l *dbmirror.Locator, now time.Time) *dbMirrorHealthStatus {
	h := l.Health()
	if !h.Enabled {
		return nil
	}
	out := &dbMirrorHealthStatus{
		Status:               "down",
		Required:             h.Required,
		PinnedName:           h.Name,
		PinnedAddress:        h.Address,
		LastError:            h.LastError,
		TokenError:           h.TokenError,
		JobsToleranceSecs:    dbmirror.JobsToleranceSecs,
		HistoryToleranceSecs: dbmirror.HistoryToleranceSecs,
	}
	if !h.LastSuccess.IsZero() {
		out.LastSuccess = h.LastSuccess.Format(time.RFC3339)
	}
	if !h.LastAttempt.IsZero() {
		out.LastAttempt = h.LastAttempt.Format(time.RFC3339)
	}
	out.DialError = h.LastDialError
	if !h.LastDialAttempt.IsZero() {
		out.DialLastAttempt = h.LastDialAttempt.Format(time.RFC3339)
	}
	if !h.LastDialSuccess.IsZero() {
		out.DialLastSuccess = h.LastDialSuccess.Format(time.RFC3339)
	}
	// A connection that failed since the last one succeeded means reads
	// are not reaching the mirror, whatever the ad says. It outranks
	// everything below: an ad can look perfectly fresh for a database
	// this daemon cannot authenticate to.
	dialBroken := h.LastDialError != "" && h.LastDialAttempt.After(h.LastDialSuccess)

	if h.Info == nil {
		if h.LastAttempt.IsZero() && !dialBroken {
			// Nothing has ever asked the collector and nothing has tried
			// to connect, so there is nothing to call down.
			out.Status = "unknown"
		}
		// Either way the freshness fields stay unset: they would be
		// describing an ad that does not exist.
		return out
	}
	out.Discovered = true
	if !h.InfoAt.IsZero() {
		if age := int64(now.Sub(h.InfoAt).Seconds()); age > 0 {
			out.AdAgeSeconds = age
		}
	}
	out.Name, out.Address = h.Info.Name, h.Info.Address
	out.JobQueueCaughtUp = h.Info.JobQueueCaughtUp
	jobsStale, historyStale := dbmirror.JobQueueStaleness(h.Info), dbmirror.HistoryStaleness(h.Info)
	out.JobQueueStalenessSecs, out.HistoryStalenessSecs = &jobsStale, &historyStale
	out.HistoryGap = h.Info.HistoryGap

	// "ok" means reads are actually routing right now, which is the
	// question being asked — a mirror that is up but too far behind to
	// serve is not working, it is just running.
	//
	// A discovery that failed since the last success stays "down" even
	// though an ad is in hand: that ad is the one routing has stopped
	// trusting, and reporting the mirror healthy off it would hide the
	// error that is the actual news.
	switch {
	case h.LastError != "" && h.LastAttempt.After(h.LastSuccess):
		out.Status = "down"
	case dialBroken:
		// Discovered and fresh, but the last read could not connect to
		// it. Reporting that as "ok" off the ad alone is how a mirror
		// that has never answered a query comes to look healthy.
		out.Status = "down"
	case !h.Info.JobQueueCaughtUp,
		jobsStale > dbmirror.JobsToleranceSecs,
		h.Info.HistoryGap,
		historyStale > dbmirror.HistoryToleranceSecs:
		out.Status = "warning"
	default:
		out.Status = "ok"
	}
	return out
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
