// Package dbmirror locates a synchronized htcondordb mirror and decides
// when a query may be served from it instead of the schedd.
//
// The point is load: condor_history scans the schedd's on-disk history
// file and competes directly with scheduling and negotiation, and a
// broad live-job query costs the schedd a queue walk. When a mirror is
// advertising and demonstrably current, serving those reads from it
// takes the load off the access point.
//
// Routing is always best-effort with a transparent fallback. Every
// decision here answers "may we?", never "must we?": any miss — no
// mirror, stale mirror, durability gap, dial or query error — means the
// caller uses the schedd, so a query never fails because the mirror is
// behind. The freshness policy lives in one place so the MCP tools and
// the REST API cannot drift apart on it.
package dbmirror

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// SessionCommand is htcondordb's DBSession CEDAR command
// (github.com/bbockelm/htcondordb/command.DBSession = 74000). It is
// duplicated here so webapi need not depend on the htcondordb module,
// matching how htcondordb/kafkasync duplicates it.
const SessionCommand = 74000

// AdType is the MyType an htcondordb daemon advertises to the collector.
const AdType = "HTCondorDB"

const (
	// DefaultLimit is the row cap applied when a caller asks for none.
	DefaultLimit = 200
	// MaxLimit is the ceiling on any single mirror read. A mirror read
	// is unpaginated, so this is what keeps one request from pulling an
	// unbounded result set into memory.
	MaxLimit = 2000
	// InfoTTL is how long a discovered mirror ad is reused before the
	// collector is asked again.
	InfoTTL = 30 * time.Second

	// HistoryToleranceSecs is the maximum mirror staleness at which
	// completed-job reads still prefer the mirror. History is
	// append-only, so minutes of lag are harmless; beyond this the
	// authoritative schedd is used instead.
	HistoryToleranceSecs int64 = 300

	// JobsToleranceSecs is the maximum job-queue mirror staleness at
	// which live job queries prefer the mirror. Much tighter than
	// history: job state (idle/running/held) is latency-sensitive, so
	// the mirror answers only when its job_queue.log tail is
	// essentially current.
	JobsToleranceSecs int64 = 60
)

// Info is a discovered mirror's location, capabilities and freshness,
// parsed from its collector advertisement.
type Info struct {
	Name              string
	Address           string
	TimeTravelEnabled bool
	SecondsSinceSync  int64
	HistoryGap        bool

	// Job-queue mirror freshness, for routing live job queries.
	// CaughtUp means the syncer had drained job_queue.log to EOF at its
	// last poll; LastSyncTime is that poll's absolute Unix time, so the
	// CURRENT staleness can be computed as now-LastSyncTime independent
	// of how old the collector ad is.
	JobQueueCaughtUp     bool
	JobQueueLastSyncTime int64
	JobQueueSecondsSync  int64
}

// ParseAd reads a mirror's collector advertisement.
func ParseAd(ad *classad.ClassAd) *Info {
	info := &Info{}
	info.Name, _ = ad.EvaluateAttrString("Name")
	info.Address, _ = ad.EvaluateAttrString("MyAddress")
	info.TimeTravelEnabled, _ = ad.EvaluateAttrBool("TimeTravelEnabled")
	info.HistoryGap, _ = ad.EvaluateAttrBool("HistoryGapDetected")
	info.SecondsSinceSync, _ = ad.EvaluateAttrInt("HistorySecondsSinceSync")
	info.JobQueueCaughtUp, _ = ad.EvaluateAttrBool("JobQueueCaughtUp")
	info.JobQueueLastSyncTime, _ = ad.EvaluateAttrInt("JobQueueLastSyncTime")
	info.JobQueueSecondsSync, _ = ad.EvaluateAttrInt("JobQueueSecondsSinceSync")
	return info
}

// Locator discovers the mirror through the collector and dials it. Safe
// for concurrent use; the discovered ad is cached for InfoTTL.
type Locator struct {
	collector *htcondor.Collector
	cfg       *config.Config

	mu     sync.Mutex
	info   *Info
	infoAt time.Time
}

// NewLocator returns a Locator. Either argument may be nil, in which
// case Enabled reports false: discovery needs the collector and
// authenticating to the mirror needs the HTCondor config's SEC_* knobs.
func NewLocator(collector *htcondor.Collector, cfg *config.Config) *Locator {
	return &Locator{collector: collector, cfg: cfg}
}

// Enabled reports whether mirror routing can run at all.
func (l *Locator) Enabled() bool {
	return l != nil && l.collector != nil && l.cfg != nil
}

// Discover finds the mirror by querying the collector for its ad,
// reusing the last answer for InfoTTL. It errors when no collector is
// configured or nothing is advertising.
func (l *Locator) Discover(ctx context.Context) (*Info, error) {
	if l == nil || l.collector == nil {
		return nil, fmt.Errorf("no collector configured for htcondordb discovery")
	}
	l.mu.Lock()
	if l.info != nil && time.Since(l.infoAt) < InfoTTL {
		info := l.info
		l.mu.Unlock()
		return info, nil
	}
	l.mu.Unlock()

	ads, _, err := l.collector.QueryAdsWithOptions(ctx, AdType, "", &htcondor.QueryOptions{Limit: 64})
	if err != nil {
		return nil, fmt.Errorf("querying collector for the htcondordb ad: %w", err)
	}
	if len(ads) == 0 {
		return nil, fmt.Errorf("no htcondordb database is advertising to the collector")
	}
	info := ParseAd(ads[0])
	if info.Address == "" {
		return nil, fmt.Errorf("the htcondordb ad has no MyAddress; cannot connect")
	}

	l.mu.Lock()
	l.info, l.infoAt = info, time.Now()
	l.mu.Unlock()
	return info, nil
}

// Client dials the discovered mirror over an authenticated DBSession and
// returns a dbrpc client, a closer the caller must invoke, and the
// discovered info (for freshness annotation).
func (l *Locator) Client(ctx context.Context) (*dbrpc.Client, func(), *Info, error) {
	info, err := l.Discover(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if l.cfg == nil {
		return nil, nil, nil, fmt.Errorf("no HTCondor config for htcondordb authentication")
	}
	sec, err := htcondor.GetSecurityConfig(l.cfg, SessionCommand, "CLIENT")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("building htcondordb security config: %w", err)
	}
	sec.Command = SessionCommand
	cl, err := htcondor.DialSinful(ctx, info.Address, sec, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connecting to htcondordb at %s: %w", info.Address, err)
	}
	return dbrpc.NewClient(dbrpc.NewCedarConn(ctx, cl.GetStream())), func() { _ = cl.Close() }, info, nil
}

// HistoryDecision decides whether a completed-job query may be served
// from the mirror. Pure, so the policy is unit-tested without I/O.
// useDB is true only when a fresh, gap-free mirror exists AND the
// request uses no schedd-specific scan semantics the mirror cannot
// reproduce faithfully (a `since` stop-scan, a `scan_limit` budget, or a
// forward/chronological scan). reason explains the choice for the
// provenance note callers surface.
func HistoryDecision(info *Info, opts *htcondor.HistoryQueryOptions) (useDB bool, reason string) {
	if info == nil || info.Address == "" {
		return false, "no htcondordb mirror is advertising"
	}
	if info.HistoryGap {
		return false, "mirror reported a history durability gap"
	}
	if info.SecondsSinceSync > HistoryToleranceSecs {
		return false, fmt.Sprintf("mirror is stale (%ds since last sync > %ds tolerance)", info.SecondsSinceSync, HistoryToleranceSecs)
	}
	if opts != nil {
		if opts.Since != "" {
			return false, "query uses a 'since' stop-scan the mirror cannot reproduce"
		}
		if opts.ScanLimit > 0 {
			return false, "query sets scan_limit (a schedd scan budget)"
		}
		if !opts.Backwards {
			return false, "query requests a forward scan; the mirror serves recent-first only"
		}
	}
	return true, "served from the htcondordb mirror"
}

// JobQueueStaleness is the mirror's CURRENT job-queue staleness in
// seconds. It uses the absolute last-sync stamp when advertised
// (now-LastSyncTime, correct regardless of how old the collector ad is)
// and falls back to the ad's frozen SecondsSinceSync only when the
// absolute stamp is missing.
func JobQueueStaleness(info *Info, nowUnix int64) int64 {
	if info.JobQueueLastSyncTime > 0 {
		if d := nowUnix - info.JobQueueLastSyncTime; d >= 0 {
			return d
		}
		return 0
	}
	return info.JobQueueSecondsSync
}

// JobsDecision decides whether a live job query may be served from the
// mirror's "jobs" table (the mirrored job_queue.log). Pure. It requires
// a caught-up mirror whose current staleness is within tolerance.
//
// Pagination is a reason to PREFER the mirror, not to decline it. The
// mirror resumes an ordered scan from a cursor that names a snapshot, so
// page two reads the queue as page one saw it, and the walk costs a
// resume rather than another pass over the whole queue — which is the
// part a busy schedd feels. The one thing that cannot work is
// continuing a SCHEDD-issued token here: the two cursors mean different
// things, so a caller holding one stays where it started (see
// EncodeCursor).
func JobsDecision(info *Info, pageToken string, nowUnix int64) (useDB bool, reason string) {
	if info == nil || info.Address == "" {
		return false, "no htcondordb mirror is advertising"
	}
	if pageToken != "" && !IsCursor(pageToken) {
		return false, "the page token came from the schedd, which owns the rest of that walk"
	}
	if !info.JobQueueCaughtUp {
		return false, "mirror's job queue is not caught up to the schedd"
	}
	if stale := JobQueueStaleness(info, nowUnix); stale > JobsToleranceSecs {
		return false, fmt.Sprintf("mirror's job queue last synced %ds ago (> %ds tolerance)", stale, JobsToleranceSecs)
	}
	if pageToken != "" {
		return true, "resumed from the htcondordb mirror's cursor"
	}
	return true, "served from the htcondordb mirror (job queue caught up)"
}

// RecencyKey ranks a completed-job ad for reverse-chronological
// ordering: the last status transition, falling back to the completion
// time. Both are Unix seconds on a job ad; 0 sorts oldest.
func RecencyKey(ad *classad.ClassAd) int64 {
	if v, ok := ad.EvaluateAttrInt("EnteredCurrentStatus"); ok && v > 0 {
		return v
	}
	v, _ := ad.EvaluateAttrInt("CompletionDate")
	return v
}

// ClampLimit bounds a caller-supplied row limit for a mirror read:
// non-positive means "unspecified" (DefaultLimit), and anything above
// MaxLimit is clamped.
func ClampLimit(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	if n > MaxLimit {
		return MaxLimit
	}
	return n
}

// Provenance renders the trailing "[source: ...]" note callers append to
// a mirror-served response, so every surface words it the same way.
func Provenance(info *Info, reason string) string {
	note := "[source: htcondordb mirror"
	if info != nil && info.Name != "" {
		note += fmt.Sprintf(" %q", info.Name)
	}
	if info != nil && info.SecondsSinceSync > 0 {
		note += fmt.Sprintf("; synced %ds ago", info.SecondsSinceSync)
	}
	if reason != "" {
		note += "; " + reason
	}
	return note + "]"
}
