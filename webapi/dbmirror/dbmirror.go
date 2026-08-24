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

// Options tunes which mirror is used and how hard routing tries.
//
// The zero value is the default deployment: discover whatever htcondordb
// is advertising to the pool's collector, and treat it as an optional
// accelerator. A mirror on a different host than the schedd needs no
// option at all — the collector is pool-wide, so the API daemon finds it
// wherever it runs, as long as that daemon's COLLECTOR_HOST is the
// pool's. The options exist for the cases the collector alone cannot
// settle.
type Options struct {
	// Name pins routing to the mirror advertising this Name. Set it when
	// more than one htcondordb advertises to the pool — say one syncing
	// this access point and one syncing another — because the mirror for
	// somebody else's schedd does not hold this schedd's jobs. Without
	// it, several advertisers mean the freshest is chosen, which is a
	// guess.
	Name string

	// Address overrides the sinful string to dial, for a mirror whose
	// advertised MyAddress is not reachable from this daemon (NAT, a
	// split network, an SSH tunnel). Freshness still comes from the
	// collector ad — this changes where to connect, not whether the
	// mirror is current enough to trust.
	Address string

	// Required turns routing from an optimization into a requirement: a
	// read that would have fallen back to the schedd fails instead, with
	// the reason. Use it when the whole point of the deployment is to
	// keep load off the access point — the default silently protects
	// availability at the cost of the load guarantee, and an operator
	// who wants the opposite trade cannot otherwise get it. Note that a
	// required mirror makes the API's availability depend on the
	// mirror's.
	Required bool
}

// Locator discovers the mirror through the collector and dials it. Safe
// for concurrent use; the discovered ad is cached for InfoTTL.
type Locator struct {
	collector *htcondor.Collector
	cfg       *config.Config
	opts      Options

	mu     sync.Mutex
	info   *Info
	infoAt time.Time
	// lastErr is why the most recent discovery failed, for the
	// readiness snapshot. Operators debugging "why is nothing routing"
	// need the error, and it is otherwise only visible at debug level.
	lastErr string
	lastTry time.Time
	lastOK  time.Time
}

// NewLocator returns a Locator with default options.
func NewLocator(collector *htcondor.Collector, cfg *config.Config) *Locator {
	return NewLocatorWithOptions(collector, cfg, Options{})
}

// NewLocatorWithOptions returns a Locator. Either of collector and cfg
// may be nil, in which case Enabled reports false: discovery needs the
// collector and authenticating to the mirror needs the HTCondor config's
// SEC_* knobs.
func NewLocatorWithOptions(collector *htcondor.Collector, cfg *config.Config, opts Options) *Locator {
	return &Locator{collector: collector, cfg: cfg, opts: opts}
}

// Enabled reports whether mirror routing can run at all.
func (l *Locator) Enabled() bool {
	return l != nil && l.collector != nil && l.cfg != nil
}

// Required reports whether a declined read must fail rather than fall
// back to the schedd. False for a Locator that cannot route at all —
// "required" describes routing that is on, and demanding a mirror from a
// daemon with no collector configured would break every read.
func (l *Locator) Required() bool {
	return l.Enabled() && l.opts.Required
}

// Options returns the configured targeting, for status reporting.
func (l *Locator) Options() Options {
	if l == nil {
		return Options{}
	}
	return l.opts
}

// Health is a point-in-time view of discovery, for /readyz and metrics.
// Info is nil when nothing has been discovered.
type Health struct {
	Enabled   bool
	Required  bool
	Name      string
	Address   string
	Info      *Info
	LastError string
	// LastSuccess is when discovery last found a mirror; zero if never.
	LastSuccess time.Time
}

// Health reports what discovery last saw. It never dials and never
// blocks on the collector: it is meant to be safe to call from a
// health endpoint or a metrics scrape.
func (l *Locator) Health() Health {
	if l == nil {
		return Health{}
	}
	h := Health{
		Enabled:  l.Enabled(),
		Required: l.Required(),
		Name:     l.opts.Name,
		Address:  l.opts.Address,
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	h.Info, h.LastError, h.LastSuccess = l.info, l.lastErr, l.lastOK
	return h
}

// Discover finds the mirror by querying the collector for its ad,
// reusing the last answer for InfoTTL. It errors when no collector is
// configured or nothing usable is advertising.
//
// The collector is the only source of a mirror's freshness, which is
// what every routing decision turns on, so discovery goes through it
// even when Options.Address pins where to connect.
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

	info, err := l.discover(ctx)

	l.mu.Lock()
	l.lastTry = time.Now()
	if err != nil {
		// Keep the previous ad out of the cache on failure: a stale
		// "everything is fine" would be worse than no answer, since the
		// freshness gate is the whole safety story. lastErr is kept for
		// the readiness snapshot.
		l.lastErr = err.Error()
		l.mu.Unlock()
		return nil, err
	}
	l.info, l.infoAt, l.lastErr, l.lastOK = info, time.Now(), "", time.Now()
	l.mu.Unlock()
	return info, nil
}

func (l *Locator) discover(ctx context.Context) (*Info, error) {
	constraint := ""
	if l.opts.Name != "" {
		constraint = fmt.Sprintf("Name == %s", classadStringLit(l.opts.Name))
	}
	ads, _, err := l.collector.QueryAdsWithOptions(ctx, AdType, constraint, &htcondor.QueryOptions{Limit: 64})
	if err != nil {
		return nil, fmt.Errorf("querying collector for the htcondordb ad: %w", err)
	}
	if len(ads) == 0 {
		if l.opts.Name != "" {
			return nil, fmt.Errorf("no htcondordb database named %q is advertising to the collector", l.opts.Name)
		}
		return nil, fmt.Errorf("no htcondordb database is advertising to the collector")
	}

	info := pickMirror(ads)
	if info == nil {
		return nil, fmt.Errorf("the htcondordb ad has no MyAddress; cannot connect")
	}
	if l.opts.Address != "" {
		// The operator says the advertised address is not the one to
		// dial. Everything else about the ad — freshness, gap, table
		// coverage — still describes this mirror.
		info.Address = l.opts.Address
	}
	return info, nil
}

// pickMirror chooses among the advertised mirrors. One is the normal
// case. Several means the pool runs more than one htcondordb, and
// nothing in the ad says which schedd each one mirrors, so the choice is
// a guess either way — take the freshest job queue, which is the one
// most likely to be this access point's, and let an operator who knows
// better pin it by Name. Ads with no address are skipped rather than
// chosen and failed on.
func pickMirror(ads []*classad.ClassAd) *Info {
	var best *Info
	for _, ad := range ads {
		info := ParseAd(ad)
		if info.Address == "" {
			continue
		}
		if best == nil || fresherJobQueue(info, best) {
			best = info
		}
	}
	return best
}

// fresherJobQueue reports whether a's job queue is more current than
// b's. A caught-up mirror beats one that is not, regardless of clock
// readings; among equals, the more recent sync wins.
func fresherJobQueue(a, b *Info) bool {
	if a.JobQueueCaughtUp != b.JobQueueCaughtUp {
		return a.JobQueueCaughtUp
	}
	return a.JobQueueLastSyncTime > b.JobQueueLastSyncTime
}

// classadStringLit quotes a value for use in a collector constraint.
// Escaping matters even though the input is an operator's config value:
// an unescaped quote would silently change the constraint's meaning
// rather than fail.
func classadStringLit(v string) string {
	out := make([]byte, 0, len(v)+2)
	out = append(out, '"')
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '"', '\\':
			out = append(out, '\\', c)
		case '\n':
			out = append(out, '\\', 'n')
		case '\t':
			out = append(out, '\\', 't')
		default:
			out = append(out, c)
		}
	}
	return string(append(out, '"'))
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
// Use is true only when a fresh, gap-free mirror exists AND the request
// uses no schedd-specific scan semantics the mirror cannot reproduce
// faithfully (a `since` stop-scan, a `scan_limit` budget, or a
// forward/chronological scan). Note explains the choice for the
// provenance callers surface; Reason is the stable code they label
// metrics and readiness output with.
func HistoryDecision(info *Info, opts *htcondor.HistoryQueryOptions) Decision {
	if info == nil || info.Address == "" {
		return decline(ReasonNoMirror, "no htcondordb mirror is advertising")
	}
	if info.HistoryGap {
		return decline(ReasonHistoryGap, "mirror reported a history durability gap")
	}
	if info.SecondsSinceSync > HistoryToleranceSecs {
		return decline(ReasonStale, fmt.Sprintf("mirror is stale (%ds since last sync > %ds tolerance)", info.SecondsSinceSync, HistoryToleranceSecs))
	}
	if opts != nil {
		if opts.Since != "" {
			return decline(ReasonUnsupportedQuery, "query uses a 'since' stop-scan the mirror cannot reproduce")
		}
		if opts.ScanLimit > 0 {
			return decline(ReasonUnsupportedQuery, "query sets scan_limit (a schedd scan budget)")
		}
		if !opts.Backwards {
			return decline(ReasonUnsupportedQuery, "query requests a forward scan; the mirror serves recent-first only")
		}
	}
	return serve("served from the htcondordb mirror")
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
func JobsDecision(info *Info, pageToken string, nowUnix int64) Decision {
	if info == nil || info.Address == "" {
		return decline(ReasonNoMirror, "no htcondordb mirror is advertising")
	}
	if pageToken != "" && !IsCursor(pageToken) {
		return decline(ReasonPageToken, "the page token came from the schedd, which owns the rest of that walk")
	}
	if !info.JobQueueCaughtUp {
		return decline(ReasonNotCaughtUp, "mirror's job queue is not caught up to the schedd")
	}
	if stale := JobQueueStaleness(info, nowUnix); stale > JobsToleranceSecs {
		return decline(ReasonStale, fmt.Sprintf("mirror's job queue last synced %ds ago (> %ds tolerance)", stale, JobsToleranceSecs))
	}
	if pageToken != "" {
		return serve("resumed from the htcondordb mirror's cursor")
	}
	return serve("served from the htcondordb mirror (job queue caught up)")
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
