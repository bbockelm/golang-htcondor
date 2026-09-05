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
	"net"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/cedar/security"
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
	// PollInterval is how often Poll re-discovers the mirror. It matches
	// InfoTTL, so a polled Locator asks the collector exactly as often as
	// a busy on-demand one did -- polling moves that query off the read
	// path rather than adding load.
	PollInterval = InfoTTL
	// PollTimeout bounds one poll's collector query, so a collector that
	// accepts the connection and then hangs cannot wedge the loop for the
	// life of the daemon.
	PollTimeout = 10 * time.Second

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
	HistoryGap        bool

	// History mirror freshness, as measured when the ad was BUILT.
	// SecondsSinceSync is the syncer's lag at that moment and
	// HistoryLastSyncTime is the absolute Unix time of the poll it was
	// measured against. Routing gates on the lag; see staleness for why
	// it is not recomputed against the local clock.
	HistoryLastSyncTime int64
	SecondsSinceSync    int64

	// Job-queue mirror freshness, for routing live job queries, and
	// likewise as of the ad's build time. CaughtUp means the syncer had
	// drained job_queue.log to EOF at its last poll; LastSyncTime is
	// that poll's absolute Unix time, which orders two mirrors' polls
	// against each other (see fresherJobQueue).
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
	info.HistoryLastSyncTime, _ = ad.EvaluateAttrInt("HistoryLastSyncTime")
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

	// ScheddAddress is the address of the schedd whose queue this daemon
	// serves. It is how discovery tells one access point's mirror from
	// another's when several advertise: htcondordb mirrors a schedd by
	// TAILING ITS job_queue.log, a local file, so a mirror necessarily
	// runs on its schedd's host. Matching hosts is therefore not a
	// heuristic -- a mirror on a different host is mirroring a different
	// schedd, whatever its ad says about freshness.
	//
	// It is a func because the address is not fixed: it may be discovered
	// from the collector after this Locator is built, and the address
	// updater can replace it at runtime. A snapshot taken at construction
	// would be empty or stale exactly when it matters.
	//
	// Nil, or returning "" (or a mirror advertising no usable address),
	// means discovery cannot match, and with more than one advertiser it
	// declines rather than guessing; see pickMirror.
	ScheddAddress func() string

	// Required turns routing from an optimization into a requirement: a
	// read that would have fallen back to the schedd fails instead, with
	// the reason. Use it when the whole point of the deployment is to
	// keep load off the access point — the default silently protects
	// availability at the cost of the load guarantee, and an operator
	// who wants the opposite trade cannot otherwise get it. Note that a
	// required mirror makes the API's availability depend on the
	// mirror's.
	Required bool

	// TokenSource mints an IDTOKEN for authenticating to the mirror, or
	// returns an error when it cannot.
	//
	// Without one, the connection can only offer whatever the ambient
	// SEC_CLIENT_AUTHENTICATION_METHODS provide, and on a containerised
	// access point that is usually nothing that works: FS needs a shared
	// filesystem and uid, Kerberos needs a ccache, and SSL needs a
	// certificate the mirror's has not outlived. htcondordb's session
	// command wants READ, so a token asserting READ is sufficient and is
	// the method least coupled to how the two are deployed.
	//
	// Optional. Nil keeps the previous behaviour exactly.
	TokenSource func(ctx context.Context) (string, error)
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
	// tokenErr is why no IDTOKEN was attached to the last connection
	// attempt, empty when one was.
	tokenErr string
	// lastDialErr is why the most recent attempt to CONNECT to the mirror
	// failed, which is a different failure from discovery and was
	// previously visible only as a metric label. An operator looking at a
	// dial_failed tally had the count and nothing else -- not the
	// address, not the error -- while lastErr next to it described
	// discovery, which was working fine.
	lastDialErr string
	lastDialAt  time.Time
	lastDialOK  time.Time
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
	// LastAttempt is when the collector was last asked, zero if it never
	// has been. On a daemon running Poll this is never more than
	// PollInterval old; without Poll, discovery only happens on a read
	// that wants to route, so an idle one leaves it zero and every other
	// field here describes nothing that was ever checked.
	//
	// It exists because "no mirror is advertising" and "nobody has
	// looked" are the same absence otherwise, and the second is the
	// common case while an operator is setting the integration up. A
	// Discover answered from the InfoTTL cache does not count as an
	// attempt -- nothing was asked of the collector.
	LastAttempt time.Time
	// InfoAt is when the cached ad in Info was discovered; zero if none.
	// Info is kept across a failed attempt, so an ad older than InfoTTL
	// is one routing would no longer use without re-discovering.
	InfoAt time.Time

	// LastDialError is why the most recent connection to the mirror
	// failed, with LastDialAttempt when that was and LastDialSuccess when
	// one last worked. Discovery and dialing fail independently -- the
	// collector can hand back a perfectly good ad for a database this
	// daemon cannot authenticate to -- so a healthy discovery says
	// nothing about whether reads are reaching it.
	LastDialError   string
	LastDialAttempt time.Time
	LastDialSuccess time.Time
	// TokenError is why no IDTOKEN was offered on the last connection
	// attempt, empty when one was. Worth reporting on its own because a
	// dial error listing FS, Kerberos and SSL reads as "everything was
	// tried", when the method most likely to work was skipped before it
	// started.
	TokenError string
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
	h.TokenError = l.tokenErr
	h.LastAttempt, h.InfoAt = l.lastTry, l.infoAt
	h.LastDialError, h.LastDialAttempt, h.LastDialSuccess = l.lastDialErr, l.lastDialAt, l.lastDialOK
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

	return l.refresh(ctx)
}

// refresh queries the collector unconditionally, bypassing the InfoTTL
// cache, and records the outcome. Discover uses it on a cache miss and
// Poll on every tick -- a poll that could be answered from the cache
// would defeat the point, since the cache is what it exists to refill.
func (l *Locator) refresh(ctx context.Context) (*Info, error) {
	info, err := l.discover(ctx)

	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastTry = time.Now()
	if err != nil {
		// Keep the previous ad out of the cache on failure: a stale
		// "everything is fine" would be worse than no answer, since the
		// freshness gate is the whole safety story. lastErr is kept for
		// the readiness snapshot.
		l.lastErr = err.Error()
		return nil, err
	}
	l.info, l.infoAt, l.lastErr, l.lastOK = info, time.Now(), "", time.Now()
	return info, nil
}

// Poll re-discovers the mirror on a timer until ctx is done. It is meant
// to be run in a goroutine for the life of the daemon, and returns
// immediately when routing is not configured.
//
// Discovery is otherwise lazy -- it happens on a read that wants to
// route -- which has two costs. The first read after startup pays the
// collector round trip and, worse, an idle daemon knows nothing at all:
// its status page cannot say whether the mirror is reachable, because
// nothing ever asked, and "never looked" is indistinguishable from
// "looked and failed". Polling makes the answer continuously true
// instead of a side effect of traffic, and gives the operator a "last
// checked" that means something.
//
// onResult, if non-nil, is called with the outcome of every poll -- the
// discovered ad, or the error. It is how a caller logs transitions; this
// package deliberately does no logging of its own, since it has no
// opinion about which of a daemon's log destinations this belongs to.
func (l *Locator) Poll(ctx context.Context, onResult func(*Info, error)) {
	if !l.Enabled() {
		return
	}
	// Poll once up front: a daemon that just started should know where
	// the mirror is before the first request arrives, not one interval
	// later.
	l.pollOnce(ctx, onResult)

	ticker := time.NewTicker(PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.pollOnce(ctx, onResult)
		}
	}
}

func (l *Locator) pollOnce(ctx context.Context, onResult func(*Info, error)) {
	ctx, cancel := context.WithTimeout(ctx, PollTimeout)
	defer cancel()
	info, err := l.refresh(ctx)
	if onResult != nil {
		onResult(info, err)
	}
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

	var scheddHost string
	if l.opts.ScheddAddress != nil {
		scheddHost = hostOfSinful(l.opts.ScheddAddress())
	}
	info, err := pickMirror(ads, scheddHost)
	if err != nil {
		return nil, err
	}
	if l.opts.Address != "" {
		// The operator says the advertised address is not the one to
		// dial. Everything else about the ad — freshness, gap, table
		// coverage — still describes this mirror.
		info.Address = l.opts.Address
	}
	return info, nil
}

// pickMirror chooses among the advertised mirrors, or returns nil with a
// reason when it cannot choose safely.
//
// One advertiser is the normal case and is taken as-is. Several means the
// pool runs more than one htcondordb, and picking the wrong one does not
// return stale data -- it returns SOMEBODY ELSE'S JOBS, from another
// access point's queue, to a caller who may not be entitled to see them.
// So the tie is broken on the one thing that actually identifies a
// mirror's schedd: the host it runs on, because syncing a schedd means
// tailing its job_queue.log off local disk.
//
// When the host cannot settle it, this declines. The previous rule --
// take the freshest job queue -- was a guess, and a bad one in a
// specific way: it ranked "caught up" above "recently synced", so a
// mirror whose syncer had stopped while caught up outranked a live one
// that was momentarily behind. A busy queue on this access point made
// its own mirror look worse and handed the read to a stranger's.
func pickMirror(ads []*classad.ClassAd, scheddHost string) (*Info, error) {
	var usable []*Info
	for _, ad := range ads {
		if info := ParseAd(ad); info.Address != "" {
			usable = append(usable, info)
		}
	}
	switch len(usable) {
	case 0:
		return nil, fmt.Errorf("the htcondordb ad has no MyAddress; cannot connect")
	case 1:
		return usable[0], nil
	}

	var matched []*Info
	for _, info := range usable {
		if scheddHost != "" && hostOfSinful(info.Address) == scheddHost {
			matched = append(matched, info)
		}
	}
	switch len(matched) {
	case 1:
		return matched[0], nil
	case 0:
		return nil, fmt.Errorf("%d htcondordb databases are advertising and none runs on this schedd's host (%q); "+
			"set HTTP_API_DBMIRROR_NAME to say which one mirrors this access point, because the others hold a different queue",
			len(usable), scheddHost)
	default:
		return nil, fmt.Errorf("%d htcondordb databases are advertising on this schedd's host (%q); "+
			"set HTTP_API_DBMIRROR_NAME to say which one mirrors this access point", len(matched), scheddHost)
	}
}

// hostOfSinful extracts the host from a sinful string such as
// "<10.0.0.1:9619?alias=ap40&sock=x>". Returns "" when there is none to
// compare, which never matches.
func hostOfSinful(addr string) string {
	s := strings.TrimPrefix(strings.TrimSpace(addr), "<")
	s = strings.TrimSuffix(s, ">")
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
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
	sec, err := l.securityConfig(ctx, info.Address)
	if err != nil {
		return nil, nil, nil, err
	}
	cl, err := htcondor.DialSinful(ctx, info.Address, sec, nil)
	if err != nil {
		err = fmt.Errorf("connecting to htcondordb at %s: %w", info.Address, err)
		l.recordDial(err)
		return nil, nil, nil, err
	}
	l.recordDial(nil)
	return dbrpc.NewClient(dbrpc.NewCedarConn(ctx, cl.GetStream())), func() { _ = cl.Close() }, info, nil
}

// RecordDialForTest records a connection outcome without dialing, so a
// test can exercise the reporting path. Not for production use: Client
// records the real thing.
func (l *Locator) RecordDialForTest(err error) { l.recordDial(err) }

// recordDial keeps the outcome of the last connection attempt for the
// readiness and admin surfaces.
func (l *Locator) recordDial(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastDialAt = time.Now()
	if err != nil {
		l.lastDialErr = err.Error()
		return
	}
	l.lastDialErr, l.lastDialOK = "", l.lastDialAt
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
	if stale := HistoryStaleness(info); stale > HistoryToleranceSecs {
		return decline(ReasonStale, fmt.Sprintf("mirror is stale (%ds since last sync > %ds tolerance)", stale, HistoryToleranceSecs))
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

// JobQueueStaleness is how far the mirror's job queue was behind the
// schedd when it last advertised. See staleness.
func JobQueueStaleness(info *Info) int64 {
	if info == nil {
		return 0
	}
	return staleness(info.JobQueueSecondsSync)
}

// HistoryStaleness is how far the mirror's history was behind when it
// last advertised. See staleness.
func HistoryStaleness(info *Info) int64 {
	if info == nil {
		return 0
	}
	return staleness(info.SecondsSinceSync)
}

// staleness is the lag the mirror measured on itself at the moment it
// built the ad, which is what every routing decision gates on.
//
// The tempting alternative -- now minus the advertised LastSyncTime --
// is wrong, and wrong in a way that quietly disables routing. It adds
// the AD's age to the MIRROR's lag, and those are different quantities:
// a mirror re-advertises on the collector's update interval (five
// minutes in a stock pool) while its syncer polls continuously, so an
// ad built when the syncer was 5s behind still reports a 5s lag four
// minutes later even though the syncer has run many times since. The
// local clock cannot see those runs. Recomputing against it would make
// a perfectly current mirror read as minutes stale for most of every
// advertise window, and the 60s job-queue tolerance would then decline
// essentially every live query.
//
// What that leaves uncovered is a mirror whose syncer stalls between
// ads. That shows up on the next advertisement, when the mirror measures
// its own now-larger lag -- so the gate closes an update interval later
// rather than immediately. How old the information is, is a separate
// question with a separate answer: the age of the ad, which callers
// report alongside the lag rather than folded into it.
//
// A negative lag (an older mirror, or a bug) clamps to 0 rather than
// passing through, since a negative would sail through every tolerance
// check.
func staleness(adTimeLagSecs int64) int64 {
	if adTimeLagSecs < 0 {
		return 0
	}
	return adTimeLagSecs
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
func JobsDecision(info *Info, pageToken string) Decision {
	if info == nil || info.Address == "" {
		return decline(ReasonNoMirror, "no htcondordb mirror is advertising")
	}
	if pageToken != "" && !IsCursor(pageToken) {
		return decline(ReasonPageToken, "the page token came from the schedd, which owns the rest of that walk")
	}
	if !info.JobQueueCaughtUp {
		return decline(ReasonNotCaughtUp, "mirror's job queue is not caught up to the schedd")
	}
	if stale := JobQueueStaleness(info); stale > JobsToleranceSecs {
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
	if s := HistoryStaleness(info); s > 0 {
		note += fmt.Sprintf("; synced %ds ago", s)
	}
	if reason != "" {
		note += "; " + reason
	}
	return note + "]"
}

// securityConfig builds the security config for a mirror connection,
// attaching an IDTOKEN when a TokenSource is configured.
//
// A token source that fails is not fatal. The connection still gets the
// ambient methods and may well succeed on a deployment where FS or SSL
// works; failing here instead would take away a path that used to work.
// The error is returned to the caller's log rather than swallowed, so a
// misconfigured signing key is visible rather than silently reducing the
// mirror to whatever else it can negotiate.
func (l *Locator) securityConfig(ctx context.Context, address string) (*security.SecurityConfig, error) {
	l.mu.Lock()
	tokenSource := l.opts.TokenSource
	l.mu.Unlock()

	if tokenSource != nil {
		token, err := tokenSource(ctx)
		if err == nil && token != "" {
			sec, cerr := htcondor.NewClientSecurityConfig(ctx, token, address, SessionCommand, "CLIENT", nil)
			if cerr != nil {
				return nil, fmt.Errorf("building htcondordb security config with a token: %w", cerr)
			}
			sec.Command = SessionCommand
			return sec, nil
		}
		l.noteTokenFailure(err)
	}

	sec, err := htcondor.GetSecurityConfig(l.cfg, SessionCommand, "CLIENT")
	if err != nil {
		return nil, fmt.Errorf("building htcondordb security config: %w", err)
	}
	sec.Command = SessionCommand
	return sec, nil
}

// noteTokenFailure records why no token was attached, so Health can say
// so. A connection that then fails every other method otherwise reports
// "all authentication methods failed" without mentioning that the one
// most likely to work was never offered.
func (l *Locator) noteTokenFailure(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.tokenErr = err.Error()
		return
	}
	l.tokenErr = "the token source returned an empty token"
}

// SetTokenSource attaches (or replaces) the mirror's token source after
// construction.
//
// It exists because the daemon that can mint a token is built after the
// Locator it owns: the signing key lives on the handler, and the handler
// literal contains the Locator. Setting it later avoids threading the
// key through construction for one optional field.
//
// Safe to call before the Locator is used; it takes the same lock every
// other mutation does.
func (l *Locator) SetTokenSource(f func(ctx context.Context) (string, error)) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.opts.TokenSource = f
}
