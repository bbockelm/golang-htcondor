// Package multiap serves read-only job queries for a multi-AP
// htcondor-api: one API server in front of every access point whose
// schedd ad matches HTTP_API_SCHEDD_CONSTRAINT.
//
// Unscoped reads come from a federation hub -- an htcondordb that fans
// every AP's per-AP mirror (spoke) into one catalog -- and every response
// carries a sources block saying which APs' rows are fresh. A read
// scoped to one job falls back, when that AP's hub copy is not fresh, to
// the AP's own spoke and then to its schedd.
//
// The hub's data contract (htcondordb federate/): tables jobs (mutable),
// history (archive) and federation_sources (one row per schedd). Every
// replicated row carries ScheddName, set by the hub from the source's
// validated identity. Hub storage keys are opaque and never parsed here;
// rows are selected on ScheddName, ClusterId and ProcId.
package multiap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"
)

// Hub table and attribute names, from the hub's contract.
const (
	TableJobs         = "jobs"
	TableHistory      = "history"
	TableEpochHistory = "epoch_history"
	TableSources      = "federation_sources"

	AttrScheddName = "ScheddName"
)

// Source states the hub reports in federation_sources.State.
const (
	StateFresh     = "fresh"
	StateStale     = "stale"
	StateAbsent    = "absent"
	StateUntrusted = "untrusted"
	StateRetiring  = "retiring"
	// StateSettling is this server's, not the hub's: the AP is fresh on
	// a hub that became active less than the settle window ago.
	StateSettling = "settling"
)

// DefaultSourcesInterval is how often the hub's federation_sources table
// is re-read. A source's state changes on the hub's own 5 s cadence.
const DefaultSourcesInterval = 5 * time.Second

// Source is one federation_sources row.
type Source struct {
	Schedd string
	State  string
	Reason string
	// Staleness is the hub's bound on how far its copy of this AP is
	// behind the AP's schedd. StalenessKnown is false when the hub could
	// not measure it (no heartbeat yet), which it reports as stale.
	Staleness      int64
	StalenessKnown bool
	LastSeen       time.Time
	LastReset      time.Time
	SpokeAddress   string
	// JobsConnected and JobsLastError describe the hub's jobs stream
	// from this source.
	JobsConnected bool
	JobsLastError string
	// Tables is the spoke tables the hub federates, as the row lists
	// them: a <Table>Connected attribute per federated table.
	Tables map[string]bool
	// TableStatus is each federated table's stream from this source.
	TableStatus map[string]TableStatus
}

// TableStatus is the hub's stream of one table from one source, from
// the <Table>Connected, <Table>LastError, <Table>Synced and
// <Table>SyncedAt attributes of its federation_sources row.
type TableStatus struct {
	Connected bool
	LastError string
	// SyncedKnown says the hub publishes <Table>Synced (htcondordb with
	// per-table catch-up state); older hubs do not. Synced is then
	// whether the stream has finished its current catch-up -- until it
	// has, a row missing from the table may simply not have been
	// replayed yet -- and SyncedAt when it last did.
	SyncedKnown bool
	Synced      bool
	SyncedAt    time.Time
	// Missing is <Table>Missing: the source keeps no such table (a spoke
	// without HTCONDORDB_JOB_METRICS, say), so it has no rows to send.
	// That is a fact about the AP, not a fault in the stream.
	Missing bool
}

// Usable reports whether the stream is connected with no error since
// its last clean session.
func (t TableStatus) Usable() bool { return t.Connected && t.LastError == "" }

// sourceTablePrefixes are the federation_sources attribute prefixes of
// the tables a hub may federate (htcondordb federate tablePrefix).
var sourceTablePrefixes = map[string]string{
	TableJobs:         "Jobs",
	TableHistory:      "History",
	TableEpochHistory: "EpochHistory",
	TableJobMetrics:   "JobMetrics",
	"syncstatus":      "SyncStatus",
}

// ParseSource reads a federation_sources row. ok is false for a row
// with no ScheddName.
func ParseSource(ad *classad.ClassAd) (Source, bool) {
	var s Source
	s.Schedd, _ = ad.EvaluateAttrString(AttrScheddName)
	if s.Schedd == "" {
		return s, false
	}
	s.State, _ = ad.EvaluateAttrString("State")
	s.Reason, _ = ad.EvaluateAttrString("Reason")
	s.Staleness, s.StalenessKnown = ad.EvaluateAttrInt("StalenessSeconds")
	if v, ok := ad.EvaluateAttrInt("LastSeen"); ok && v > 0 {
		s.LastSeen = time.Unix(v, 0).UTC()
	}
	if v, ok := ad.EvaluateAttrInt("LastReset"); ok && v > 0 {
		s.LastReset = time.Unix(v, 0).UTC()
	}
	s.SpokeAddress, _ = ad.EvaluateAttrString("SpokeAddress")
	s.JobsConnected, _ = ad.EvaluateAttrBool("JobsConnected")
	s.JobsLastError, _ = ad.EvaluateAttrString("JobsLastError")
	s.Tables = map[string]bool{}
	s.TableStatus = map[string]TableStatus{}
	for table, prefix := range sourceTablePrefixes {
		if _, ok := ad.Lookup(prefix + "Connected"); !ok {
			continue
		}
		s.Tables[table] = true
		var ts TableStatus
		ts.Connected, _ = ad.EvaluateAttrBool(prefix + "Connected")
		ts.LastError, _ = ad.EvaluateAttrString(prefix + "LastError")
		if _, ok := ad.Lookup(prefix + "Synced"); ok {
			ts.SyncedKnown = true
			ts.Synced, _ = ad.EvaluateAttrBool(prefix + "Synced")
		}
		ts.Missing, _ = ad.EvaluateAttrBool(prefix + "Missing")
		if v, ok := ad.EvaluateAttrInt(prefix + "SyncedAt"); ok && v > 0 {
			ts.SyncedAt = time.Unix(v, 0).UTC()
		}
		s.TableStatus[table] = ts
	}
	if s.State == "" {
		// A row the hub wrote without a state says nothing about
		// freshness, so it is not fresh.
		s.State = StateStale
	}
	return s, true
}

// Dialer opens a dbrpc session to a database. The caller invokes the
// returned closer.
type Dialer func(ctx context.Context) (*dbrpc.Client, func(), error)

// HubEndpoint is one federation hub: how to dial it, and the latest
// federation_sources snapshot read from it. A Hub holds one per hub it
// knows (see hubset.go); everything a read learns about freshness comes
// from the endpoint the read is pinned to, never from another.
type HubEndpoint struct {
	owner *Hub
	name  string
	dial  Dialer

	mu          sync.RWMutex
	address     string
	sources     map[string]Source // keyed by lower-cased schedd name
	sourcesAt   time.Time
	lastAttempt time.Time
	lastErr     string
	// failures counts federation_sources reads that failed in a row.
	failures int
	// readFailures counts reads of the hub's data (jobs, history, ...)
	// that failed in a row on the transport -- a dial, a dropped
	// connection, a timeout -- not on the query. A hub can answer its
	// small sources table and still fail every real read.
	readFailures int
	lastReadErr  string
}

// Name is the hub's collector ad Name; empty for a hub given only as a
// dialer.
func (e *HubEndpoint) Name() string {
	if e == nil {
		return ""
	}
	return e.name
}

func (e *HubEndpoint) clock() time.Time { return e.owner.clock() }

// Client dials the hub for a data read. A failed dial counts toward
// failover (NoteRead).
func (e *HubEndpoint) Client(ctx context.Context) (*dbrpc.Client, func(), error) {
	c, closer, err := e.connect(ctx)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(ctx.Err(), context.Canceled) {
		// Whatever stopped the dial -- refused, unreachable, the hub's
		// ad gone, authentication -- the hub cannot be read.
		e.noteReadFailure(err)
	}
	return c, closer, err
}

// NoteRead records the outcome of a data read on this hub. A transport
// failure -- the connection failed or dropped, or the read timed out --
// counts toward FailAfter, and on the active hub brings the next
// selection forward; a success clears the count. A query the server
// refused (a bad constraint, an unknown table) and a caller that went
// away say nothing about the hub, and are not counted.
func (e *HubEndpoint) NoteRead(ctx context.Context, err error) {
	if e == nil {
		return
	}
	switch {
	case err == nil:
		e.mu.Lock()
		e.readFailures, e.lastReadErr = 0, ""
		e.mu.Unlock()
		return
	case !transportFailure(ctx, err):
		return
	}
	e.noteReadFailure(err)
}

func (e *HubEndpoint) noteReadFailure(err error) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.readFailures++
	e.lastReadErr = err.Error()
	e.mu.Unlock()
	if e.owner.Active() == e {
		e.owner.kickRefresh()
	}
}

// transportFailure reports whether err, from a query made with ctx,
// says the hub dropped the connection or did not answer in time -- not
// that it refused the query, or that the caller went away.
func transportFailure(ctx context.Context, err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return false
	}
	var ne net.Error
	return errors.Is(err, dbrpc.ErrConnClosed) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) || errors.As(err, &ne)
}

func (e *HubEndpoint) connect(ctx context.Context) (*dbrpc.Client, func(), error) {
	if e == nil || e.dial == nil {
		return nil, nil, fmt.Errorf("no federation hub is configured")
	}
	return e.dial(ctx)
}

// refresh re-reads federation_sources. On error the previous snapshot is
// kept, and its age says how old it is.
func (e *HubEndpoint) refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Taken before the read: the rows describe the hub no later than
	// this, which is the direction of error that only delays a verdict.
	now := e.clock()
	sources, err := e.readSources(ctx)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastAttempt = now
	if err != nil {
		e.lastErr = err.Error()
		e.failures++
		return err
	}
	e.sources, e.sourcesAt, e.lastErr, e.failures = sources, now, "", 0
	return nil
}

func (e *HubEndpoint) readSources(ctx context.Context) (map[string]Source, error) {
	dbc, closer, err := e.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer closer()
	out := map[string]Source{}
	var perr error
	err = dbc.QueryRawTableStream(ctx, TableSources, "true", 0, func(row string) bool {
		ad, e := classad.ParseOld(row)
		if e != nil {
			perr = fmt.Errorf("unparseable %s row: %w", TableSources, e)
			return false
		}
		if s, ok := ParseSource(ad); ok {
			out[strings.ToLower(s.Schedd)] = s
		}
		return true
	})
	if err == nil {
		err = perr
	}
	if err != nil {
		return nil, fmt.Errorf("reading the hub's %s: %w", TableSources, err)
	}
	return out, nil
}

// HubStatus is a hub's reachability, for /readyz and /api/v1/aps.
type HubStatus struct {
	// Name and Address identify the hub: its collector ad Name and the
	// address last dialed. Both are empty for a hub given only as a
	// dialer.
	Name    string
	Address string
	// Active is whether reads are served from this hub now.
	Active bool
	// Reachable is whether the last federation_sources read succeeded
	// within three refresh intervals.
	Reachable   bool
	LastSuccess time.Time
	LastAttempt time.Time
	LastError   string
	// Failures is how many federation_sources reads have failed in a
	// row; ReadFailures how many data reads failed in a row on the
	// transport, and LastReadError why the last one did.
	Failures      int
	ReadFailures  int
	LastReadError string
	Sources       int
	// FreshAPs is how many access points in the AP set the hub reports
	// fresh, the measure hub selection ranks on.
	FreshAPs int
}

// Status reports the hub's reachability.
func (e *HubEndpoint) Status() HubStatus {
	if e == nil {
		return HubStatus{LastError: "no federation hub is configured"}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	st := HubStatus{Name: e.name, Address: e.address, LastSuccess: e.sourcesAt, LastAttempt: e.lastAttempt,
		LastError: e.lastErr, Failures: e.failures, ReadFailures: e.readFailures, LastReadError: e.lastReadErr,
		Sources: len(e.sources)}
	st.Reachable = e.reachableLocked()
	st.FreshAPs = e.freshLocked(e.owner.isMember)
	return st
}

func (e *HubEndpoint) reachableLocked() bool {
	return !e.sourcesAt.IsZero() && e.clock().Sub(e.sourcesAt) <= 3*e.owner.interval+10*time.Second
}

// freshLocked counts the sources the hub reports fresh, with their jobs
// caught up, among those member accepts: JobsSynced where the hub
// publishes it, else no Reset within resetSettle (the rule the watch
// evaluator applies to an older hub) -- a hub replaying an AP from
// scratch reports it fresh while its rows are still arriving, and must
// not rank as holding it.
func (e *HubEndpoint) freshLocked(member func(string) bool) int {
	n := 0
	for _, s := range e.sources {
		if s.State != StateFresh || !member(s.Schedd) {
			continue
		}
		jobs := s.TableStatus[TableJobs]
		switch {
		case jobs.SyncedKnown && !jobs.Synced:
			continue
		case !jobs.SyncedKnown && !s.LastReset.IsZero() && e.sourcesAt.Sub(s.LastReset) < resetSettle:
			continue
		}
		n++
	}
	return n
}

// Source returns the hub's row for schedd. ok is false when the hub has
// none -- or when the snapshot is too old to vouch for anything, in which
// case nothing the hub holds counts as fresh.
func (e *HubEndpoint) Source(schedd string) (Source, bool) {
	if e == nil {
		return Source{}, false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.reachableLocked() {
		return Source{}, false
	}
	s, ok := e.sources[strings.ToLower(schedd)]
	return s, ok
}

// Federates reports whether the hub federates a spoke table, as its
// federation_sources rows list it. A hub with no source rows yet, or
// none this server has read, is taken not to.
func (e *HubEndpoint) Federates(table string) bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, s := range e.sources {
		if s.Tables[table] {
			return true
		}
	}
	return false
}

// Sources returns the snapshot, sorted by schedd.
func (e *HubEndpoint) Sources() []Source {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Source, 0, len(e.sources))
	for _, s := range e.sources {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Schedd < out[j].Schedd })
	return out
}

// ReadSources reads federation_sources now, bypassing the snapshot, and
// returns it with the time taken before the read.
func (e *HubEndpoint) ReadSources(ctx context.Context) (map[string]Source, time.Time, error) {
	if e == nil {
		return nil, time.Time{}, fmt.Errorf("no federation hub is configured")
	}
	at := e.clock()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	src, err := e.readSources(ctx)
	return src, at, err
}

// Freshness is how far behind its AP the hub's copy of schedd is, bounded
// from above: the hub's own staleness measure plus the age of the
// snapshot this server holds of it. ok is false unless the hub reports
// the source fresh with a measured staleness -- an unknown lag is never
// fresh enough.
//
// The jobs stream must also be connected with no error: freshness is
// measured on the syncstatus stream, which says nothing about whether
// the jobs stream is flowing.
func (e *HubEndpoint) Freshness(schedd string) (time.Duration, bool) {
	src, ok := e.Source(schedd)
	if !ok || src.State != StateFresh || !src.StalenessKnown || src.Staleness < 0 {
		return 0, false
	}
	if !src.JobsConnected || src.JobsLastError != "" {
		return 0, false
	}
	e.mu.RLock()
	snapshotAge := e.clock().Sub(e.sourcesAt)
	e.mu.RUnlock()
	if snapshotAge < 0 {
		snapshotAge = 0
	}
	return time.Duration(src.Staleness)*time.Second + snapshotAge, true
}
