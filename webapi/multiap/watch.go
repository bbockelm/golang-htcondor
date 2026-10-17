package multiap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// Job watches in multi-AP mode.
//
// The evaluator reads one owner's jobs on every AP from the hub's jobs
// table, and their finished jobs from the hub's history archive. A
// tracked job's absence from the queue is the evidence "done" rests on,
// and on a hub it is evidence only for an AP whose copy is known to be
// current: WatchSource returns, with every queue read, which APs it can
// vouch for (jobwatch.Coverage). Everything else -- a stale, absent,
// retiring or untrusted source, a jobs stream that is down or whose last
// session failed, a hub whose sources this server has not heard from --
// is not vouched for, and the evaluator waits.
//
// With two hubs, an evaluation pass is pinned to one (PinPass): its
// queue read, both federation_sources reads around it, its history read
// and the feed's terminal records all come from that hub, and the
// coverage it returns names the hub and selection generation as its
// origin. The evaluator forgets what it remembered about a watch's jobs
// when the origin changes, so after a switch absence is re-earned on the
// new hub -- which vouches for nothing until its own federation_sources
// says its jobs stream from that AP has caught up.

// AttrUser is the attribute multi-AP owner scoping keys on.
const AttrUser = "User"

// WatchSource is the job-watch evaluator's source in multi-AP mode. It
// implements jobwatch.CoveredSource.
type WatchSource struct {
	Service *Service
	// Feed, when set and warm, supplies terminal records seen on the
	// hub's jobs stream: the last ad of a job that left the queue saying
	// how it finished. Only those that say so are used; a delete alone is
	// not evidence here (see jobwatch.Coverage).
	Feed *jobwatch.Feed
}

var (
	_ jobwatch.CoveredSource = WatchSource{}
	_ jobwatch.PassPinner    = WatchSource{}
)

// PinPass implements jobwatch.PassPinner: one evaluation pass reads one
// hub.
func (w WatchSource) PinPass(ctx context.Context) context.Context { return w.Service.PinHub(ctx) }

// Queue implements jobwatch.Source. The evaluator reads a CoveredSource
// through QueueCovered; this answers the same rows without saying which
// APs they vouch for.
func (w WatchSource) Queue(ctx context.Context, owner string, attrs []string, limit int,
	yield func(*classad.ClassAd)) (bool, error) {
	truncated, _, err := w.QueueCovered(ctx, owner, attrs, limit, yield)
	return truncated, err
}

// QueueCovered streams owner's live jobs on every AP from the hub, and
// says which APs the read vouches for. owner is a watch's owner, the
// local part of User; the read keys on User (owner@UID_DOMAIN).
//
// federation_sources is read just before the jobs and again just after,
// as htcondordb's catch-up contract asks: an AP is vouched for only if
// the first read does (see vouch), and -- on a hub that publishes
// <Table>Synced -- the second still says JobsSynced with the same
// JobsSyncedAt, so no replay began or ended while the jobs were read.
// The time taken before the first read is the snapshot's time, the
// direction of error that only delays a verdict.
func (w WatchSource) QueueCovered(ctx context.Context, owner string, attrs []string, limit int,
	yield func(*classad.ClassAd)) (bool, *jobwatch.Coverage, error) {
	s := w.Service
	user, err := s.UserFor(owner)
	if err != nil {
		return false, nil, err
	}
	constraint, err := s.memberScope(user, "true")
	if err != nil {
		return false, nil, err
	}
	ctx = s.PinHub(ctx)
	hub := s.Hub.For(ctx)
	before, at, err := hub.ReadSources(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("reading the federation hub's sources: %w", err)
	}
	seen := 0
	err = s.hubStream(ctx, TableJobs, constraint, projectionWith(attrs, AttrScheddName, AttrUser), limit+1,
		func(ad *classad.ClassAd) {
			seen++
			if seen <= limit {
				yield(ad)
			}
		})
	if err != nil {
		return false, nil, fmt.Errorf("reading the federation hub's queue: %w", err)
	}
	truncated := seen > limit
	after, _, aerr := hub.ReadSources(ctx)
	if aerr != nil {
		// Nothing confirms the catch-up held across the read: vouch for
		// nothing this pass.
		return truncated, s.newCoverage(ctx), nil
	}
	return truncated, s.coverage(s.newCoverage(ctx), before, after, at), nil
}

// newCoverage is an empty coverage naming the hub ctx is pinned to and
// its selection generation as the origin, and whether there is more than
// one hub a watch's jobs could have been seen on.
func (s *Service) newCoverage(ctx context.Context) *jobwatch.Coverage {
	return jobwatch.NewCoverageFrom(s.HubOrigin(ctx), s.Hub.Several())
}

// coverage vouches, in cov, for each member that before vouches for at
// time at, and whose jobs catch-up, where the hub publishes one, after
// confirms. before and after are the hub cov names.
func (s *Service) coverage(cov *jobwatch.Coverage, before, after map[string]Source, at time.Time) *jobwatch.Coverage {
	for _, m := range s.Registry.Members() {
		key := strings.ToLower(m.Name)
		src, ok := before[key]
		if !ok {
			continue
		}
		asOf, ok := s.vouch(m, src, at)
		if !ok {
			continue
		}
		if ts := src.TableStatus[TableJobs]; ts.SyncedKnown {
			again, ok := after[key]
			at2 := again.TableStatus[TableJobs]
			if !ok || !at2.Synced || !at2.SyncedAt.Equal(ts.SyncedAt) {
				continue
			}
		}
		cov.Vouch(m.Name, asOf)
	}
	return cov
}

// History streams owner's jobs that finished since a point in time, on
// every AP: the hub's history archive, then terminal records the hub's
// jobs stream saw. History records are terminal evidence whatever the
// AP's freshness -- the archive is append-only, so a late copy is still
// right about what it holds.
func (w WatchSource) History(ctx context.Context, owner string, attrs []string, since time.Time, limit int,
	yield func(*classad.ClassAd)) error {
	s := w.Service
	user, err := s.UserFor(owner)
	if err != nil {
		return err
	}
	ctx = s.PinHub(ctx)
	seen := map[[3]string]bool{}
	emit := func(ad *classad.ClassAd) {
		k := rowKey(ad)
		if seen[k] {
			return
		}
		seen[k] = true
		yield(ad)
	}
	window := fmt.Sprintf("EnteredHistoryTime >= %d || CompletionDate >= %d || EnteredCurrentStatus >= %d",
		since.Unix(), since.Unix(), since.Unix())
	constraint, err := s.memberScope(user, window)
	if err != nil {
		return err
	}
	archiveErr := s.hubStream(ctx, TableHistory, constraint, projectionWith(attrs, AttrScheddName, AttrUser), limit, emit)

	streamed := 0
	// The feed's records count only while it follows the hub this pass
	// reads: after a switch it starts over on the new hub.
	if w.Feed != nil && w.Feed.Origin() == s.HubOrigin(ctx) {
		for _, ad := range w.Feed.Terminal(owner, since) {
			// The ad itself must say the job finished: a delete on the
			// hub is also an AP being retired or reconciled.
			if st, ok := ad.EvaluateAttrInt("JobStatus"); !ok || (st != 3 && st != 4) {
				continue
			}
			if !s.isMember(attrString(ad, AttrScheddName)) {
				continue
			}
			streamed++
			emit(ad)
		}
	}
	if archiveErr != nil && streamed == 0 {
		return fmt.Errorf("terminal job outcomes cannot be resolved: %w", archiveErr)
	}
	return nil
}

func rowKey(ad *classad.ClassAd) [3]string {
	c, _ := ad.EvaluateAttrInt("ClusterId")
	p, _ := ad.EvaluateAttrInt("ProcId")
	return [3]string{strings.ToLower(attrString(ad, AttrScheddName)), fmt.Sprint(c), fmt.Sprint(p)}
}

func attrString(ad *classad.ClassAd, name string) string {
	v, _ := ad.EvaluateAttrString(name)
	return v
}

// DefaultHubStateInterval is htcondordb's default
// HTCONDORDB_FEDERATE_STATE_INTERVAL: how often the hub recomputes
// source states and writes federation_sources. The hub does not publish
// it; Service.HubStateInterval overrides it.
const DefaultHubStateInterval = 5 * time.Second

// resetSettle is, on a hub that does not publish <Table>Synced, how long
// after a source's LastReset its jobs are not vouched for: such a hub
// cannot say when the replay a Reset starts has finished, and a replay
// from scratch has a connected, error-free stream and a fresh heartbeat
// while its rows are still arriving.
const resetSettle = 10 * time.Minute

// WatchCoverage is which APs the snapshot of federation_sources of the
// hub ctx is pinned to (else the active one) vouches for (see vouch).
// The evaluator reads the sources itself around each queue read
// (QueueCovered); this is the same rule over the snapshot.
func (s *Service) WatchCoverage(ctx context.Context) *jobwatch.Coverage {
	ctx = s.PinHub(ctx)
	hub := s.Hub.For(ctx)
	cov := s.newCoverage(ctx)
	st := hub.Status()
	if !st.Reachable {
		return cov
	}
	for _, m := range s.Registry.Members() {
		src, ok := hub.Source(m.Name)
		if !ok {
			continue
		}
		if asOf, ok := s.vouch(m, src, st.LastSuccess); ok {
			cov.Vouch(m.Name, asOf)
		}
	}
	return cov
}

// vouch decides whether a member's jobs on the hub, per a
// federation_sources row read at time at, are complete enough that a
// job missing from them has left its AP's queue, and up to when. It
// must be: in the registry and not failed its trust probe; fresh on the
// hub with a measured staleness; its jobs stream connected with no error
// since its last clean session; and caught up -- JobsSynced where the hub
// publishes it, else no Reset within resetSettle.
//
// It is vouched for up to at less the staleness the row reported, the
// most the row can lag the hub's measurement (the hub rewrites staleness
// alone at most once a minute) and one hub state interval.
func (s *Service) vouch(m apregistry.Member, src Source, at time.Time) (time.Time, bool) {
	if m.Untrusted() || src.State != StateFresh || !src.StalenessKnown {
		return time.Time{}, false
	}
	jobs, ok := src.TableStatus[TableJobs]
	if !ok {
		jobs = TableStatus{Connected: src.JobsConnected, LastError: src.JobsLastError}
	}
	if !jobs.Usable() {
		return time.Time{}, false
	}
	switch {
	case jobs.SyncedKnown && !jobs.Synced:
		return time.Time{}, false
	case !jobs.SyncedKnown && !src.LastReset.IsZero() && at.Sub(src.LastReset) < resetSettle:
		return time.Time{}, false
	}
	lag := time.Duration(src.Staleness)*time.Second + sourceRowRefresh + s.hubStateInterval()
	return at.Add(-lag), true
}

func (s *Service) hubStateInterval() time.Duration {
	if s.HubStateInterval > 0 {
		return s.HubStateInterval
	}
	return DefaultHubStateInterval
}

// OwnerOfRow is the owner a hub row belongs to, for the jobwatch.Feed:
// the local part of its User when User is in UID_DOMAIN, else none. A
// row whose User is in another domain belongs to nobody this server can
// name, and is shown to nobody.
func (s *Service) OwnerOfRow(ad *classad.ClassAd) string {
	user := attrString(ad, AttrUser)
	i := strings.LastIndex(user, "@")
	if i <= 0 || !strings.EqualFold(user[i+1:], s.UIDDomain) {
		return ""
	}
	return user[:i]
}

// isMember reports whether schedd is in the AP set.
func (s *Service) isMember(schedd string) bool {
	if schedd == "" {
		return false
	}
	_, ok := s.Registry.Get(schedd)
	return ok
}

// memberScope is constraint confined to user's jobs on every member of
// the AP set, whatever their freshness: the caller decides what a
// degraded AP's rows mean.
func (s *Service) memberScope(user, constraint string) (string, error) {
	var names []string
	for _, m := range s.Registry.Members() {
		names = append(names, m.Name)
	}
	return scoped(user, constraint, names)
}

// hubStream reads rows from a table of the hub ctx is pinned to (else
// the active one), parsed. A row that will not parse stops the read: to
// a watch a missing job is a finished one.
func (s *Service) hubStream(ctx context.Context, table, constraint string, proj []string, limit int,
	yield func(*classad.ClassAd)) error {
	dbc, closer, err := s.Hub.For(ctx).Client(ctx)
	if err != nil {
		return err
	}
	defer closer()
	var perr error
	err = dbc.QueryRawProjectStream(ctx, table, constraint, proj, limit, func(text string) bool {
		ad, e := classad.ParseOld(text)
		if e != nil {
			perr = fmt.Errorf("unparseable %s row: %w", table, e)
			return false
		}
		yield(ad)
		return true
	})
	if err == nil {
		err = perr
	}
	return err
}

// OpenJobsWatch opens a watch on the active hub's jobs table, for the
// job-watch feed (jobwatch.Feed.RunResumableFrom): resuming after
// from.Cursor when from is this hub's, from the table's head otherwise.
// origin names the hub and selection generation (Hub.Origin).
//
// A cursor is a position in one hub's change log, so another hub's is
// never sent: after a switch the feed starts over on the new hub, holding
// nothing from the old one. The stream ends when the active hub changes,
// which is what moves the feed. The hub answers a cursor of its own it
// cannot resume from (it restarted, or its change log no longer reaches
// back) with a Reset and its whole table.
func (s *Service) OpenJobsWatch(ctx context.Context, from jobwatch.Resume) (<-chan jobwatch.WatchEvent, func(), string, error) {
	if s.Hub == nil {
		return nil, nil, "", fmt.Errorf("no federation hub is configured")
	}
	pin := s.Hub.pinNow()
	origin := pin.origin()
	cursor := from.Cursor
	if from.Origin != origin {
		cursor = nil
	}
	dbc, closer, err := pin.ep.Client(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	if cursor == nil {
		if cursor, err = dbc.WatchHead(ctx, TableJobs); err != nil {
			closer()
			return nil, nil, "", fmt.Errorf("reading the hub's jobs watch head: %w", err)
		}
	}
	raw, stop, err := dbc.WatchTable(ctx, TableJobs, cursor)
	if err != nil {
		closer()
		return nil, nil, "", fmt.Errorf("opening the hub's jobs watch: %w", err)
	}
	out := make(chan jobwatch.WatchEvent, 64)
	go func() {
		defer close(out)
		for {
			select {
			case ev, ok := <-raw:
				if !ok {
					return
				}
				select {
				case out <- jobwatch.WatchEvent{Kind: ev.Kind, Key: ev.Key, AdText: ev.AdText, Cursor: ev.Cursor}:
				case <-ctx.Done():
					return
				case <-pin.changed:
					return
				}
			case <-ctx.Done():
				return
			case <-pin.changed:
				// Another hub is active: end this stream so the feed
				// reopens on it.
				return
			}
		}
	}()
	return out, func() { stop(); closer() }, origin, nil
}
