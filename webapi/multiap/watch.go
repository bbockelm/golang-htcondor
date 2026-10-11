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

var _ jobwatch.CoveredSource = WatchSource{}

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
// The coverage is computed before the rows are read: it describes the
// hub's copy no later than the read, which is the direction of error
// that only delays a verdict.
func (w WatchSource) QueueCovered(ctx context.Context, owner string, attrs []string, limit int,
	yield func(*classad.ClassAd)) (bool, *jobwatch.Coverage, error) {
	s := w.Service
	user, err := s.UserFor(owner)
	if err != nil {
		return false, nil, err
	}
	cov := s.WatchCoverage()
	constraint, err := s.memberScope(user, "true")
	if err != nil {
		return false, nil, err
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
	return seen > limit, cov, nil
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
	if w.Feed != nil {
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

// WatchCoverage is which APs a hub read made now can vouch for, and how
// far: an AP the registry holds, that has not failed its trust probe,
// whose hub source is fresh with a measured staleness, and whose jobs
// stream is connected with no error since its last clean session -- all
// as of a federation_sources snapshot the hub is still answering for.
//
// The time each AP is vouched for up to is the snapshot's time less the
// staleness it reported, less the most the row can lag the hub's own
// measurement (the hub rewrites staleness alone at most once a minute)
// and one snapshot interval. A job last seen before that and missing now
// has left the queue.
func (s *Service) WatchCoverage() *jobwatch.Coverage {
	cov := jobwatch.NewCoverage()
	st := s.Hub.Status()
	if !st.Reachable {
		return cov
	}
	for _, m := range s.Registry.Members() {
		if asOf, ok := s.vouchedAsOf(m, st.LastSuccess); ok {
			cov.Vouch(m.Name, asOf)
		}
	}
	return cov
}

// vouchedAsOf applies WatchCoverage's rule to one member.
func (s *Service) vouchedAsOf(m apregistry.Member, sourcesAt time.Time) (time.Time, bool) {
	if m.Untrusted() {
		return time.Time{}, false
	}
	src, ok := s.Hub.Source(m.Name)
	if !ok || src.State != StateFresh || !src.StalenessKnown || !src.JobsConnected || src.JobsLastError != "" {
		return time.Time{}, false
	}
	lag := time.Duration(src.Staleness)*time.Second + sourceRowRefresh + s.Hub.interval
	return sourcesAt.Add(-lag), true
}

// VouchDeparture reports whether a job leaving the hub's jobs table now
// is evidence that it left its AP's queue: the jobwatch.Feed hook. The
// delete arrived on the hub's ordered stream, so only the AP's state
// matters, by the same rule as WatchCoverage.
func (s *Service) VouchDeparture(ad *classad.ClassAd) bool {
	st := s.Hub.Status()
	if !st.Reachable {
		return false
	}
	m, ok := s.Registry.Get(attrString(ad, AttrScheddName))
	if !ok {
		return false
	}
	_, ok = s.vouchedAsOf(m, st.LastSuccess)
	return ok
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

// hubStream reads rows from a hub table, parsed. A row that will not
// parse stops the read: to a watch a missing job is a finished one.
func (s *Service) hubStream(ctx context.Context, table, constraint string, proj []string, limit int,
	yield func(*classad.ClassAd)) error {
	dbc, closer, err := s.Hub.Client(ctx)
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
