package jobwatch

import (
	"context"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Absence across several access points.
//
// With one schedd, a tracked job missing from a complete read of its
// owner's queue has left it: that is what lets "done" work without a
// history archive. A server fronting many access points reads them all
// through one federation hub, and "complete" is then per access point.
// If one AP's copy on the hub is stale -- its spoke is down, its stream
// is failing, it is being replayed -- its jobs are missing from nothing:
// the hub simply has not heard. Counting that as completion would fire a
// "your job finished" for every job on that AP.
//
// So a multi-AP source says, per access point, how far its read can be
// trusted to show a departure (Coverage). An AP the source cannot vouch
// for is not in it, and its jobs' absence is never evidence; the watch
// waits. History records -- terminal evidence in their own right -- are
// unaffected.

// Coverage is a queue read's per-access-point completeness: for each AP
// whose source the read can vouch for, the time up to which every change
// on that AP is reflected in the read. A job of that AP absent from the
// read left the queue if it was last seen before that time; a job of an
// AP not listed proves nothing by being absent.
type Coverage struct {
	asOf map[string]time.Time // by lower-cased schedd name
	// origin names what the read came from, when the source can read
	// from more than one backend (two federation hubs): evidence is only
	// comparable between reads of one origin.
	origin string
	// several says the source has more than one backend it could have
	// read from, so a job tracked before this process's first read may
	// have been seen on another (see absenceMemory.strict).
	several bool
}

// NewCoverage returns a Coverage that vouches for no access point.
func NewCoverage() *Coverage { return &Coverage{asOf: map[string]time.Time{}} }

// NewCoverageFrom returns a Coverage of a read from origin that vouches
// for no access point yet; several says the source has more than one
// backend it could read from. When the origin of a watch's reads
// changes, the evaluator starts its memory of the watch's jobs over, and
// a tracked job counts as gone by its absence only once it has been seen
// in the new origin's queue: before that, the new backend may simply
// never have held it (a lagging hub's jobs stream). Until then only
// terminal evidence from the new origin -- a history record, a terminal
// record on its stream -- finishes it.
func NewCoverageFrom(origin string, several bool) *Coverage {
	return &Coverage{asOf: map[string]time.Time{}, origin: origin, several: several}
}

// Several reports whether the source has more than one backend.
func (c *Coverage) Several() bool { return c != nil && c.several }

// Origin is the origin the read came from; empty when the source names
// none.
func (c *Coverage) Origin() string {
	if c == nil {
		return ""
	}
	return c.origin
}

// Vouch records that the read reflects every change on schedd up to
// asOf.
func (c *Coverage) Vouch(schedd string, asOf time.Time) {
	if schedd == "" {
		return
	}
	c.asOf[strings.ToLower(schedd)] = asOf
}

// AsOf returns the time up to which the read covers schedd, and whether
// it vouches for schedd at all.
func (c *Coverage) AsOf(schedd string) (time.Time, bool) {
	if c == nil || schedd == "" {
		return time.Time{}, false
	}
	t, ok := c.asOf[strings.ToLower(schedd)]
	return t, ok
}

// evidence reports whether a job on schedd, last seen in the queue at
// lastSeen, has left it if a read with this coverage does not show it:
// the read must vouch for the AP and reflect changes newer than that
// sighting.
func (c *Coverage) evidence(schedd string, lastSeen time.Time) bool {
	asOf, ok := c.AsOf(schedd)
	return ok && asOf.After(lastSeen)
}

// CoveredSource is a Source whose queue spans several access points. The
// evaluator reads the queue through QueueCovered instead of Queue, and a
// tracked job's absence counts only where the coverage it returns says
// so. A nil Coverage vouches for nothing.
type CoveredSource interface {
	Source
	QueueCovered(ctx context.Context, owner string, attrs []string, limit int,
		yield func(*classad.ClassAd)) (truncated bool, cov *Coverage, err error)
}

// PassPinner is a Source that reads from one of several backends (two
// federation hubs) and can hold one evaluation pass to one of them. The
// evaluator calls PinPass at the start of each owner's pass and makes
// every read of that pass with the context it returns, so a pass never
// mixes what two backends said.
type PassPinner interface {
	PinPass(ctx context.Context) context.Context
}

// absenceMemory is what the evaluator remembers between passes about a
// watch's jobs, for deciding whether a read is newer than a job's last
// sighting. It lives in memory only: after a restart every absent job is
// taken to have been seen at the first pass's read, which only delays a
// verdict.
type absenceMemory struct {
	// origin is the Coverage origin the memory was gathered from. A
	// read of another origin starts the memory over.
	origin string
	// strict is set when the memory may describe jobs tracked on another
	// origin: it was started over because the origin changed, or started
	// fresh on a source with several origins. A strict memory counts a
	// job's absence only once seenHere says the job was in this origin's
	// queue.
	strict   bool
	seenHere map[JobID]bool
	// lastRead is when the previous pass's queue read finished: every
	// tracked job not in since was present in it (or beyond its cut).
	lastRead time.Time
	// since is, for each tracked job missing from the queue, when it was
	// last seen there.
	since map[JobID]time.Time
}
