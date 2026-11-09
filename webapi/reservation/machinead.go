package reservation

import (
	"math"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// The attribute contract between the controller and an execute point.
//
// Three properties of CA_UPDATE_MACHINE_AD -- the only way to put an
// attribute on a running startd -- shape all of it, and none is visible
// from the API:
//
//   - the merge is per machine, into one ad every slot publishes, so
//     holding is a per-machine act;
//   - there is no delete and no expiry, so an attribute lives until the
//     startd restarts;
//   - the attributes become operands of the slot's own expressions, not
//     decoration on what the collector shows, which is what lets START
//     read them at all.
//
// The second is why every value here is absolute rather than a flag. A
// controller that dies leaves its last push behind; a deadline in the
// past stops constraining anything on its own, where a flag would hold
// a machine for the life of the startd with nobody left to clear it.
//
// It is also why no reservation's name appears in an attribute name. A
// semester of classes would otherwise leave hundreds of dead keys on
// every execute point.
const (
	// AttrStart is the sieve: the expression the site's START is
	// composed with. Pushed as a whole so that a controller and the
	// operands it refers to always agree.
	AttrStart = "ReservationStart"
	// AttrDeadline is the bell, in unix seconds: nothing may start here
	// that will not have finished by then. Zero or absent means no
	// drain is in progress.
	AttrDeadline = "ReservationDeadline"
	// AttrUntil is the end of the window, in unix seconds. Until it
	// passes the machine belongs to AttrProject; after it, the machine
	// is unconstrained again whether or not anyone clears it.
	AttrUntil = "ReservationUntil"
	// AttrProject is the ProjectName whose jobs the machine is being
	// held for.
	AttrProject = "ReservationProject"
)

// AttrBucket is what a job must carry to be admitted to a draining
// machine: an upper bound, in seconds, on how long it will run if it
// starts now.
//
// A job without it is refused rather than guessed about. The estimate
// is written by the access point, not by the submitter -- but nothing
// stops a submitter writing their own, and the sieve cannot tell the
// difference. The backstop is that eviction does not consult it: a job
// that lied its way onto a reserved core is preempted at the bell like
// any other.
const AttrBucket = "RuntimeP90Bucket"

// BucketGrain is what estimates are rounded up to.
//
// This attribute is referenced by the execute points' START, so the
// negotiator reports it to the schedd as a significant attribute and
// the schedd splits autoclusters on it. The number of distinct values
// in play is therefore a matchmaking cost, paid by the whole pool, and
// it is the reason the estimate is bucketed rather than answered to the
// second.
//
// Half an hour is also the default forgiveness threshold, so the
// coarsest useful grain and the cost rule agree.
const BucketGrain = 30 * time.Minute

// Bucket rounds a duration up to the next BucketGrain, in seconds. A
// non-positive duration is one grain: a job the estimator thinks takes
// no time still occupies a core for a while.
//
// Prefer BucketCapped. Rounding alone is not enough: measured against
// an access point's idle queue, rounding took 7,765 distinct estimates
// down to 194, and 194 is still far more autocluster splitting than
// this feature is worth.
func Bucket(d time.Duration) int64 {
	grains := int64(1)
	if d > 0 {
		grains = int64(math.Ceil(float64(d) / float64(BucketGrain)))
	}
	return grains * int64(BucketGrain/time.Second)
}

// BucketCapped is Bucket, clamped to one grain beyond horizon.
//
// The sieve asks one question of this number: does the job finish
// before the bell. The bell is never further away than the longest
// reservation's lead, so every value past that is the same answer --
// "does not fit" -- and distinguishing them buys nothing while costing
// autocluster splits. Capping is therefore exactly equivalent for
// admission, not an approximation.
//
// On the queue measured above it takes 194 distinct values to 13 at a
// six-hour lead, and to 5 at two hours. Most of the saving is the tail:
// 15.5% of clusters estimate past six hours and collapse to one value.
//
// A horizon of zero means no cap, which is what a caller with no
// reservations to size against should pass.
func BucketCapped(d time.Duration, horizon time.Duration) int64 {
	b := Bucket(d)
	if horizon <= 0 {
		return b
	}
	// One grain beyond the horizon, so the capped value still fails the
	// sieve's comparison against a deadline exactly horizon away.
	limit := (int64(math.Ceil(float64(horizon)/float64(BucketGrain))) + 1) *
		int64(BucketGrain/time.Second)
	if b > limit {
		return limit
	}
	return b
}

// Sieve is the expression pushed as ReservationStart.
//
// It is a constant: every controller composes the identical bytes, so
// two access points pushing the same machine at the same moment cannot
// disagree, and only the operands change from tick to tick.
//
// Read as three ways to be admitted:
//
//  1. The reservation is over, or the machine was never held. An
//     untouched machine has no ReservationUntil, which defaults to zero
//     and is always in the past.
//  2. The job belongs to the project the machine is held for. Guarded on
//     a non-empty project so that a machine holding an empty one does
//     not admit every job that names no project at all --
//     undefined =?= undefined is true.
//  3. The job will have finished by the bell. An unstamped job defaults
//     to -1 and fails the test, which is the refusal the drain depends
//     on.
//
// Written with the defaulting operator rather than explicit undefined
// tests, and with operators rather than functions: strlen is a ClassAd
// function in HTCondor and not in every implementation that has to
// parse this, and a sieve that parses differently in two places is
// worse than a wordier one.
//
// There is deliberately no large sentinel for the unstamped case. An
// "effectively infinite" runtime is only infinite relative to the
// deadline, and a deadline far enough out makes it finite again.
const Sieve = `( time() >= ( ` + AttrUntil + ` ?: 0 ) )` +
	` || ( ( ` + AttrProject + ` ?: "" ) != "" && TARGET.ProjectName =?= ` + AttrProject + ` )` +
	` || ( ( TARGET.` + AttrBucket + ` ?: -1 ) >= 0` +
	` && time() + TARGET.` + AttrBucket + ` <= ( ` + AttrDeadline + ` ?: 0 ) )`

// StartStanza is the one line a site puts in its execute points' config
// to let reservations govern them.
//
// It has to be in the config file. START cannot be pushed: the startd
// republishes it from its own configuration on every refresh, so a
// pushed one is overwritten and the machine goes on admitting
// everything while appearing to be held. The operands above are pushed;
// this is not.
const StartStanza = `START = $(START) && ( ` + AttrStart + ` ?: True )`

// Provisioned reports whether an execute point's published START will
// consult the sieve.
//
// The test is for a reference to the attribute rather than for the
// stanza's exact text, so an operator who wrote the clause themselves,
// in their own spelling, is recognised.
//
// An empty expression is not provisioned and is not evidence of
// anything: START missing from a slot ad usually means the census did
// not ask for it.
func Provisioned(start string) bool {
	return containsFold(start, AttrStart)
}

// HoldAd is the push that puts a machine under a reservation.
//
// deadline is the bell, until is the end of the window, project is whose
// seats these are. The sieve goes with them on every push: an execute
// point that restarted since the last one has forgotten it, and a push
// that set only the operands would leave that machine unconstrained
// while the controller counted it as held.
func HoldAd(deadline, until time.Time, project string) *classad.ClassAd {
	ad := classad.New()
	ad.InsertExpr(AttrStart, sieveExpr)
	_ = ad.Set(AttrDeadline, unixOrZero(deadline))
	_ = ad.Set(AttrUntil, unixOrZero(until))
	_ = ad.Set(AttrProject, project)
	return ad
}

// ReleaseAd is the push that takes a machine back out of a reservation.
//
// Nothing is deleted, because nothing can be: the attributes are set to
// values that stop constraining anything. The sieve stays where it is,
// evaluating to true on every job, so a later hold is three operands
// rather than a reinstallation.
func ReleaseAd() *classad.ClassAd {
	ad := classad.New()
	ad.InsertExpr(AttrStart, sieveExpr)
	_ = ad.Set(AttrDeadline, int64(0))
	_ = ad.Set(AttrUntil, int64(0))
	_ = ad.Set(AttrProject, "")
	return ad
}

// ProbeAd is a push that changes nothing, for asking an execute point
// whether this access point may still administer it.
//
// It writes the sieve and nothing else. Writing no attribute at all
// would be a cheaper probe but a weaker one: the startd answers a
// request it cannot act on the same way it answers one it can, so a
// probe that never writes proves only that the connection was accepted.
func ProbeAd() *classad.ClassAd {
	ad := classad.New()
	ad.InsertExpr(AttrStart, sieveExpr)
	return ad
}

// sieveExpr is Sieve parsed once. It is a compile-time constant, so a
// parse failure is a programming error rather than something a caller
// could act on, and the expression is shared because expressions are
// immutable.
var sieveExpr = func() *classad.Expr {
	expr, err := classad.ParseExpr(Sieve)
	if err != nil {
		panic("reservation: the sieve does not parse: " + err.Error())
	}
	return expr
}()

// containsFold reports whether s mentions sub, ignoring case. ClassAd
// attribute names are case-insensitive, so a site that wrote the clause
// in its own spelling still counts.
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// HeldFromAd reads back what a machine is currently held for.
//
// The controller reads this from the pool every tick rather than
// remembering what it pushed: a restart mid-drain, a push that failed,
// and a deadline left by a process that died all have to be visible
// before they can be corrected.
//
// held is false when the machine is not under a reservation now --
// never touched, released, or a window that has passed.
func HeldFromAd(ad *classad.ClassAd, now time.Time) (deadline, until time.Time, project string, held bool) {
	if ad == nil {
		return time.Time{}, time.Time{}, "", false
	}
	untilSec := int64(adNum(ad, AttrUntil))
	if untilSec <= 0 {
		return time.Time{}, time.Time{}, "", false
	}
	until = time.Unix(untilSec, 0)
	if !until.After(now) {
		return time.Time{}, time.Time{}, "", false
	}
	deadline = time.Unix(int64(adNum(ad, AttrDeadline)), 0)
	project, _ = ad.EvaluateAttrString(AttrProject)
	return deadline, until, project, true
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	if u := t.Unix(); u > 0 {
		return u
	}
	return 0
}
