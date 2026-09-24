package issues

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Collecting the raw material for the issues view.
//
// Two sources, because the two questions have different answers:
//
//   - What is stuck right now is the live queue. A held job sits there
//     with its full HoldReason, and nothing else has to be scanned.
//   - What went wrong and then stopped being wrong is the epoch history:
//     one record per run attempt, carrying VacateReason. A job whose
//     shadow threw an exception is running again minutes later, so the
//     queue has no memory of it -- measured on ap40, the whole live
//     queue held six jobs with NumShadowExceptions set while epoch
//     history carried a steady stream of them.
//
// Both are bounded. An unbounded read over either is how this view would
// become the thing that takes the access point down.
//
// The reads themselves belong to the caller (Source): the HTTP server
// and the MCP server each have their own mirror client, schedd handle
// and owner-scoping rules, and neither should have its own copy of what
// a "problem" is.

// Source reads ads for the collector. Implementations decide where from
// -- an htcondordb mirror, the schedd, or a test fixture -- and return a
// short name for what answered.
type Source interface {
	// JobAds reads the live queue.
	JobAds(ctx context.Context, constraint string, projection []string, limit int) (ads []*classad.ClassAd, source string, err error)
	// EpochAds reads per-run-attempt records. Returning an error is
	// expected where JOB_EPOCH_HISTORY is not configured; the collector
	// reports that rather than failing.
	EpochAds(ctx context.Context, constraint string, projection []string, limit int) (ads []*classad.ClassAd, source string, err error)
}

// Options are what to collect.
type Options struct {
	// Scope is a ClassAd predicate confining the read to what the caller
	// may see, e.g. `Owner == "alice"`. Empty means everything the
	// underlying source would return.
	Scope string
	// Window is how far back to look.
	Window time.Duration
	// IncludeEnded reads run-attempt history as well as the live queue:
	// without it the view describes what is stuck now, with it what has
	// gone wrong over the window.
	IncludeEnded bool
	// Now is injectable for tests.
	Now func() time.Time
}

// HoldProjection is the attributes read per held job. Lean on purpose:
// this can be tens of thousands of rows, and HoldReason is already the
// long one.
var HoldProjection = append([]string{
	"ClusterId", "ProcId", "Owner", "JobBatchName",
	"HoldReason", "HoldReasonCode", "HoldReasonSubCode", "EnteredCurrentStatus",
}, facetAttrs...)

// EpochProjection is the attributes read per run attempt.
var EpochProjection = append([]string{
	"ClusterId", "ProcId", "Owner", "JobBatchName",
	"VacateReason", "VacateReasonCode", "VacateReasonSubCode",
	"EpochWriteDate", "JobCurrentStartDate", "NumShadowExceptions",
}, facetAttrs...)

// EpochTimeAttr is the attribute the epoch window is expressed in.
//
// It has to be this one. htcondordb zone-maps an epoch archive on
// EpochWriteDate and EnteredHistoryTime and on nothing else, so a range
// predicate over any other attribute prunes no segments at all and the
// read walks every run attempt the access point has ever made rather
// than the window's. The page was asking about JobCurrentStartDate,
// which is not zone-mapped -- correct, and answered by reading months of
// history to produce a day of it.
//
// It is also the better timestamp on its own terms: the schedd writes it
// when the run instance ends, so it is when the failure happened, where
// JobCurrentStartDate is when the attempt that failed began.
const EpochTimeAttr = "EpochWriteDate"

// Where a job ran, as the attributes that carry it.
//
// These are glidein attributes: on OSPool every execute slot is a pilot,
// and the resource (the CE the pilot came from) and the site are recorded
// on the job when it matches. They correlate strongly with what goes
// wrong -- a CE with a broken CVMFS or a full scratch disk produces hold
// reasons that read exactly like everyone else's until you notice they
// are all from one place.
//
// An access point whose jobs do not carry them (a local CHTC pool, say)
// simply has no facets, and everything below degrades to grouping on the
// message alone.
var facetAttrs = []string{
	"MachineAttrGLIDEIN_ResourceName0",
	"MATCH_EXP_JOBGLIDEIN_ResourceName",
	"MachineAttrGLIDEIN_Site0",
}

// LocalPoolLabel is what a job that did not run on a pilot is said to
// have run on.
//
// The submit-side configuration that populates JOBGLIDEIN_ResourceName
// is a match expression over the machine's glidein attributes, with a
// literal fallback for when the machine has none. On CHTC's access
// points that fallback is the string "Local Job", so a local pool's
// every hold reports having happened at a place called "Local Job" --
// which is not a place, and reads as a bug because it is describing the
// absence of a pilot as though it were a site.
const LocalPoolLabel = "Local Pool"

// notAPlace are the values of the resource attribute that mean "this did
// not run on a pilot" rather than naming somewhere.
//
// Matched on the value because the fallback lives in site configuration
// rather than in HTCondor, so there is no attribute to test instead.
// Compared case-insensitively and after trimming, since it is a string
// somebody typed into a config file.
var notAPlace = map[string]bool{
	"local job": true,
	"unknown":   true,
	"undefined": true,
}

// facetsOf reads the where-it-ran attributes off an ad.
//
// Resource has two spellings: MachineAttrGLIDEIN_ResourceName0 is what
// the startd advertised and MATCH_EXP_JOBGLIDEIN_ResourceName is what the
// match expression evaluated to. The first is preferred because it is
// the machine's own word for itself; the second is a fallback, and the
// one that carries the sentinel.
func facetsOf(ad *classad.ClassAd) map[string]string {
	facets := map[string]string{}
	resource := ""
	if v, ok := ad.EvaluateAttrString("MachineAttrGLIDEIN_ResourceName0"); ok {
		resource = strings.TrimSpace(v)
	}
	if resource == "" {
		if v, ok := ad.EvaluateAttrString("MATCH_EXP_JOBGLIDEIN_ResourceName"); ok {
			resource = strings.TrimSpace(v)
		}
	}
	if notAPlace[strings.ToLower(resource)] {
		resource = LocalPoolLabel
	}
	if resource != "" {
		facets["resource"] = resource
	}
	// No site for a local job: there is no pilot and therefore no site,
	// and repeating the resource under a second name would be two chips
	// saying one thing.
	if v, ok := ad.EvaluateAttrString("MachineAttrGLIDEIN_Site0"); ok {
		if site := strings.TrimSpace(v); site != "" && !notAPlace[strings.ToLower(site)] {
			facets["site"] = site
		}
	}
	if len(facets) == 0 {
		return nil
	}
	return facets
}

// MaxRecords bounds each source. Past it the view reports what it read
// rather than pretending it read everything: an access point with a
// 40,000-job hold backlog is exactly the one where this matters, and
// also the one where an unbounded scan is a bad idea.
const MaxRecords = 20000

// benignVacateCodes are run attempts that ended without anything going
// wrong. Putting "Cleaning up after job" at the top of a view titled
// Issues would bury the things that did go wrong.
var benignVacateCodes = map[int64]bool{
	1028: true, // "Cleaning up after job" -- ordinary completion
}

// shadowSideCodeFloor is where HTCondor's vacate codes stop describing
// the job and start describing the run.
//
// Its own hold codes are small numbers (21 is a memory overrun, 12 a
// transfer failure). The 1000s are the shadow's: 1007 lost contact with
// the execute point, 1008 the lease expired, 1009 the shadow threw an
// exception. That is the line between "your job was stopped for a reason
// about the job" and "your job could not be kept running", which is the
// line the view draws between its two sections.
const shadowSideCodeFloor = 1000

// Set is one collection pass.
type Set struct {
	Records []Record
	// Source names what answered, for the footer.
	Source string
	// Notes are the sentences to show when a section is thin for a
	// reason other than "nothing went wrong".
	Notes []string
	// Truncated says a source hit MaxRecords, so the counts are a floor
	// rather than a total.
	Truncated bool
	// Incomplete says a source could not be read at all, so this set is
	// missing a section rather than merely being short. A caller that
	// caches sets should keep this one only briefly: a transient failure
	// that sticks for the full lifetime turns one bad moment into
	// minutes of a banner nobody can dismiss.
	Incomplete bool
	ComputedAt time.Time

	// What each read cost and returned. This page reads two large
	// tables, so "it is slow" has at least three possible answers and
	// no way to tell them apart from the outside -- these are what make
	// the question answerable without attaching a profiler to a
	// production access point.
	HoldCount     int
	HoldDuration  time.Duration
	EpochCount    int
	EpochDuration time.Duration
}

// Collect reads both sources for one scope and window.
func Collect(ctx context.Context, src Source, opts Options) (*Set, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	since := now().Add(-opts.Window).Unix()
	scope := opts.Scope
	if scope == "" {
		scope = "true"
	}
	set := &Set{ComputedAt: now()}

	// Currently held. The window is when the job entered the held state,
	// so a backlog held last Tuesday does not drown out this morning.
	holdConstraint := fmt.Sprintf("(%s) && EnteredCurrentStatus >= %d && JobStatus == 5", scope, since)
	holdStart := now()
	held, heldSource, err := src.JobAds(ctx, holdConstraint, HoldProjection, MaxRecords)
	set.HoldDuration = now().Sub(holdStart)
	set.HoldCount = len(held)
	if err != nil {
		return nil, fmt.Errorf("reading held jobs: %w", err)
	}
	if len(held) >= MaxRecords {
		set.Truncated = true
	}
	set.Source = heldSource
	for _, ad := range held {
		set.Records = append(set.Records, holdRecord(ad))
	}

	if !opts.IncludeEnded {
		return set, nil
	}

	// Run attempts that ended badly. This is both "jobs failing to
	// start" and the holds that have since been released or removed --
	// one read, because they are the same record with different codes.
	// The zone-mapped time bound goes first, ahead of the existence test.
	//
	// Epoch history is append-only and unbounded -- it holds every run
	// attempt this access point has ever made, not just this window's --
	// so which predicate the storage can prune on is the difference
	// between reading a day and reading a year. See EpochTimeAttr.
	// "VacateReasonCode isnt undefined" can prune nothing on its own: it
	// is an existence test, true of no rows or many, with no range for a
	// zone map to skip on.
	epochConstraint := fmt.Sprintf(
		"(%s) && %s >= %d && VacateReasonCode isnt undefined", scope, EpochTimeAttr, since)
	epochStart := now()
	attempts, epochSource, eerr := src.EpochAds(ctx, epochConstraint, EpochProjection, MaxRecords)
	set.EpochDuration = now().Sub(epochStart)
	set.EpochCount = len(attempts)
	if eerr != nil {
		// A missing epoch history is a configuration fact, not an error:
		// JOB_EPOCH_HISTORY is off by default. Say so and show the rest
		// rather than failing whole.
		//
		// A read that ran out of time is a different thing from one that
		// could not be made, and saying "so they are not included" about
		// both taught people to read a timeout as a misconfiguration.
		set.Incomplete = true
		if errors.Is(eerr, context.Canceled) || errors.Is(eerr, context.DeadlineExceeded) {
			set.Notes = append(set.Notes,
				"Reading run-attempt history took too long, so jobs that failed to start and holds that have already ended are missing from this answer. It will be retried.")
		} else {
			set.Notes = append(set.Notes,
				"Could not read run-attempt history, so jobs that failed to start and holds that have already ended are not included: "+eerr.Error())
		}
		return set, nil
	}
	if len(attempts) >= MaxRecords {
		set.Truncated = true
	}
	if epochSource != "" && epochSource != set.Source {
		set.Source = set.Source + " + " + epochSource
	}
	for _, ad := range attempts {
		if rec, ok := vacateRecord(ad); ok {
			set.Records = append(set.Records, rec)
		}
	}
	return set, nil
}

// holdRecord turns a held job's ad into one occurrence.
func holdRecord(ad *classad.ClassAd) Record {
	cluster, _ := ad.EvaluateAttrInt("ClusterId")
	proc, _ := ad.EvaluateAttrInt("ProcId")
	owner, _ := ad.EvaluateAttrString("Owner")
	batch, _ := ad.EvaluateAttrString("JobBatchName")
	reason, _ := ad.EvaluateAttrString("HoldReason")
	code, _ := ad.EvaluateAttrInt("HoldReasonCode")
	sub, _ := ad.EvaluateAttrInt("HoldReasonSubCode")
	at, _ := ad.EvaluateAttrInt("EnteredCurrentStatus")
	return Record{
		Kind: KindHold, Message: reason, Owner: owner,
		Cluster: cluster, Proc: proc, Batch: batch, At: at,
		Code: code, SubCode: sub, Facets: facetsOf(ad),
	}
}

// vacateRecord turns a run attempt into an occurrence, or reports that it
// was not a failure.
func vacateRecord(ad *classad.ClassAd) (Record, bool) {
	code, ok := ad.EvaluateAttrInt("VacateReasonCode")
	if !ok || benignVacateCodes[code] {
		return Record{}, false
	}
	cluster, _ := ad.EvaluateAttrInt("ClusterId")
	proc, _ := ad.EvaluateAttrInt("ProcId")
	owner, _ := ad.EvaluateAttrString("Owner")
	batch, _ := ad.EvaluateAttrString("JobBatchName")
	reason, _ := ad.EvaluateAttrString("VacateReason")
	sub, _ := ad.EvaluateAttrInt("VacateReasonSubCode")
	// When the attempt ended, falling back to when it started for a
	// record from a schedd too old to write the one we ask the window
	// in.
	at, ok := ad.EvaluateAttrInt(EpochTimeAttr)
	if !ok || at <= 0 {
		at, _ = ad.EvaluateAttrInt("JobCurrentStartDate")
	}

	kind := KindHold
	if code >= shadowSideCodeFloor {
		kind = KindRunFailure
	}
	return Record{
		Kind: kind, Message: reason, Owner: owner,
		Cluster: cluster, Proc: proc, Batch: batch, At: at,
		Code: code, SubCode: sub, Facets: facetsOf(ad),
	}, true
}
