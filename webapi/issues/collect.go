package issues

import (
	"context"
	"fmt"
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
	"JobCurrentStartDate", "NumShadowExceptions",
}, facetAttrs...)

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

// facetsOf reads the where-it-ran attributes off an ad.
//
// Resource has two spellings: MachineAttrGLIDEIN_ResourceName0 is what
// the startd advertised and MATCH_EXP_JOBGLIDEIN_ResourceName is what the
// match expression evaluated to. They agree where both are present; the
// second is the fallback because some pilots set only it.
func facetsOf(ad *classad.ClassAd) map[string]string {
	facets := map[string]string{}
	if v, ok := ad.EvaluateAttrString("MachineAttrGLIDEIN_ResourceName0"); ok && v != "" {
		facets["resource"] = v
	} else if v, ok := ad.EvaluateAttrString("MATCH_EXP_JOBGLIDEIN_ResourceName"); ok && v != "" {
		facets["resource"] = v
	}
	if v, ok := ad.EvaluateAttrString("MachineAttrGLIDEIN_Site0"); ok && v != "" {
		facets["site"] = v
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
	Truncated  bool
	ComputedAt time.Time
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
	holdConstraint := fmt.Sprintf("(%s) && JobStatus == 5 && EnteredCurrentStatus >= %d", scope, since)
	held, heldSource, err := src.JobAds(ctx, holdConstraint, HoldProjection, MaxRecords)
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
	epochConstraint := fmt.Sprintf(
		"(%s) && VacateReasonCode isnt undefined && JobCurrentStartDate >= %d", scope, since)
	attempts, epochSource, eerr := src.EpochAds(ctx, epochConstraint, EpochProjection, MaxRecords)
	if eerr != nil {
		// A missing epoch history is a configuration fact, not an error:
		// JOB_EPOCH_HISTORY is off by default. Say so and show the rest
		// rather than failing whole.
		set.Notes = append(set.Notes,
			"Could not read run-attempt history, so jobs that failed to start and holds that have already ended are not included: "+eerr.Error())
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
	at, _ := ad.EvaluateAttrInt("JobCurrentStartDate")

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
