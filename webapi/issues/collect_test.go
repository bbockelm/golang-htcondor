package issues

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// fakeSource answers from fixtures and records what it was asked, so the
// tests can assert on the constraint the collector builds -- the window
// predicate is the difference between "what is going wrong now" and "the
// backlog since March".
type fakeSource struct {
	jobs, epochs         []*classad.ClassAd
	jobErr, epochErr     error
	jobQuery, epochQuery string
	jobLimit, epochLimit int
}

func (f *fakeSource) JobAds(_ context.Context, constraint string, _ []string, limit int) ([]*classad.ClassAd, string, error) {
	f.jobQuery, f.jobLimit = constraint, limit
	return f.jobs, "fake-queue", f.jobErr
}

func (f *fakeSource) EpochAds(_ context.Context, constraint string, _ []string, limit int) ([]*classad.ClassAd, string, error) {
	f.epochQuery, f.epochLimit = constraint, limit
	return f.epochs, "fake-epochs", f.epochErr
}

func ad(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	a, err := classad.Parse(text)
	if err != nil {
		t.Fatalf("parsing %q: %v", text, err)
	}
	return a
}

func heldAd(t *testing.T, cluster int, owner, reason string, code, sub int64) *classad.ClassAd {
	// Inside the window every caller uses; the window itself is what the
	// query tests vary.
	const at = 900
	return ad(t, fmt.Sprintf(`[ ClusterId = %d; ProcId = 0; Owner = %q; HoldReason = %q; HoldReasonCode = %d; HoldReasonSubCode = %d; EnteredCurrentStatus = %d ]`,
		cluster, owner, reason, code, sub, at))
}

func vacatedAd(t *testing.T, cluster int, owner, reason string, code int64) *classad.ClassAd {
	return ad(t, fmt.Sprintf(`[ ClusterId = %d; ProcId = 0; Owner = %q; VacateReason = %q; VacateReasonCode = %d; JobCurrentStartDate = 500 ]`,
		cluster, owner, reason, code))
}

func TestCollectConfinesToScopeAndWindow(t *testing.T) {
	src := &fakeSource{jobs: []*classad.ClassAd{heldAd(t, 1, "alice", "boom", 21, 102)}}
	now := time.Unix(10000, 0)
	_, err := Collect(context.Background(), src, Options{
		Scope:  `Owner == "alice"`,
		Window: time.Hour,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	// The scope is what stops one user's view from reading another's
	// jobs, and the window is what stops a standing backlog from
	// drowning out what is going wrong now. Both belong in the query
	// rather than in a filter applied afterwards.
	if !strings.Contains(src.jobQuery, `Owner == "alice"`) {
		t.Errorf("scope missing from query: %s", src.jobQuery)
	}
	if !strings.Contains(src.jobQuery, "EnteredCurrentStatus >= 6400") {
		t.Errorf("window missing from query: %s", src.jobQuery)
	}
	if !strings.Contains(src.jobQuery, "JobStatus == 5") {
		t.Errorf("hold predicate missing from query: %s", src.jobQuery)
	}
	if src.jobLimit != MaxRecords {
		t.Errorf("limit = %d, want the bound", src.jobLimit)
	}
}

func TestCollectLeavesEpochHistoryAloneUnlessAsked(t *testing.T) {
	// Reading run-attempt history is the expensive half, and on an
	// access point that does not keep it the read fails outright. It is
	// opt-in for both reasons.
	src := &fakeSource{}
	if _, err := Collect(context.Background(), src, Options{Window: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if src.epochQuery != "" {
		t.Errorf("epoch history was read without being asked: %s", src.epochQuery)
	}
}

func TestCollectReportsMissingEpochHistoryRatherThanFailing(t *testing.T) {
	// JOB_EPOCH_HISTORY is off by default. A view that returned an error
	// here would show nothing at all on a working access point, when it
	// has a perfectly good answer about what is held.
	src := &fakeSource{
		jobs:     []*classad.ClassAd{heldAd(t, 1, "alice", "boom", 21, 102)},
		epochErr: fmt.Errorf("no epoch history configured"),
	}
	set, err := Collect(context.Background(), src, Options{Window: time.Hour, IncludeEnded: true})
	if err != nil {
		t.Fatalf("collection failed instead of noting the gap: %v", err)
	}
	if len(set.Records) != 1 {
		t.Errorf("records = %d, want the hold to survive", len(set.Records))
	}
	if len(set.Notes) != 1 || !strings.Contains(set.Notes[0], "epoch") {
		t.Errorf("notes = %v, want one explaining the gap", set.Notes)
	}
}

func TestCollectSplitsRunFailuresFromHolds(t *testing.T) {
	// HTCondor's own hold codes are small numbers; the shadow-side
	// reasons a run ended without the job finishing are the 1000s. That
	// range is the line between the view's two sections.
	src := &fakeSource{epochs: []*classad.ClassAd{
		vacatedAd(t, 1, "alice", "memory usage exceeded request_memory", 21),
		vacatedAd(t, 2, "bob", "Failed to receive GoAhead message from 10.0.0.1.", 1007),
		vacatedAd(t, 3, "bob", "Job disconnected too long: JobLeaseDuration expired", 1008),
		vacatedAd(t, 4, "carol", "Cleaning up after job", 1028),
	}}
	set, err := Collect(context.Background(), src, Options{Window: time.Hour, IncludeEnded: true})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, r := range set.Records {
		kinds[r.Kind]++
	}
	if kinds[KindHold] != 1 {
		t.Errorf("hold-kind records = %d, want 1", kinds[KindHold])
	}
	if kinds[KindRunFailure] != 2 {
		t.Errorf("run-failure records = %d, want 2", kinds[KindRunFailure])
	}
	// "Cleaning up after job" is an ordinary completion. At the top of a
	// view titled Issues it would bury the things that did go wrong.
	if len(set.Records) != 3 {
		t.Errorf("records = %d, want the benign vacate dropped", len(set.Records))
	}
}

func TestCollectFlagsTruncation(t *testing.T) {
	// A count that is really a floor has to say so: the view's job is to
	// rank problems, and a rank computed from a truncated read is a
	// claim about what was read, not about the access point.
	many := make([]*classad.ClassAd, MaxRecords)
	for i := range many {
		many[i] = heldAd(t, i, "alice", "boom", 21, 102)
	}
	set, err := Collect(context.Background(), &fakeSource{jobs: many}, Options{Window: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !set.Truncated {
		t.Error("a full page of records was not reported as truncated")
	}
}

func TestLocalPoolIsNotAPlaceName(t *testing.T) {
	// A CHTC access point's own jobs: the machine advertises no glidein
	// attributes, so the submit-side match expression falls through to
	// its literal, which on those pools is "Local Job". Reported as-is,
	// every hold on a local pool claims to have happened somewhere
	// called "Local Job".
	local := ad(t, `[ ClusterId = 1; ProcId = 0; Owner = "alice"; HoldReason = "x"; HoldReasonCode = 21; MATCH_EXP_JOBGLIDEIN_ResourceName = "Local Job" ]`)
	got := holdRecord(local).Facets
	if got["resource"] != LocalPoolLabel {
		t.Errorf("resource = %q, want %q", got["resource"], LocalPoolLabel)
	}
	// And no site: there is no pilot, so there is no site, and inventing
	// one would be two badges saying the same thing.
	if _, ok := got["site"]; ok {
		t.Errorf("facets = %v, want no site for a local job", got)
	}
}

func TestSentinelsAreMatchedLoosely(t *testing.T) {
	// The fallback string lives in site configuration rather than in
	// HTCondor, so it is whatever somebody typed.
	for _, raw := range []string{"Local Job", "local job", "  Local Job  ", "Unknown", "undefined"} {
		a := ad(t, `[ ClusterId = 1; ProcId = 0; MATCH_EXP_JOBGLIDEIN_ResourceName = "`+raw+`" ]`)
		if got := holdRecord(a).Facets["resource"]; got != LocalPoolLabel {
			t.Errorf("%q -> %q, want %q", raw, got, LocalPoolLabel)
		}
	}
}

func TestTheMachinesOwnWordWinsOverTheMatchExpression(t *testing.T) {
	// Where a pilot did run, the startd's advertised name is the one to
	// use: the match expression is a submit-side reconstruction of it.
	a := ad(t, `[ ClusterId = 1; ProcId = 0; MachineAttrGLIDEIN_ResourceName0 = "Purdue-Anvil-CE1"; MATCH_EXP_JOBGLIDEIN_ResourceName = "Local Job"; MachineAttrGLIDEIN_Site0 = "Purdue-Anvil" ]`)
	facets := holdRecord(a).Facets
	if facets["resource"] != "Purdue-Anvil-CE1" {
		t.Errorf("resource = %q, want the startd's own name", facets["resource"])
	}
	if facets["site"] != "Purdue-Anvil" {
		t.Errorf("site = %q", facets["site"])
	}
}

func TestNoGlideinAttributesAtAllMeansNoFacets(t *testing.T) {
	// An access point whose ads carry none of these has no location to
	// report, and should not acquire one.
	a := ad(t, `[ ClusterId = 1; ProcId = 0; Owner = "alice" ]`)
	if got := holdRecord(a).Facets; got != nil {
		t.Errorf("facets = %v, want none", got)
	}
}

func TestEpochWindowUsesTheZoneMappedAttribute(t *testing.T) {
	// htcondordb zone-maps an epoch archive on EpochWriteDate and on
	// EnteredHistoryTime, and on nothing else. A range predicate over
	// any other attribute prunes no segments, so the read walks every
	// run attempt the access point has ever made in order to answer a
	// question about the last day.
	src := &fakeSource{}
	now := time.Unix(100000, 0)
	if _, err := Collect(context.Background(), src, Options{
		Window: time.Hour, IncludeEnded: true, Now: func() time.Time { return now },
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src.epochQuery, EpochTimeAttr+" >= 96400") {
		t.Errorf("epoch query = %q, want the window on %s", src.epochQuery, EpochTimeAttr)
	}
	if strings.Contains(src.epochQuery, "JobCurrentStartDate") {
		t.Errorf("epoch query = %q, still bounded on an attribute with no zone map", src.epochQuery)
	}
	// The existence test comes after the bound: it can prune nothing by
	// itself, so it must not be what the scan leads with.
	if i, j := strings.Index(src.epochQuery, EpochTimeAttr), strings.Index(src.epochQuery, "VacateReasonCode"); i > j {
		t.Errorf("epoch query = %q, want the prunable bound first", src.epochQuery)
	}
}

func TestRunFailureIsTimedWhenItEnded(t *testing.T) {
	// EpochWriteDate is written when the run instance ends, which is
	// when the failure happened; JobCurrentStartDate is when the attempt
	// that failed began. The timeline is drawn from this, so the choice
	// moves bars.
	a := ad(t, `[ ClusterId = 1; ProcId = 0; VacateReason = "x"; VacateReasonCode = 1007; EpochWriteDate = 500; JobCurrentStartDate = 100 ]`)
	rec, ok := vacateRecord(a)
	if !ok || rec.At != 500 {
		t.Errorf("At = %d, want the end of the attempt", rec.At)
	}

	// A schedd too old to write it still has to land somewhere on the
	// timeline rather than being dropped as untimed.
	old := ad(t, `[ ClusterId = 1; ProcId = 0; VacateReason = "x"; VacateReasonCode = 1007; JobCurrentStartDate = 100 ]`)
	rec, ok = vacateRecord(old)
	if !ok || rec.At != 100 {
		t.Errorf("At = %d, want the fallback", rec.At)
	}
}

// --- one job, one row -----------------------------------------------
//
// Reported from ap40: the page showed the same job twice under two
// different hold reasons, one of them blank. Three separate causes,
// each enough on its own.

func TestAJobHeldNowIsNotAlsoCountedFromItsRunInstance(t *testing.T) {
	// The live queue says this job is held; the run instance that got it
	// there is in epoch history saying the same thing a different way.
	// One problem, recorded twice by two sources.
	src := &fakeSource{
		jobs: []*classad.ClassAd{
			heldAd(t, 15799789, "derek", "Job credentials are not available", 4, 0),
		},
		epochs: []*classad.ClassAd{
			ad(t, `[ ClusterId = 15799789; ProcId = 0; Owner = "derek"; VacateReason = "Job credentials are not available"; VacateReasonCode = 4; EpochWriteDate = 900 ]`),
		},
	}
	set, err := Collect(context.Background(), src, Options{Window: time.Hour, IncludeEnded: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Records) != 1 {
		for _, r := range set.Records {
			t.Logf("  kind=%s code=%d msg=%q", r.Kind, r.Code, r.Message)
		}
		t.Fatalf("records = %d, want the job counted once", len(set.Records))
	}
	// The queue's version survives: it is the current state, where the
	// run instance is the attempt that produced it.
	if set.Records[0].Message != "Job credentials are not available" {
		t.Errorf("kept %+v, want the live hold", set.Records[0])
	}
}

func TestAHeldJobsEarlierRunFailureIsStillCounted(t *testing.T) {
	// Only the hold half is deduplicated. A job that is held now may
	// also have failed to keep running earlier in the window, and those
	// are different problems in different sections of the page.
	src := &fakeSource{
		jobs: []*classad.ClassAd{heldAd(t, 42, "alice", "held for a reason", 4, 0)},
		epochs: []*classad.ClassAd{
			ad(t, `[ ClusterId = 42; ProcId = 0; Owner = "alice"; VacateReason = "Failed to receive GoAhead message"; VacateReasonCode = 1007; EpochWriteDate = 800 ]`),
		},
	}
	set, err := Collect(context.Background(), src, Options{Window: time.Hour, IncludeEnded: true})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, r := range set.Records {
		kinds[r.Kind]++
	}
	if kinds[KindHold] != 1 || kinds[KindRunFailure] != 1 {
		t.Errorf("kinds = %v, want one of each", kinds)
	}
}

func TestOnlyTheRunInstanceAdTypeIsRead(t *testing.T) {
	// A run instance leaves several records behind and only one of them
	// is the run ending: EPOCH is the finished instance, SPAWN is
	// written at the start, and INPUT/OUTPUT/CHECKPOINT/COMMON are the
	// transfer records. An access point that configures those banners to
	// copy vacate attributes gets one failure reported as several rows.
	src := &fakeSource{}
	if _, err := Collect(context.Background(), src, Options{Window: time.Hour, IncludeEnded: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src.epochQuery, `EpochAdType == "EPOCH"`) {
		t.Errorf("epoch query = %q, want it confined to finished run instances", src.epochQuery)
	}
	// A schedd old enough not to write the attribute wrote only the one
	// kind, so those records must not be excluded.
	if !strings.Contains(src.epochQuery, "EpochAdType =?= undefined") {
		t.Errorf("epoch query = %q, want records without the attribute kept", src.epochQuery)
	}
}

func TestAVacateRecordWithNothingToSayIsDropped(t *testing.T) {
	// Code zero and no text is the absence of a vacate reason, not a
	// reason of "unspecified". Reported, it drew a row with a blank
	// message under a label that made it look like a distinct problem.
	silent := ad(t, `[ ClusterId = 1; ProcId = 0; Owner = "alice"; VacateReasonCode = 0; EpochWriteDate = 900 ]`)
	if _, ok := vacateRecord(silent); ok {
		t.Error("a vacate record with neither a reason nor a code was kept")
	}

	// Code zero WITH text is still something that happened.
	spoken := ad(t, `[ ClusterId = 1; ProcId = 0; Owner = "alice"; VacateReason = "something happened"; VacateReasonCode = 0; EpochWriteDate = 900 ]`)
	if rec, ok := vacateRecord(spoken); !ok || rec.Message != "something happened" {
		t.Errorf("record = %+v ok=%v, want it kept", rec, ok)
	}

	// And a code with no text is still informative -- the code names the
	// category even when nobody wrote a sentence.
	coded := ad(t, `[ ClusterId = 1; ProcId = 0; Owner = "alice"; VacateReasonCode = 1007; EpochWriteDate = 900 ]`)
	if _, ok := vacateRecord(coded); !ok {
		t.Error("a coded vacate record with no text was dropped")
	}
}
