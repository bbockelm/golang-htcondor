package htcondor

import (
	"context"
	"strings"
	"testing"
)

// submitProcAds parses raw and materializes its procs, the way
// Schedd.Submit and Schedd.SubmitRemote do before either stamps anything.
func submitProcAds(t *testing.T, raw string) *SubmitResult {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	result, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return result
}

// TestSubmitMethodUnstampedByDefault pins what a caller who says nothing
// gets: no JobSubmitMethod at all, which reads as "Unknown". This library
// is not condor_submit and has never claimed to be -- the differential
// test against condor_submit -dry-run masks this attribute for exactly
// that reason -- so acquiring a default here would be a behaviour change
// for every existing caller, not just a new feature for the API.
func TestSubmitMethodUnstampedByDefault(t *testing.T) {
	result := submitProcAds(t, "executable = /bin/true\nqueue 2\n")
	stampSubmitMethod(context.Background(), result)

	for i, ad := range result.ProcAds {
		if expr, ok := ad.Lookup(attrJobSubmitMethod); ok && expr != nil {
			t.Errorf("proc %d: %s = %v on a submission that named no method", i, attrJobSubmitMethod, expr)
		}
	}
}

// TestSubmitMethodStampsEveryProc checks the attribute lands on every job
// of the submission, not only the first. A site constraint written
// against it would otherwise match proc 0 and miss the other 999.
func TestSubmitMethodStampsEveryProc(t *testing.T) {
	result := submitProcAds(t, "executable = /bin/true\nqueue 3\n")
	stampSubmitMethod(WithSubmitMethod(context.Background(), SubmitMethodMCP), result)

	if len(result.ProcAds) != 3 {
		t.Fatalf("got %d procs, want 3", len(result.ProcAds))
	}
	for i, ad := range result.ProcAds {
		got, ok := ad.EvaluateAttrInt(attrJobSubmitMethod)
		if !ok {
			t.Errorf("proc %d: no %s", i, attrJobSubmitMethod)
			continue
		}
		if got != SubmitMethodMCP {
			t.Errorf("proc %d: %s = %d, want %d", i, attrJobSubmitMethod, got, SubmitMethodMCP)
		}
	}
	// A factory submission sends no proc ads and the schedd materializes
	// from the cluster ad, so that one has to carry it too.
	if got, ok := result.ClusterAd.EvaluateAttrInt(attrJobSubmitMethod); !ok || got != SubmitMethodMCP {
		t.Errorf("cluster ad: %s = %d (present %v), want %d", attrJobSubmitMethod, got, ok, SubmitMethodMCP)
	}
}

// TestSubmitMethodBeatsTheSubmitFile is the guarantee a site writing a
// SUBMIT_REQUIREMENT against this attribute depends on: a submit file
// cannot claim to be something else.
//
// `+JobSubmitMethod` is a custom attribute, and custom attributes are
// applied LAST inside MakeJobAd -- condor_submit's own ordering, so that
// they trump the submit commands. Stamping anywhere inside the ad build
// would therefore lose to this submit file. Stamping after it wins.
func TestSubmitMethodBeatsTheSubmitFile(t *testing.T) {
	// The submit file claims to be condor_submit, the most useful lie:
	// it is the value a policy keyed on "agents only" would be looking
	// for the absence of.
	result := submitProcAds(t, "executable = /bin/true\n+JobSubmitMethod = 0\nqueue 1\n")

	// Before the stamp, the submit file's claim is what the ad holds --
	// asserted so this test fails if the custom attribute ever stops
	// being applied, which would make the rest of it vacuous.
	if got, ok := result.ProcAds[0].EvaluateAttrInt(attrJobSubmitMethod); !ok || got != SubmitMethodCondorSubmit {
		t.Fatalf("precondition: submit file's %s = %d (present %v), want %d",
			attrJobSubmitMethod, got, ok, SubmitMethodCondorSubmit)
	}

	stampSubmitMethod(WithSubmitMethod(context.Background(), SubmitMethodMCP), result)

	if got, _ := result.ProcAds[0].EvaluateAttrInt(attrJobSubmitMethod); got != SubmitMethodMCP {
		t.Errorf("%s = %d, want %d: a submit file overrode the submitting service's identity",
			attrJobSubmitMethod, got, SubmitMethodMCP)
	}
}

// TestSubmitMethodSurfacesAreDistinct pins the two values this project
// claims. They are a published identity: a site's SUBMIT_REQUIREMENT and
// a pool's accounting are written against the numbers, so changing one
// silently reclassifies every job already in a queue.
func TestSubmitMethodSurfacesAreDistinct(t *testing.T) {
	if SubmitMethodRESTAPI == SubmitMethodMCP {
		t.Fatal("REST and MCP must be distinguishable; that is the whole point of stamping them")
	}
	for name, v := range map[string]int{
		"SubmitMethodRESTAPI": SubmitMethodRESTAPI,
		"SubmitMethodMCP":     SubmitMethodMCP,
	} {
		if v <= SubmitMethodPortal {
			t.Errorf("%s = %d: must be above %d, the band HTCondor reserves for portals",
				name, v, SubmitMethodPortal)
		}
	}
}

// TestWithSubmitMethodUnsetIsANoop keeps "no method" expressible, so a
// caller that computes one can pass the absence along without a branch.
func TestWithSubmitMethodUnsetIsANoop(t *testing.T) {
	ctx := WithSubmitMethod(context.Background(), SubmitMethodUnset)
	if got := SubmitMethodFromContext(ctx); got != SubmitMethodUnset {
		t.Errorf("SubmitMethodFromContext = %d, want %d", got, SubmitMethodUnset)
	}
	// And the innermost call wins, which is what lets the MCP door
	// override the REST door for a tool call arriving over HTTP.
	ctx = WithSubmitMethod(WithSubmitMethod(context.Background(), SubmitMethodRESTAPI), SubmitMethodMCP)
	if got := SubmitMethodFromContext(ctx); got != SubmitMethodMCP {
		t.Errorf("SubmitMethodFromContext = %d, want %d", got, SubmitMethodMCP)
	}
}
