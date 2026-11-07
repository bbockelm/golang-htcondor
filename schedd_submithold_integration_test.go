package htcondor

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// A submit file with `hold = true` must produce a job that is held and
// stays held. Before JobStatusOnRelease this silently produced a job
// that ran: the submitter's hold was overwritten by the spooling hold,
// and the schedd released that hold when the files arrived.
//
// An integration test rather than a unit test because the behaviour
// under test is the schedd's: whether it honours JobStatusOnRelease when
// it ends a spooling hold. A test of what this library writes into the
// ad would have passed against a schedd that ignored it.
func TestSubmitHoldStaysHeld(t *testing.T) {
	t.Parallel()
	harness := SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	loc := getScheddAddress(t, harness)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	schedd := NewSchedd(loc.Name, loc.Address)

	// transfer_executable = False means no input files, so SubmitRemote
	// does the empty spool itself -- the path that reproduced fastest,
	// because the release follows the submit immediately.
	cluster, _, err := schedd.SubmitRemote(ctx, `
universe = vanilla
executable = /bin/true
transfer_executable = False
output = held.out
error = held.err
log = held.log
hold = True
queue
`)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("submit: %v", err)
	}

	constraint := fmt.Sprintf("ClusterId == %d", cluster)
	projection := []string{
		"ClusterId", "ProcId", "JobStatus", "HoldReason", "HoldReasonCode",
		"NumJobStarts", "JobStatusOnRelease", "SubmitHoldReason",
	}

	// Watch for long enough to cover a negotiation cycle: the bug let
	// the job go idle and then run, and it ran within ten seconds.
	deadline := time.Now().Add(45 * time.Second)
	sawReason := false
	for time.Now().Before(deadline) {
		ads, qerr := schedd.Query(ctx, constraint, projection)
		if qerr != nil {
			t.Fatalf("query: %v", qerr)
		}
		if len(ads) == 0 {
			t.Fatal("the job left the queue; it should be sitting held")
		}
		ad := ads[0]

		status, _ := ad.EvaluateAttrInt("JobStatus")
		if status != jobStatusHeld {
			t.Fatalf("job is in status %d, not held (5): %s", status, ad.String())
		}
		// The sharpest statement of the bug: it is not enough that the
		// job is held now, it must never have started.
		if starts, ok := ad.EvaluateAttrInt("NumJobStarts"); ok && starts > 0 {
			t.Fatalf("the job started %d time(s) despite hold = true: %s", starts, ad.String())
		}

		if reason, ok := ad.EvaluateAttrString("HoldReason"); ok &&
			strings.Contains(reason, defaultSubmitHoldReason) {
			sawReason = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !sawReason {
		ads, _ := schedd.Query(ctx, constraint, projection)
		var got string
		if len(ads) > 0 {
			got = ads[0].String()
		}
		t.Errorf("the job is held but never got the submitter's hold reason: %s", got)
	}

	// Still held after the watch loop, and still never started.
	ads, err := schedd.Query(ctx, constraint, projection)
	if err != nil {
		t.Fatalf("final query: %v", err)
	}
	if len(ads) == 0 {
		t.Fatal("the job left the queue")
	}
	if status, _ := ads[0].EvaluateAttrInt("JobStatus"); status != jobStatusHeld {
		t.Errorf("job ended in status %d, not held: %s", status, ads[0].String())
	}
	if starts, ok := ads[0].EvaluateAttrInt("NumJobStarts"); ok && starts > 0 {
		t.Errorf("the job started despite hold = true: %s", ads[0].String())
	}

	// And it is a normal held job afterwards: releasing it works, which
	// it would not if the job were still carrying the spooling hold.
	if _, err := schedd.ReleaseJobs(ctx, constraint, "test release"); err != nil {
		t.Errorf("a job held this way could not be released: %v", err)
	}
}

// hold_reason from the submit file has to reach the finished job, or the
// hold says the wrong thing about why it is there.
func TestSubmitHoldKeepsTheSubmittersReason(t *testing.T) {
	t.Parallel()
	harness := SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	loc := getScheddAddress(t, harness)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	schedd := NewSchedd(loc.Name, loc.Address)

	const want = "waiting for the input dataset to land"
	cluster, _, err := schedd.SubmitRemote(ctx, fmt.Sprintf(`
universe = vanilla
executable = /bin/true
transfer_executable = False
output = held.out
error = held.err
log = held.log
hold = True
hold_reason = %s
queue
`, want))
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("submit: %v", err)
	}

	constraint := fmt.Sprintf("ClusterId == %d", cluster)
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		ads, qerr := schedd.Query(ctx, constraint, []string{"JobStatus", "HoldReason", "NumJobStarts"})
		if qerr != nil {
			t.Fatalf("query: %v", qerr)
		}
		if len(ads) == 0 {
			t.Fatal("the job left the queue")
		}
		if starts, ok := ads[0].EvaluateAttrInt("NumJobStarts"); ok && starts > 0 {
			t.Fatalf("the job started despite hold = true: %s", ads[0].String())
		}
		if reason, ok := ads[0].EvaluateAttrString("HoldReason"); ok && strings.Contains(reason, want) {
			return // held, for the reason the submitter gave
		}
		time.Sleep(500 * time.Millisecond)
	}
	ads, _ := schedd.Query(ctx, constraint, []string{"JobStatus", "HoldReason"})
	var got string
	if len(ads) > 0 {
		got = ads[0].String()
	}
	t.Errorf("the submitter's hold_reason never reached the job: %s", got)
}

// An ordinary submission must be untouched: no JobStatusOnRelease, no
// extra attribute, and no wait for a release that has nothing to restore.
func TestOrdinarySubmitIsUnaffected(t *testing.T) {
	t.Parallel()
	ad := classad.New()
	_ = ad.Set("JobStatus", int64(jobStatusIdle))
	_ = ad.Set("TransferExecutable", false)

	configureRemoteJobAd(ad, false)

	if _, ok := ad.Lookup(attrJobStatusOnRelease); ok {
		t.Errorf("a job that asked for no hold was given %s", attrJobStatusOnRelease)
	}
	if _, ok := ad.Lookup(attrSubmitHoldReason); ok {
		t.Errorf("a job that asked for no hold was given %s", attrSubmitHoldReason)
	}
	if len(groupHeldSubmissions([]*classad.ClassAd{ad})) != 0 {
		t.Error("an ordinary submission was treated as submitted-on-hold")
	}
}

// What configureRemoteJobAd does to a held submission, without needing a
// schedd: the spooling hold goes on, and the submitter's intent is
// recorded where the release cannot reach it.
func TestConfigureRemoteJobAdRecordsTheHold(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		holdReason string
		want       string
	}{
		{"default reason", "", defaultSubmitHoldReason},
		{"submitter's reason", "because I said so", "because I said so"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := classad.New()
			_ = ad.Set("JobStatus", int64(jobStatusHeld))
			if tc.holdReason != "" {
				_ = ad.Set("HoldReason", tc.holdReason)
			}
			configureRemoteJobAd(ad, false)

			// The spooling hold has to be what goes to the schedd, or
			// the job gets no spool directory and no Iwd.
			if code, _ := ad.EvaluateAttrInt("HoldReasonCode"); code != holdCodeSpoolingInput {
				t.Errorf("HoldReasonCode = %d, want %d", code, holdCodeSpoolingInput)
			}
			if status, _ := ad.EvaluateAttrInt("JobStatus"); status != jobStatusHeld {
				t.Errorf("JobStatus = %d, want %d", status, jobStatusHeld)
			}
			// And the release has to land on held, not idle.
			if on, ok := ad.EvaluateAttrInt(attrJobStatusOnRelease); !ok || on != jobStatusHeld {
				t.Errorf("%s = %d (present=%v), want %d", attrJobStatusOnRelease, on, ok, jobStatusHeld)
			}
			if got, _ := ad.EvaluateAttrString(attrSubmitHoldReason); got != tc.want {
				t.Errorf("%s = %q, want %q", attrSubmitHoldReason, got, tc.want)
			}

			_ = ad.Set("ClusterId", int64(7))
			_ = ad.Set("ProcId", int64(0))
			groups := groupHeldSubmissions([]*classad.ClassAd{ad})
			if len(groups) != 1 {
				t.Fatalf("groupHeldSubmissions found %d groups, want 1", len(groups))
			}
			if groups[0].reason != tc.want {
				t.Errorf("carried reason %q, want %q", groups[0].reason, tc.want)
			}
		})
	}
}

// A cluster's procs are released by one pass of the schedd's reaper, so
// they are held back in one call rather than one per job. Without the
// grouping, `queue 100` submitted on hold is a hundred waits and a
// hundred authenticated round trips.
func TestHeldSubmissionsGroupPerCluster(t *testing.T) {
	t.Parallel()
	mk := func(cluster, proc int, reason string) *classad.ClassAd {
		ad := classad.New()
		_ = ad.Set(attrJobStatusOnRelease, int64(jobStatusHeld))
		_ = ad.Set("ClusterId", int64(cluster))
		_ = ad.Set("ProcId", int64(proc))
		if reason != "" {
			_ = ad.Set(attrSubmitHoldReason, reason)
		}
		return ad
	}

	groups := groupHeldSubmissions([]*classad.ClassAd{
		mk(4, 0, "same"), mk(4, 1, "same"), mk(4, 2, "same"),
		mk(4, 3, "different"), // one proc given its own reason
		mk(9, 0, "same"),      // a second cluster
	})
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3 (cluster 4 x2 reasons, cluster 9): %+v", len(groups), groups)
	}

	// The constraint has to name the cluster, or it would also match a
	// job held by an earlier submission that used the same words.
	for _, g := range groups {
		c := g.constraint()
		if !strings.Contains(c, fmt.Sprintf("ClusterId == %d", g.cluster)) {
			t.Errorf("constraint %q is not scoped to cluster %d", c, g.cluster)
		}
	}

	// A reason with a quote in it must not break out of the constraint.
	evil := groupHeldSubmissions([]*classad.ClassAd{mk(1, 0, `he said "go" \ then`)})
	if len(evil) != 1 {
		t.Fatalf("got %d groups, want 1", len(evil))
	}
	if c := evil[0].constraint(); !strings.Contains(c, `\"go\"`) || !strings.Contains(c, `\\`) {
		t.Errorf("a quote in the reason was not escaped into the constraint: %s", c)
	}
}

// Several procs submitted on hold all end up held, with the reason, from
// one grouped restore.
func TestMultiProcSubmitHoldStaysHeld(t *testing.T) {
	t.Parallel()
	harness := SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	loc := getScheddAddress(t, harness)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	schedd := NewSchedd(loc.Name, loc.Address)

	const procs = 4
	cluster, procAds, err := schedd.SubmitRemote(ctx, fmt.Sprintf(`
universe = vanilla
executable = /bin/true
transfer_executable = False
output = held.$(ProcId).out
error = held.$(ProcId).err
log = held.log
hold = True
queue %d
`, procs))
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("submit: %v", err)
	}
	if len(procAds) != procs {
		t.Fatalf("submitted %d procs, want %d", len(procAds), procs)
	}

	constraint := fmt.Sprintf("ClusterId == %d", cluster)
	projection := []string{"ClusterId", "ProcId", "JobStatus", "HoldReason", "NumJobStarts"}

	deadline := time.Now().Add(45 * time.Second)
	for {
		ads, qerr := schedd.Query(ctx, constraint, projection)
		if qerr != nil {
			t.Fatalf("query: %v", qerr)
		}
		if len(ads) != procs {
			t.Fatalf("found %d jobs, want %d", len(ads), procs)
		}
		withReason := 0
		for _, ad := range ads {
			if status, _ := ad.EvaluateAttrInt("JobStatus"); status != jobStatusHeld {
				t.Fatalf("a job is in status %d, not held: %s", status, ad.String())
			}
			if starts, ok := ad.EvaluateAttrInt("NumJobStarts"); ok && starts > 0 {
				t.Fatalf("a job started despite hold = true: %s", ad.String())
			}
			if reason, ok := ad.EvaluateAttrString("HoldReason"); ok &&
				strings.Contains(reason, defaultSubmitHoldReason) {
				withReason++
			}
		}
		if withReason == procs {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d jobs got the submitter's hold reason", withReason, procs)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// SubmittedOnHold has to answer correctly at both points in a job's
// life, because its two callers ask at different times: the submit tool
// asks while the job is still spooling, and anything reading a job back
// later asks after the release has consumed JobStatusOnRelease.
func TestSubmittedOnHold(t *testing.T) {
	t.Parallel()
	spooling := classad.New()
	_ = spooling.Set(attrJobStatusOnRelease, int64(jobStatusHeld))

	released := classad.New()
	_ = released.Set(attrSubmitHoldReason, defaultSubmitHoldReason)

	ordinary := classad.New()
	_ = ordinary.Set("JobStatus", int64(jobStatusIdle))

	// A grid job the gridmanager has marked for removal on release is
	// not a held submission, and must not be read as one.
	gridRemoval := classad.New()
	_ = gridRemoval.Set(attrJobStatusOnRelease, int64(jobStatusRemoved))

	for _, tc := range []struct {
		name string
		ad   *classad.ClassAd
		want bool
	}{
		{"still spooling", spooling, true},
		{"after the release", released, true},
		{"ordinary submission", ordinary, false},
		{"grid removal-on-release", gridRemoval, false},
		{"no ad at all", nil, false},
	} {
		if got := SubmittedOnHold(tc.ad); got != tc.want {
			t.Errorf("%s: SubmittedOnHold = %v, want %v", tc.name, got, tc.want)
		}
	}
}
