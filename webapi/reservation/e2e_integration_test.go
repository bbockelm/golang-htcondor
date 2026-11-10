//go:build integration

package reservation_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/startd"
	"github.com/bbockelm/golang-htcondor/webapi/reservation"
)

// The reservation subsystem rests on a handful of claims about what
// HTCondor actually publishes. Every one of them is cheap to get wrong
// against synthetic ClassAds and expensive to get wrong in production:
//
//   - the slot ad carries START as an expression, not as the true/false
//     it evaluates to (composing against "false" wedges a machine for
//     the life of the startd, irreversibly);
//   - a running job's start time is JobStart on the slot ad, not
//     JobStartDate, which belongs to the job ad (reading the wrong one
//     makes every job look brand new and the whole pool look free);
//   - a machine ad reports Memory in MiB and Disk in KiB.
//
// These tests check them against a real condor rather than against ads
// this package wrote itself.

func harness(t *testing.T, extra string) (*htcondor.CondorTestHarness, *htcondor.Collector) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH")
	}
	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	if err := h.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	return h, htcondor.NewCollector(h.GetCollectorAddr())
}

// waitForSlots polls until the startd has advertised, so a slow collector
// update is not read as an empty pool.
func waitForSlots(t *testing.T, coll *htcondor.Collector) []reservation.Machine {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		machines, err := reservation.Census(context.Background(), coll, "")
		if err == nil && len(machines) > 0 {
			return machines
		}
		if time.Now().After(deadline) {
			t.Fatalf("no slots advertised within the deadline (last error: %v)", err)
		}
		time.Sleep(time.Second)
	}
}

// TestCensusReadsARealPool: the census returns the machine with real
// capacity, in the units Resources expects.
func TestCensusReadsARealPool(t *testing.T) {
	_, coll := harness(t, "NUM_CPUS = 4\nMEMORY = 2048\n")
	machines := waitForSlots(t, coll)

	var total reservation.Resources
	for _, m := range machines {
		total.Cpus += m.Free.Cpus
		total.MemoryMB += m.Free.MemoryMB
		for _, d := range m.Dslots {
			total.Cpus += d.Res.Cpus
			total.MemoryMB += d.Res.MemoryMB
		}
	}
	if total.Cpus < 1 {
		t.Errorf("census found %d CPUs across %d machines, want at least 1", total.Cpus, len(machines))
	}
	// Memory is MiB in a machine ad. If it were read as bytes or KiB the
	// number would be absurd rather than merely wrong, so this catches
	// the unit rather than the exact value the startd chose.
	if total.MemoryMB < 64 || total.MemoryMB > 1<<20 {
		t.Errorf("census read %d MB of memory, which is not a plausible MiB reading", total.MemoryMB)
	}
}

// TestStartIsReadAsAnExpression is the claim the whole provisioning path
// rests on. A slot ad's START evaluates to true or false; the prober
// must see the text.
func TestStartIsReadAsAnExpression(t *testing.T) {
	// A START the site could plausibly write, distinctive enough to find
	// in the text and not something that evaluates to a bare boolean.
	const siteStart = `START = (TARGET.ReservationE2EMarker =?= true)`
	_, coll := harness(t, siteStart+"\n")
	waitForSlots(t, coll)

	src := reservation.CollectorStarts{Query: coll}
	starts, err := src.Starts(context.Background())
	if err != nil {
		t.Fatalf("Starts: %v", err)
	}
	if len(starts) == 0 {
		t.Fatal("no execute point reported a START")
	}
	for machine, expr := range starts {
		if expr == "true" || expr == "false" || expr == "True" || expr == "False" {
			t.Fatalf("%s reported START as the evaluated %q, not an expression: composing against that would wedge the machine", machine, expr)
		}
		if !strings.Contains(expr, "ReservationE2EMarker") {
			t.Errorf("%s reported START as %q, which does not contain the site's own expression", machine, expr)
		}
		// And the provisioning decision follows from it: this execute
		// point has a START of its own and does not consult the sieve,
		// so a reservation would hold it to no effect.
		if reservation.Provisioned(expr) {
			t.Errorf("%s: a START with no reservation clause read as provisioned: %q", machine, expr)
		}
	}
}

// TestStartCannotBePushed is why the stanza has to be in the execute
// point's configuration rather than installed by the access point.
//
// A startd republishes START from its own configuration every time it
// refreshes its ad, so an attribute named START merged into the machine
// ad is overwritten within seconds. Nothing reports a failure: the push
// is accepted, the other attributes in it stick, and the machine goes
// on admitting everything while a controller counts it as held.
//
// If this ever stops being true -- if a pushed START survives -- the
// access point could provision execute points itself, and this test is
// where that is noticed.
func TestStartCannotBePushed(t *testing.T) {
	const siteStart = `START = (TARGET.ReservationE2EMarker =?= true)`
	_, coll := harness(t, siteStart+"\nSEC_ENABLE_REMOTE_ADMINISTRATION = True\n")
	waitForSlots(t, coll)

	ads, _, err := coll.QueryAdsWithOptions(context.Background(), "StartdAd", "", &htcondor.QueryOptions{
		Limit: 100, Projection: []string{"*"}, PrivateAttributes: true,
	})
	if err != nil {
		t.Fatalf("querying slots: %v", err)
	}
	var withCap *classad.ClassAd
	for _, ad := range ads {
		if v, ok := ad.EvaluateAttrString(startd.AdminCapabilityAttr); ok && v != "" {
			withCap = ad
			break
		}
	}
	if withCap == nil {
		t.Fatal("no slot ad carried an administrative capability")
	}
	admin, err := startd.NewAdminFromAd(withCap, true, nil)
	if err != nil {
		t.Fatalf("NewAdminFromAd: %v", err)
	}

	// Push a START alongside an operand, so a push that did nothing at
	// all is distinguishable from one that landed everything but START.
	update := classad.New()
	_ = update.Set("ReservationE2EPushedMarker", int64(99))
	pushed, err := classad.ParseExpr(`(TARGET.ReservationE2EMarker =?= true) && ( ReservationStart ?: True )`)
	if err != nil {
		t.Fatalf("parsing the START to push: %v", err)
	}
	update.InsertExpr("START", pushed)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := admin.UpdateMachineAd(ctx, update); err != nil {
		t.Fatalf("UpdateMachineAd: %v", err)
	}

	machine, _ := withCap.EvaluateAttrString("Machine")
	deadline := time.Now().Add(45 * time.Second)
	var landed bool
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		fresh, _, qerr := coll.QueryAdsWithOptions(context.Background(), "StartdAd", "", &htcondor.QueryOptions{
			Limit: 100, Projection: []string{"*"},
		})
		if qerr != nil {
			t.Fatalf("re-querying slots: %v", qerr)
		}
		for _, ad := range fresh {
			if m, _ := ad.EvaluateAttrString("Machine"); m != machine {
				continue
			}
			if v, ok := ad.EvaluateAttrInt("ReservationE2EPushedMarker"); ok && v == 99 {
				landed = true
			}
			if e, ok := ad.Lookup("START"); ok && e != nil && reservation.Provisioned(e.String()) {
				t.Fatalf("a pushed START survived on %s (%s); the access point could provision execute points itself and this package should be changed to do so", machine, e)
			}
		}
	}
	if !landed {
		t.Fatal("the push never reached the slot ad at all, so this test proved nothing about START")
	}
}

// TestRunningJobAppearsAsADslotWithAnAge checks the attribute that
// decides every eviction: a running job's age must come from the slot
// ad's JobStart. Reading JobStartDate instead would leave Started zero
// and make the whole pool look free to evict.
func TestRunningJobAppearsAsADslotWithAnAge(t *testing.T) {
	h, coll := harness(t, "NUM_CPUS = 2\n")
	waitForSlots(t, coll)

	// Submitted with condor_submit rather than the library's own submit
	// path: this test is about what the startd publishes once something
	// is running on it, so the job has to really run.
	dir := t.TempDir()
	submit := filepath.Join(dir, "sleep.sub")
	body := "executable = /bin/sleep\narguments = 600\nuniverse = vanilla\n" +
		"request_cpus = 1\nshould_transfer_files = no\n" +
		"output = " + filepath.Join(dir, "out") + "\nerror = " + filepath.Join(dir, "err") +
		"\nlog = " + filepath.Join(dir, "log") + "\nqueue\n"
	if err := os.WriteFile(submit, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the submit file: %v", err)
	}
	//nolint:gosec,noctx // G204: fixed command in a test; the test does not need cancellation
	cmd := exec.Command("condor_submit", submit)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("condor_submit: %v\n%s", err, out)
	}

	deadline := time.Now().Add(120 * time.Second)
	for {
		machines, err := reservation.Census(context.Background(), coll, "")
		if err != nil {
			t.Fatalf("census: %v", err)
		}
		for _, m := range machines {
			for _, d := range m.Dslots {
				if d.Started.IsZero() {
					continue
				}
				age := time.Since(d.Started)
				if age < 0 || age > time.Hour {
					t.Fatalf("%s: a job that just started has an age of %v, so JobStart was misread", m.Name, age)
				}
				return // found a running job with a plausible age
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no dynamic slot with a start time appeared; either the job never ran or JobStart was not read")
		}
		time.Sleep(2 * time.Second)
	}
}

// TestTheConstraintReachesTheCollector: a site that limits reservations
// to a subset of its pool must actually get that subset.
func TestTheConstraintReachesTheCollector(t *testing.T) {
	_, coll := harness(t, "STARTD_ATTRS = $(STARTD_ATTRS) ReservationE2ETeaching\nReservationE2ETeaching = true\n")
	waitForSlots(t, coll)

	matching, err := reservation.Census(context.Background(), coll, "ReservationE2ETeaching =?= true")
	if err != nil {
		t.Fatalf("census with a matching constraint: %v", err)
	}
	if len(matching) == 0 {
		t.Error("the constraint excluded an execute point that advertises the attribute")
	}
	none, err := reservation.Census(context.Background(), coll, "ReservationE2ETeaching =?= false")
	if err != nil {
		t.Fatalf("census with a non-matching constraint: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("a constraint matching nothing returned %d machines, so it never reached the collector", len(none))
	}
}
