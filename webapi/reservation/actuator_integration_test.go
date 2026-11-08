//go:build integration

package reservation_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/reservation"
)

// The reservation only works if the sieve really governs a real startd.
// Everything else in this package can be checked against ClassAds it
// wrote itself; this cannot. The whole mechanism is three claims:
//
//   - a held machine refuses a job with no estimate on it;
//   - it admits one whose estimate fits before the bell;
//   - it admits the reservation's own project whatever the estimate;
//
// and a released machine goes back to admitting everything.
//
// A job that does not start is indistinguishable from a job that has
// not started yet, so each negative is held open for long enough that a
// pool which would have run it has had several negotiation cycles to do
// so, and is paired with a positive on the same pool at the same time.
// Without the pairing a broken test harness reads as a working sieve.

const seatProject = "cs301"

// reservedHarness runs a pool whose execute points carry the stanza, so
// the sieve governs them, and negotiates often enough that a test does
// not spend its life waiting for a cycle.
func reservedHarness(t *testing.T) (*htcondor.CondorTestHarness, *htcondor.Collector) {
	t.Helper()
	cfg := "NUM_CPUS = 4\nMEMORY = 4096\n" +
		"SEC_ENABLE_REMOTE_ADMINISTRATION = True\n" +
		reservation.StartStanza + "\n" +
		"NEGOTIATOR_INTERVAL = 5\nNEGOTIATOR_CYCLE_DELAY = 5\n" +
		"SCHEDD_INTERVAL = 5\nUPDATE_INTERVAL = 5\n"
	return harness(t, cfg)
}

// submitSleep submits a short sleeping job carrying extra job-ad
// attributes, and returns its cluster id.
func submitSleep(t *testing.T, h *htcondor.CondorTestHarness, extra map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("executable = /bin/sleep\narguments = 300\nuniverse = vanilla\n")
	b.WriteString("request_cpus = 1\nrequest_memory = 128\nshould_transfer_files = no\n")
	for k, v := range extra {
		fmt.Fprintf(&b, "%s = %s\n", k, v)
	}
	b.WriteString("output = " + filepath.Join(dir, "out") + "\n")
	b.WriteString("error = " + filepath.Join(dir, "err") + "\n")
	b.WriteString("log = " + filepath.Join(dir, "log") + "\nqueue\n")

	path := filepath.Join(dir, "job.sub")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("writing the submit file: %v", err)
	}
	//nolint:gosec,noctx // G204: fixed command in a test
	cmd := exec.Command("condor_submit", "-terse", path)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("condor_submit: %v\n%s", err, out)
	}
	// -terse prints "first - last", e.g. "12.0 - 12.0".
	id := strings.TrimSpace(string(out))
	if i := strings.IndexByte(id, '.'); i > 0 {
		id = id[:i]
	}
	return id
}

// running reports whether a cluster has a job executing.
func running(t *testing.T, h *htcondor.CondorTestHarness, cluster string) bool {
	t.Helper()
	//nolint:gosec,noctx // G204: fixed command in a test
	cmd := exec.Command("condor_q", cluster, "-af", "JobStatus")
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("condor_q: %v\n%s", err, out)
	}
	for _, line := range strings.Fields(string(out)) {
		if line == "2" { // Running
			return true
		}
	}
	return false
}

// waitRunning waits for a cluster to start, and reports whether it did.
func waitRunning(t *testing.T, h *htcondor.CondorTestHarness, cluster string, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if running(t, h, cluster) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
}

func actuatorFor(t *testing.T, coll *htcondor.Collector) *reservation.PoolActuator {
	t.Helper()
	return &reservation.PoolActuator{
		Query: coll,
		// The whole point is that the execute point's own
		// authorization lists are not involved, so a run that silently
		// fell back to this process's credentials would be testing
		// something else.
		RequireCapability: true,
	}
}

func machineName(t *testing.T, coll *htcondor.Collector) string {
	t.Helper()
	machines := waitForSlots(t, coll)
	if len(machines) == 0 {
		t.Fatal("no machines")
	}
	return machines[0].Name
}

// TestSieveGovernsARealStartd is the end-to-end claim: on a held
// machine, an unstamped job does not run and a short stamped one does,
// at the same time on the same pool.
func TestSieveGovernsARealStartd(t *testing.T) {
	h, coll := reservedHarness(t)
	machine := machineName(t, coll)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	act := actuatorFor(t, coll)
	bell := time.Now().Add(time.Hour)
	if err := act.Hold(ctx, reservation.HoldRequest{
		Machine: machine, Deadline: bell, Until: bell.Add(time.Hour), Project: seatProject,
	}); err != nil {
		t.Fatalf("Hold: %v", err)
	}

	// Both are submitted before either is waited on, so they compete
	// for the same pool at the same moment.
	unstamped := submitSleep(t, h, nil)
	stamped := submitSleep(t, h, map[string]string{
		"+" + reservation.AttrBucket: "1800",
	})

	if !waitRunning(t, h, stamped, 150*time.Second) {
		t.Fatalf("a job estimated to finish well before the bell never ran on a held machine; the sieve is refusing everything")
	}
	// The negative is checked only after the positive has run, so the
	// pool has demonstrably been matching during the window.
	if running(t, h, unstamped) {
		t.Errorf("a job with no estimate ran on a held machine")
	}
}

// TestSieveAdmitsTheReservationsOwnProject: the seats exist to be used.
// A job of the reserved project is admitted whether or not anything has
// estimated it.
func TestSieveAdmitsTheReservationsOwnProject(t *testing.T) {
	h, coll := reservedHarness(t)
	machine := machineName(t, coll)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	act := actuatorFor(t, coll)
	// Deadline already past and the window open: the machine is the
	// project's, and nothing else is admitted on an estimate.
	if err := act.Hold(ctx, reservation.HoldRequest{
		Machine:  machine,
		Deadline: time.Now().Add(-time.Minute),
		Until:    time.Now().Add(time.Hour),
		Project:  seatProject,
	}); err != nil {
		t.Fatalf("Hold: %v", err)
	}

	seat := submitSleep(t, h, map[string]string{"+ProjectName": `"` + seatProject + `"`})
	other := submitSleep(t, h, map[string]string{"+" + reservation.AttrBucket: "1800"})

	if !waitRunning(t, h, seat, 150*time.Second) {
		t.Fatalf("the reservation's own job did not run on its own machine")
	}
	if running(t, h, other) {
		t.Errorf("a short job of another project ran during the window")
	}
}

// TestReleaseGivesTheMachineBack: nothing can be deleted from a machine
// ad, so release writes values that stop constraining anything. If that
// did not work, a machine held once would be held until the startd
// restarted.
func TestReleaseGivesTheMachineBack(t *testing.T) {
	h, coll := reservedHarness(t)
	machine := machineName(t, coll)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	act := actuatorFor(t, coll)
	bell := time.Now().Add(time.Hour)
	if err := act.Hold(ctx, reservation.HoldRequest{
		Machine: machine, Deadline: bell, Until: bell.Add(time.Hour), Project: seatProject,
	}); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	// Read back from the pool, not remembered: this is what the
	// controller does every tick. It goes through the collector, so it
	// lags the push by one update however promptly the startd answered.
	if !waitHeld(t, coll, machine, true, 60*time.Second) {
		t.Fatalf("HeldPool never reported %s as held after a push", machine)
	}

	unstamped := submitSleep(t, h, nil)
	if waitRunning(t, h, unstamped, 45*time.Second) {
		t.Fatalf("an unstamped job ran on a held machine")
	}

	if err := act.Release(ctx, machine); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !waitRunning(t, h, unstamped, 150*time.Second) {
		t.Errorf("the job never ran after the machine was released")
	}

	if !waitHeld(t, coll, machine, false, 60*time.Second) {
		t.Errorf("HeldPool still reports %s as held after a release", machine)
	}
}

// waitHeld polls HeldPool until a machine is (or is not) held. The read
// goes through the collector, so it trails a push by one update.
func waitHeld(t *testing.T, coll *htcondor.Collector, machine string, want bool, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		held, err := reservation.HeldPool(context.Background(), coll, "", time.Now())
		if err != nil {
			t.Fatalf("HeldPool: %v", err)
		}
		if _, ok := held[machine]; ok == want {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
}

// TestEvictVacatesByName: the startd vacates a claim by the slot ad's
// Name, which is the name the census has to carry for an eviction to be
// possible at all.
func TestEvictVacatesByName(t *testing.T) {
	h, coll := reservedHarness(t)
	waitForSlots(t, coll)

	cluster := submitSleep(t, h, map[string]string{"+" + reservation.AttrBucket: "1800"})
	if !waitRunning(t, h, cluster, 150*time.Second) {
		t.Fatalf("the job never ran, so there is nothing to vacate")
	}

	// Find the d-slot it is running on, by name.
	var machine, slot string
	deadline := time.Now().Add(60 * time.Second)
	for machine == "" {
		machines, err := reservation.Census(context.Background(), coll, "")
		if err != nil {
			t.Fatalf("census: %v", err)
		}
		for _, m := range machines {
			for _, d := range m.Dslots {
				if d.Started.IsZero() {
					continue
				}
				machine, slot = m.Name, d.Slot
			}
		}
		if machine == "" && time.Now().After(deadline) {
			t.Fatal("no running d-slot appeared in the census")
		}
		if machine == "" {
			time.Sleep(2 * time.Second)
		}
	}
	if slot == "" {
		t.Fatalf("the census found a running d-slot on %s with no slot name, so it cannot be vacated", machine)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	act := actuatorFor(t, coll)
	if err := act.Evict(ctx, reservation.EvictRequest{Machine: machine, Slot: slot}); err != nil {
		t.Fatalf("Evict %s: %v", slot, err)
	}

	// The startd answers a vacate with nothing, so the only evidence is
	// the job leaving the slot.
	stopped := time.Now().Add(120 * time.Second)
	for {
		if !running(t, h, cluster) {
			return
		}
		if time.Now().After(stopped) {
			t.Fatalf("the job on %s was still running two minutes after it was vacated", slot)
		}
		time.Sleep(2 * time.Second)
	}
}
