//go:build integration

package htcondor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Whether the schedd really holds a persistent claim, and whether
// anything can run on it, are properties of the schedd rather than of
// the request. They cannot be checked against ads this package wrote
// itself, so these run against a real pool.
//
// The pool is deliberately two cpus wide, and both are taken before any
// question is asked: one by a job, one by the claim. On a pool with
// nothing spare, "did the job run" has exactly one meaning, because the
// claim is the only place it could have run. Every earlier shape of
// this test was confounded by spare capacity -- the negotiator simply
// handed the job a fresh slot, and the claim read as having refused it.

// ocuPoolCpus is the width of the harness pool. Two: one for the job
// that creates the user record a claim hangs off, one for the claim.
const ocuPoolCpus = 2

// ocuHarness runs a pool that negotiates often enough for a test not to
// spend its life waiting for a cycle, and makes the test's own user an
// OCU super user so the create command is not refused before it is
// tried.
func ocuHarness(t *testing.T) (*CondorTestHarness, *Schedd, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH")
	}
	me, err := user.Current()
	if err != nil {
		t.Fatalf("looking up the current user: %v", err)
	}

	cfg := fmt.Sprintf("NUM_CPUS = %d\nMEMORY = 2048\nDISK = 4096000\n", ocuPoolCpus) +
		"NEGOTIATOR_INTERVAL = 5\nNEGOTIATOR_CYCLE_DELAY = 5\n" +
		"SCHEDD_INTERVAL = 5\nUPDATE_INTERVAL = 5\n" +
		"OCU_SUPER_USERS = " + me.Username + "\n"

	h := SetupCondorHarnessWithConfig(t, cfg)
	if err := h.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	loc := getScheddAddress(t, h)
	return h, NewSchedd(loc.Name, loc.Address), me.Username
}

// ocuSubmit submits one sleeping job with extra attributes and returns
// its cluster id.
func ocuSubmit(t *testing.T, h *CondorTestHarness, extra map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("executable = /bin/sleep\narguments = 900\nuniverse = vanilla\n")
	b.WriteString("request_cpus = 1\nrequest_memory = 128\nrequest_disk = 1024\n")
	b.WriteString("should_transfer_files = no\n")
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
	id := strings.TrimSpace(string(out))
	if i := strings.IndexByte(id, '.'); i > 0 {
		id = id[:i]
	}
	return id
}

// ocuRequestAd is the shape every claim in these tests asks for.
func ocuRequestAd() *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("RequestCpus", int64(1))
	_ = ad.Set("RequestMemory", int64(128))
	_ = ad.Set("RequestDisk", int64(1024))
	return ad
}

// ocuFreeCpus is how many cpus the partitionable slots still have to
// give out. Zero means nothing new can start anywhere in this pool.
func ocuFreeCpus(t *testing.T, h *CondorTestHarness) int {
	t.Helper()
	//nolint:gosec,noctx // G204: fixed command in a test
	cmd := exec.Command("condor_status", "-constraint", "PartitionableSlot", "-af", "Cpus")
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("condor_status: %v\n%s", err, out)
		return -1
	}
	total := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "undefined" {
			continue
		}
		n, err := strconv.Atoi(line)
		if err != nil {
			t.Logf("unreadable Cpus %q from the partitionable slot", line)
			continue
		}
		total += n
	}
	return total
}

// ocuClaimSlot returns the dynamic slot a claim is holding, or "".
//
// The discriminator is Claimed/Idle **with no RemoteOwner**. A slot
// running a job carries its owner, and carries it from the moment the
// schedd claims it -- so Claimed/Idle alone catches whichever job
// happens to be starting. A slot held by a persistent claim carries
// nobody, because nothing is running there and nothing ever will be
// until a job is placed on it.
//
// Reading the claim rather than counting free cpus matters: the
// collector's view of the partitionable slot lags the startd by an
// update interval, so "no cpus free" is briefly true before the claim
// has actually taken one, and a test that proceeds on it is testing a
// pool that still has room.
func ocuClaimSlot(t *testing.T, h *CondorTestHarness) string {
	t.Helper()
	return ocuSlotsMatching(t, h, `DynamicSlot && State == "Claimed" && Activity == "Idle" && RemoteOwner =?= undefined`)
}

// ocuSlotsMatching returns the one slot matching a constraint, or "".
func ocuSlotsMatching(t *testing.T, h *CondorTestHarness, constraint string) string {
	t.Helper()
	//nolint:gosec,noctx // G204: fixed command in a test
	cmd := exec.Command("condor_status", "-constraint", constraint, "-af", "Name")
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("condor_status: %v\n%s", err, out)
		return ""
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, line)
		}
	}
	if len(names) != 1 {
		return ""
	}
	return names[0]
}

// ocuWaitClaimSlot polls until exactly one claim is holding a slot.
func ocuWaitClaimSlot(t *testing.T, h *CondorTestHarness, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if slot := ocuClaimSlot(t, h); slot != "" {
			return slot
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(2 * time.Second)
	}
}

// ocuRan reports whether a job ever started.
func ocuRan(t *testing.T, ctx context.Context, s *Schedd, cluster string, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		ads, err := s.Query(ctx, "ClusterId == "+cluster, []string{"JobStatus"})
		if err != nil {
			t.Fatalf("querying job %s: %v", cluster, err)
		}
		if len(ads) > 0 {
			if st, ok := ads[0].EvaluateAttrInt("JobStatus"); ok && st == 2 {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
}

// ocuOwnerName reads the user record name the schedd gave the test's
// own jobs, which is what a claim has to be hung off.
//
// Read back rather than composed from the username and UID_DOMAIN: a
// composed name that is wrong is refused with "Owner not found", and
// every test here would then fail for a reason that is not what it is
// testing.
func ocuOwnerName(t *testing.T, ctx context.Context, s *Schedd, cluster, fallback string) string {
	t.Helper()
	ads, err := s.Query(ctx, "ClusterId == "+cluster, []string{"User", "Owner"})
	if err != nil || len(ads) == 0 {
		t.Logf("could not read the job's owner (%v); falling back to %q", err, fallback)
		return fallback
	}
	if u, ok := ads[0].EvaluateAttrString("User"); ok && u != "" {
		return u
	}
	if o, ok := ads[0].EvaluateAttrString("Owner"); ok && o != "" {
		return o
	}
	return fallback
}

// ocuDiagnoseSlots prints every slot and what it is doing.
func ocuDiagnoseSlots(t *testing.T, h *CondorTestHarness) {
	t.Helper()
	//nolint:gosec,noctx // G204: fixed command in a test
	cmd := exec.Command("condor_status", "-af", "Name", "State", "Activity", "Cpus", "RemoteOwner")
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	out, _ := cmd.CombinedOutput()
	t.Logf("slots:\n%s", out)
}

// ocuHeldClaim seeds the user record, creates one claim, and waits
// until the claim is holding a slot.
//
// It returns that slot's name. Everything downstream is a comparison
// against it, so a claim that never reached a slot fails here rather
// than producing a result that would be read as something else.
func ocuHeldClaim(t *testing.T, ctx context.Context, h *CondorTestHarness, schedd *Schedd, username, project string) (string, *OCU, func()) {
	t.Helper()

	// The schedd will not hang a claim off a user record it does not
	// have, and it creates one on first submit. This job also takes the
	// pool's other cpu, so the claim and it between them leave nothing
	// spare. It has to be running before the claim is asked for: while
	// a job is being started its slot is Claimed/Idle too, and the
	// claim would be indistinguishable from it.
	seed := ocuSubmit(t, h, nil)
	owner := ocuOwnerName(t, ctx, schedd, seed, username)
	if !ocuRan(t, ctx, schedd, seed, 3*time.Minute) {
		ocuDiagnoseSlots(t, h)
		t.Fatalf("the seeding job never ran, so this pool cannot start anything")
	}

	created, err := schedd.CreateOCU(ctx, &OCURequest{
		Owner:     owner,
		Project:   project,
		Submitter: owner,
		Request:   ocuRequestAd(),
	})
	if err != nil {
		t.Fatalf("creating the claim: %v", err)
	}
	cleanup := func() { _ = schedd.RemoveOCU(context.Background(), created.ID) }

	slot := ocuWaitClaimSlot(t, h, 4*time.Minute)
	if slot == "" {
		ocuDiagnoseSlots(t, h)
		cleanup()
		t.Fatalf("the claim never took a slot, so it is not holding anything")
	}
	t.Logf("claim %d is holding %s", created.ID, slot)
	return slot, created, cleanup
}

// ocuRanOnClaim reports whether a job ended up on the claim's slot.
//
// Both halves are needed. The job's RemoteHost says where it went; the
// claim's slot disappearing from the Claimed/Idle-with-no-owner set
// says the claim took something. Either alone is weaker: a job can be
// running before its RemoteHost is published, and the claim's slot
// could in principle be released rather than used.
func ocuRanOnClaim(t *testing.T, ctx context.Context, h *CondorTestHarness, s *Schedd, cluster, slot string, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		ads, err := s.Query(ctx, "ClusterId == "+cluster, []string{"JobStatus", "RemoteHost"})
		if err != nil {
			t.Fatalf("querying job %s: %v", cluster, err)
		}
		if len(ads) > 0 {
			if host, ok := ads[0].EvaluateAttrString("RemoteHost"); ok && host != "" {
				if host != slot {
					t.Logf("the job ran on %q, not on the claim's slot %q", host, slot)
				}
				return host == slot
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
}

// TestOCUCreateQueryRemove: the three management commands round-trip
// against a real schedd, and the claim the query returns is the claim
// that was created.
func TestOCUCreateQueryRemove(t *testing.T) {
	h, schedd, username := ocuHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cluster := ocuSubmit(t, h, nil)
	owner := ocuOwnerName(t, ctx, schedd, cluster, username)

	created, err := schedd.CreateOCU(ctx, &OCURequest{
		Owner:     owner,
		Name:      "permanent-test",
		Submitter: owner,
		Request:   ocuRequestAd(),
	})
	if err != nil {
		t.Fatalf("creating the claim: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("the claim came back with no id, so it could never be removed")
	}
	if created.Name != "permanent-test" {
		t.Errorf("claim name = %q, want %q", created.Name, "permanent-test")
	}

	ocus, err := schedd.OCUsFor(ctx, owner, "")
	if err != nil {
		t.Fatalf("querying claims: %v", err)
	}
	var found *OCU
	for _, o := range ocus {
		if o.ID == created.ID {
			found = o
		}
	}
	if found == nil {
		t.Fatalf("the claim just created is not in the query reply (%d claims for %q)", len(ocus), owner)
	}
	if found.Name != "permanent-test" {
		t.Errorf("queried name = %q, want %q", found.Name, "permanent-test")
	}

	if err := schedd.RemoveOCU(ctx, created.ID); err != nil {
		t.Fatalf("removing the claim: %v", err)
	}
	after, err := schedd.OCUsFor(ctx, owner, "")
	if err != nil {
		t.Fatalf("re-querying claims: %v", err)
	}
	for _, o := range after {
		if o.ID == created.ID {
			t.Fatalf("claim %d is still there after being removed", created.ID)
		}
	}
}

// TestOCUClaimTakesASlotAndHoldsIt: a claim really does acquire
// capacity and keep it while the pool is quiet.
//
// This is the property a permanent reservation is built on -- capacity
// acquired once stays with its owner instead of returning to the pool
// between jobs -- and nothing short of a real pool can observe it.
func TestOCUClaimTakesASlotAndHoldsIt(t *testing.T) {
	h, schedd, username := ocuHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	slot, _, cleanup := ocuHeldClaim(t, ctx, h, schedd, username, "")
	defer cleanup()

	// A claim that was matched and then released would give its slot
	// back within a negotiation cycle or two. Hold past several.
	const settle = 45 * time.Second
	time.Sleep(settle)
	if still := ocuClaimSlot(t, h); still != slot {
		ocuDiagnoseSlots(t, h)
		t.Errorf("the claim gave up %s within %s (now holding %q)", slot, settle, still)
	}
}

// TestOCUClaimDoesNotYetSurviveAnOrdinaryJob is the finding that keeps
// a permanent reservation from being held as an OCU today.
//
// A claim is supposed to be persistent: capacity that stays with its
// owner. Measured against 26.2.0 it is not persistent against ordinary
// work. The claim takes a slot and holds it while the queue is empty;
// the moment a plain job appears -- one declaring neither OCUWanted nor
// OCUWilling, entitled to nothing -- the claim's match record is
// deleted and that job runs on the slot the claim was holding. The
// claim survives in the user record, unmatched, with nothing left to
// take.
//
// The pairing is what makes it a finding rather than a coincidence:
// TestOCUClaimTakesASlotAndHoldsIt holds the same claim for longer than
// this test waits, on the same kind of pool, and it keeps its slot. The
// only difference here is a job in the queue.
//
// This asserts the current behaviour so the day it changes is visible.
// When a claim holds against ordinary work, this fails and should be
// inverted, not deleted.
func TestOCUClaimDoesNotYetSurviveAnOrdinaryJob(t *testing.T) {
	h, schedd, username := ocuHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	slot, _, cleanup := ocuHeldClaim(t, ctx, h, schedd, username, "")
	defer cleanup()

	job := ocuSubmit(t, h, nil)
	took := ocuRanOnClaim(t, ctx, h, schedd, job, slot, 3*time.Minute)
	ocuDiagnoseSlots(t, h)
	if !took {
		t.Fatalf("a plain job did not take the claim's slot %s, which 26.2.0 lets it do. "+
			"If a claim now holds against ordinary work, invert this test: surviving one is "+
			"what makes a claim worth holding a reservation in", slot)
	}
	t.Logf("a plain job entitled to nothing took the claim's slot %s", slot)
}

// Whether a job *entitled* to the claim -- one declaring OCUWilling, or
// the owner's own OCUWanted job, or one in the claim's project -- can
// be placed on it cannot be measured from outside while the test above
// passes.
//
// Both answers look identical: the job ends up on the claim's slot
// either way, because the claim is dropped and the slot is then matched
// like any other. The one signal that would tell them apart is the
// claim's own OCUState reaching 'R', and that transition is
// unreachable -- the schedd sets it by looking OCUId up on the match
// ad, and nothing puts OCUId there.
//
// Reading FindRunnableJob says those jobs would be refused: it compares
// the claim's RemoteOwner and RemoteProject against the job's, and
// nothing sets either on an idle claim, so every job reads as somebody
// else's and is required to be OCUWilling. That is a reading, not a
// measurement, and it is recorded as one. These tests get written when
// a claim survives long enough to answer the question.
