//go:build integration

package htcondor

import (
	"context"
	"os/exec"
	"os/user"
	"testing"
	"time"
)

// TestOCUStaticSlotClaimDoesNotYetSurviveAnOrdinaryJob asks the same
// question of a pool of static slots.
//
// Worth asking separately because the obvious suspect for losing a
// claim is the code that reuses a partitionable slot's claim and
// carves a new dynamic slot from it. It is not that: a claim on a
// plain static slot is taken the same way, so whatever gives it up is
// common to both.
func TestOCUStaticSlotClaimDoesNotYetSurviveAnOrdinaryJob(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH")
	}
	me, err := user.Current()
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	cfg := "NUM_CPUS = 2\nMEMORY = 2048\nDISK = 4096000\n" +
		"NUM_SLOTS = 2\nNUM_SLOTS_TYPE_1 = 2\nSLOT_TYPE_1 = cpus=1, mem=1024, disk=50%\n" +
		"SLOT_TYPE_1_PARTITIONABLE = False\n" +
		"NEGOTIATOR_INTERVAL = 5\nNEGOTIATOR_CYCLE_DELAY = 5\n" +
		"SCHEDD_INTERVAL = 5\nUPDATE_INTERVAL = 5\n" +
		"OCU_SUPER_USERS = " + me.Username + "\n"

	h := SetupCondorHarnessWithConfig(t, cfg)
	if err := h.WaitForDaemons(); err != nil {
		t.Fatalf("daemons: %v", err)
	}
	loc := getScheddAddress(t, h)
	schedd := NewSchedd(loc.Name, loc.Address)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	seed := ocuSubmit(t, h, nil)
	owner := ocuOwnerName(t, ctx, schedd, seed, me.Username)
	if !ocuRan(t, ctx, schedd, seed, 3*time.Minute) {
		ocuDiagnoseSlots(t, h)
		t.Fatal("seed never ran")
	}

	created, err := schedd.CreateOCU(ctx, &OCURequest{
		Owner: owner, Submitter: owner, Request: ocuRequestAd(),
	})
	if err != nil {
		t.Fatalf("creating the claim: %v", err)
	}
	defer func() { _ = schedd.RemoveOCU(context.Background(), created.ID) }()

	// Same discriminator as the partitionable case, without
	// DynamicSlot: the claim's slot is Claimed/Idle with nobody on it.
	slot := ""
	deadline := time.Now().Add(4 * time.Minute)
	for slot == "" && time.Now().Before(deadline) {
		slot = ocuStaticClaimSlot(t, h)
		if slot == "" {
			time.Sleep(2 * time.Second)
		}
	}
	if slot == "" {
		ocuDiagnoseSlots(t, h)
		t.Fatal("the claim never took a slot")
	}
	t.Logf("claim %d is holding %s", created.ID, slot)

	job := ocuSubmit(t, h, nil)
	took := ocuRanOnClaim(t, ctx, h, schedd, job, slot, 3*time.Minute)
	ocuDiagnoseSlots(t, h)
	if !took {
		t.Fatalf("a plain job did not take the claim's static slot %s, which 26.2.0 lets it do; "+
			"if a claim now holds against ordinary work, invert this test", slot)
	}
	t.Logf("a plain job entitled to nothing took the claim's static slot %s", slot)
}

func ocuStaticClaimSlot(t *testing.T, h *CondorTestHarness) string {
	t.Helper()
	return ocuSlotsMatching(t, h, `State == "Claimed" && Activity == "Idle" && RemoteOwner =?= undefined`)
}
