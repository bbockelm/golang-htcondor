package htcondor

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// TestSendJobAttributesKeepsProcPlacement pins the behavior of the deprecated
// SendJobAttributes: it writes every attribute to the proc ad it is given.
//
// SendClusterAttributes and SendProcAttributes replaced it because that
// placement is wrong for a multi-proc cluster -- see
// TestSubmitPlacesSharedAttributesOnClusterAd -- but the method is exported,
// so callers outside this module still get what they have always got.
func TestSendJobAttributesKeepsProcPlacement(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	harness := SetupCondorHarness(t)
	if err := harness.WaitForSchedd(60 * time.Second); err != nil {
		t.Fatalf("schedd failed to start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	collector := NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("failed to locate schedd: %v", err)
	}

	jobAd := classad.New()
	_ = jobAd.Set("Cmd", "/bin/sleep")
	_ = jobAd.Set("Args", "60")
	_ = jobAd.Set("JobUniverse", 5)
	_ = jobAd.Set("JobStatus", 1)
	_ = jobAd.Set("RequestCpus", 1)
	_ = jobAd.Set("RequestMemory", 128)

	qmgmt, err := NewQmgmtConnection(ctx, location.Address)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("failed to connect to schedd: %v", err)
	}
	defer func() {
		if cerr := qmgmt.Close(); cerr != nil {
			t.Logf("warning: failed to close qmgmt connection: %v", cerr)
		}
	}()

	// The connection's GetCapabilities already opened a transaction.
	owner := qmgmt.authenticatedUser
	if owner == "" {
		harness.PrintScheddLog()
		_ = qmgmt.AbortTransaction(ctx)
		t.Fatal("no authenticated user from the QMGMT connection")
	}
	if err := qmgmt.SetEffectiveOwner(ctx, owner); err != nil {
		_ = qmgmt.AbortTransaction(ctx)
		t.Fatalf("failed to set effective owner: %v", err)
	}

	cluster, err := qmgmt.NewCluster(ctx)
	if err != nil {
		_ = qmgmt.AbortTransaction(ctx)
		t.Fatalf("failed to create a cluster: %v", err)
	}
	proc, err := qmgmt.NewProc(ctx, cluster)
	if err != nil {
		_ = qmgmt.AbortTransaction(ctx)
		t.Fatalf("failed to create a proc: %v", err)
	}

	// Deprecated on purpose: this test is what keeps it working.
	if err := qmgmt.SendJobAttributes(ctx, cluster, proc, jobAd); err != nil {
		_ = qmgmt.AbortTransaction(ctx)
		t.Fatalf("SendJobAttributes failed: %v", err)
	}
	if err := qmgmt.CommitTransaction(ctx); err != nil {
		_ = qmgmt.AbortTransaction(ctx)
		t.Fatalf("failed to commit: %v", err)
	}

	var clusterAttrs, procAttrs map[string]string
	for key, attrs := range setAttrsByKey(t, harness.GetSpoolDir()) {
		c, p, ok := jobQueueKey(key)
		if !ok || c != cluster {
			continue
		}
		switch p {
		case clusterAdProcID:
			clusterAttrs = attrs
		case proc:
			procAttrs = attrs
		}
	}
	if procAttrs == nil {
		t.Fatalf("job %d.%d has no proc ad in job_queue.log", cluster, proc)
	}

	// Everything the caller passed is on the proc ad, as it always was.
	for attr, want := range map[string]string{
		"Cmd":           `"/bin/sleep"`,
		"Args":          `"60"`,
		"JobUniverse":   "5",
		"RequestCpus":   "1",
		"RequestMemory": "128",
	} {
		if got, ok := procAttrs[attr]; !ok {
			t.Errorf("proc ad is missing %s, which SendJobAttributes should have sent to it", attr)
		} else if got != want {
			t.Errorf("proc ad has %s = %s, want %s", attr, got, want)
		}
		if _, ok := clusterAttrs[attr]; ok {
			t.Errorf("cluster ad holds %s: SendJobAttributes must not move attributes to the cluster ad", attr)
		}
	}

	// SendJobAttributes sends nothing of its own: unlike SendProcAttributes it
	// never writes ProcId, so the ad is identified only by the key NewProc
	// created it under. Callers that need it in the ad set it themselves.
	if got, ok := procAttrs["ProcId"]; ok {
		t.Errorf("proc ad has ProcId = %s; SendJobAttributes sends only what the caller put in the ad", got)
	}
}
