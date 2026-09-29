package htcondor

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// TestStartdQueryHistoryIntegration runs a job on the harness's startd and then reads that job
// back out of the startd's own history (GET_HISTORY), which is a different daemon, command and
// file from the schedd history the other integration tests cover.
func TestStartdQueryHistoryIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	harness := SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(60 * time.Second); err != nil {
		t.Fatalf("Startd never advertised: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	collector := NewCollector(harness.GetCollectorAddr())
	scheddLoc, err := collector.LocateDaemon(ctx, DaemonSchedd, "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}
	startdLoc, err := collector.LocateDaemon(ctx, DaemonStartd, "")
	if err != nil {
		t.Fatalf("Failed to locate startd: %v", err)
	}
	schedd := NewSchedd(scheddLoc.Name, scheddLoc.Address)
	startd := NewStartd(startdLoc.Name, startdLoc.Address)

	submitFile := fmt.Sprintf(`
universe = vanilla
executable = /bin/echo
arguments = Hello from the startd history test
output = startd_history.out
error = startd_history.err
log = startd_history.log
transfer_executable = false
initialdir = %s
queue
`, harness.tmpDir)

	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}
	t.Logf("Submitted cluster %s", clusterID)

	// The startd writes its history record when the starter exits, which is not the same instant
	// the job leaves the queue -- so poll the startd itself rather than waiting a fixed time and
	// hoping. Failing to find the record is then a real absence, not a race we lost.
	constraint := "ClusterId == " + clusterID
	var records []*classad.ClassAd
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		records, err = startd.QueryHistory(ctx, constraint, []string{"*"})
		if err != nil {
			t.Fatalf("Startd history query failed: %v", err)
		}
		if len(records) > 0 {
			break
		}
		time.Sleep(time.Second)
	}
	if len(records) == 0 {
		harness.PrintStartdLog()
		harness.PrintStarterLogs()
		t.Fatalf("no startd history record for cluster %s within the deadline", clusterID)
	}

	rec := records[0]
	t.Logf("startd history record: %s", rec.MarshalOld())

	// The startd stamps CompletionDate at the moment it appends the record, which is what makes
	// it usable as a resume cursor for an incremental reader.
	if v, ok := rec.EvaluateAttrInt("CompletionDate"); !ok || v <= 0 {
		t.Errorf("CompletionDate = %v (ok=%v); want the record's append time", v, ok)
	}
	if v, ok := rec.EvaluateAttrString("GlobalJobId"); !ok || v == "" {
		t.Error("GlobalJobId missing; a cross-pool reader has no stable key without it")
	}
	// "*" must really mean every attribute: the default projection would not carry Owner.
	if v, ok := rec.EvaluateAttrString("Owner"); !ok || v == "" {
		t.Errorf("Owner = %q (ok=%v); projection \"*\" should return the whole record", v, ok)
	}

	// Since stops the backward scan, which is how an incremental importer asks for "only what is
	// new". Asking for records strictly older than this one must return nothing.
	completion, _ := rec.EvaluateAttrInt("CompletionDate")
	opts := &HistoryQueryOptions{
		Projection: []string{"*"},
		Backwards:  true,
		Limit:      -1,
		Since:      fmt.Sprintf("CompletionDate < %d", completion),
	}
	newer, err := startd.QueryHistoryWithOptions(ctx, "", opts)
	if err != nil {
		t.Fatalf("Startd history query with Since failed: %v", err)
	}
	for _, ad := range newer {
		if v, ok := ad.EvaluateAttrInt("CompletionDate"); ok && v < completion {
			t.Errorf("Since did not stop the scan: got a record with CompletionDate %d < %d", v, completion)
		}
	}

	// The streaming path is what the importer uses; it must deliver the same record.
	ch, err := startd.QueryHistoryStream(ctx, constraint, &HistoryQueryOptions{Projection: []string{"*"}, Backwards: true, Limit: -1}, nil)
	if err != nil {
		t.Fatalf("Startd history stream failed: %v", err)
	}
	streamed := 0
	for r := range ch {
		if r.Err != nil {
			t.Fatalf("Startd history stream error: %v", r.Err)
		}
		streamed++
	}
	if streamed == 0 {
		t.Error("streaming query returned no records for a cluster the buffered query found")
	}
}
