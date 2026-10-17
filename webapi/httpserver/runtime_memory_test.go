package httpserver

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// memoryFixture: six of alice's finished /home/alice/sim runs, five
// peaking at 1000..1400 MiB (by ResidentSetSize_RAW, in KiB) and one
// with no peak recorded. Queued: 20.0 running at 6000 MiB so far, 20.1
// running at 900, 20.2 waiting; each requests 1200 MiB. Read by the
// estimator.
func memoryFixture(t *testing.T) *twoOwnerFixture {
	t.Helper()
	f := twoOwnerScheddServer(t)
	now := time.Now().Unix()
	var history []*classad.ClassAd
	for i := range 6 {
		text := historyRecordText("alice", 10+i, 100, now-int64(3600*(6-i)))
		if i < 5 {
			text += fmt.Sprintf("\nResidentSetSize_RAW = %d", (1000+100*i)*1024)
		}
		ad, err := classad.ParseOld(text)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, ad)
	}
	f.schedd.AddHistory(history...)
	queued := func(proc, status int, mib int) *classad.ClassAd {
		text := fmt.Sprintf(`ClusterId = 20
ProcId = %d
Owner = "alice"
Cmd = "/home/alice/sim"
JobUniverse = 5
JobStatus = %d
RequestMemory = 1200
ResidentSetSize = %d
MemoryUsage = ((ResidentSetSize + 1023) / 1024)`, proc, status, mib*1024)
		if status == 2 {
			text += fmt.Sprintf("\nJobCurrentStartDate = %d", now-60)
		}
		ad, err := classad.ParseOld(text)
		if err != nil {
			t.Fatal(err)
		}
		return ad
	}
	f.schedd.AddJobs(queued(0, 2, 6000), queued(1, 2, 900), queued(2, 1, 0))
	f.s.runtimeEst = runtimeest.New(runtimeest.Config{})
	b := runtimeest.NewBatch()
	for _, ad := range history {
		b.AddAd(ad)
	}
	f.s.runtimeEst.Ingest(b)
	return f
}

// The single-job estimate carries the group's memory and the job's own
// peak; a job far past its group's runs is above usual.
func TestRuntimeEstimateMemory(t *testing.T) {
	f := memoryFixture(t)
	alice := f.bearer(t, "alice")

	code, body := f.estimate(t, "20.0", alice)
	if code != http.StatusOK || body.Basis == nil || body.Basis.Level != "exact" {
		t.Fatalf("status %d, %+v", code, body)
	}
	m := body.Memory
	if m == nil || m.SampleCount != 5 || m.P50MiB != 1200 || m.P10MiB != 1040 || m.P90MiB != 1360 || m.Rough {
		t.Fatalf("memory = %+v; want the five known peaks of the exact group", m)
	}
	if m.PeakMiB == nil || *m.PeakMiB != 6000 || !m.AboveUsual {
		t.Errorf("running job at 6000 MiB: %+v", m)
	}
	// 1300 and 1400 are above the 1200 requested.
	if m.RequestedMiB == nil || *m.RequestedMiB != 1200 || m.AboveRequested == nil || *m.AboveRequested != 2 {
		t.Errorf("request: %+v", m)
	}

	_, body = f.estimate(t, "20.1", alice)
	if body.Memory == nil || body.Memory.AboveUsual || *body.Memory.PeakMiB != 900 {
		t.Errorf("running job at 900 MiB: %+v", body.Memory)
	}
	_, body = f.estimate(t, "20.2", alice)
	if body.Memory == nil || body.Memory.AboveUsual || body.Memory.PeakMiB != nil {
		t.Errorf("waiting job: %+v", body.Memory)
	}
}

// A job that has left the queue is answered from its history record:
// its own peak against its group's.
func TestRuntimeEstimateFinishedJob(t *testing.T) {
	f := memoryFixture(t)
	code, body := f.estimate(t, "14.0", f.bearer(t, "alice"))
	if code != http.StatusOK || !body.Available || body.Memory == nil {
		t.Fatalf("finished job: status %d, %+v", code, body)
	}
	if body.Memory.PeakMiB == nil || *body.Memory.PeakMiB != 1400 || body.Memory.AboveUsual || body.ElapsedSeconds != nil {
		t.Errorf("finished job: %+v", body.Memory)
	}
	// Still scoped: bob does not see it, and a job in neither is missing.
	if code, _ := f.estimate(t, "14.0", f.bearer(t, "bob")); code != http.StatusNotFound {
		t.Errorf("bob asking about alice's finished job: %d", code)
	}
	if code, _ := f.estimate(t, "77.0", f.bearer(t, "alice")); code != http.StatusNotFound {
		t.Errorf("missing job: %d", code)
	}
}

// The listing's bulk answer carries the same memory block.
func TestBulkRuntimeEstimatesMemory(t *testing.T) {
	f := memoryFixture(t)
	code, body, raw := f.bulkEstimates(t, f.bearer(t, "alice"), "20.0", "20.1", "20.2")
	if code != http.StatusOK || len(body.Estimates) != 3 {
		t.Fatalf("status %d: %s", code, raw)
	}
	for id, want := range map[string]bool{"20.0": true, "20.1": false, "20.2": false} {
		m, ok := estimateField[runtimeest.MemoryEstimate](t, body.Estimates[id], "memory")
		if !ok || m.SampleCount != 5 || m.P90MiB != 1360 || m.AboveUsual != want {
			t.Errorf("%s memory = %+v (present %v), want above_usual %v: %s", id, m, ok, want, raw)
		}
	}
}

// The similar-jobs view gives the group's memory beside its runtimes,
// and each listed job's peak -- null where the record has none.
func TestJobSimilarMemory(t *testing.T) {
	f := memoryFixture(t)
	code, resp := f.similar(t, "/api/v1/jobs/20.0/similar", f.bearer(t, "alice"))
	if code != http.StatusOK || resp.Level != "exact" {
		t.Fatalf("similar: %d %+v", code, resp)
	}
	if resp.Memory == nil || *resp.Memory != (runtimeest.MemorySummary{Count: 5, P10: 1040, P25: 1100, P50: 1200, P75: 1300, P90: 1360}) {
		t.Errorf("memory = %+v", resp.Memory)
	}
	if resp.Runtimes == nil || resp.Runtimes.Count != 6 {
		t.Errorf("runtimes = %+v; every run counts for its runtime", resp.Runtimes)
	}
	peaks := map[string]*float64{}
	for _, j := range resp.Jobs {
		peaks[j.ID] = j.PeakMemoryMiB
	}
	if len(peaks) != 6 || peaks["15.0"] != nil || peaks["14.0"] == nil || *peaks["14.0"] != 1400 {
		t.Errorf("peaks = %v; want 14.0 at 1400 and 15.0 null", peaks)
	}
	w := f.do(t, http.MethodGet, "/api/v1/jobs/20.0/similar", "", f.bearer(t, "alice"))
	if body := w.Body.String(); !strings.Contains(body, `"peak_memory_mib":null`) || !strings.Contains(body, `"memory":{"count":5`) {
		t.Errorf("wire form: %s", body)
	}
}
