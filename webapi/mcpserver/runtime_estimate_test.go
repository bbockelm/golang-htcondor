package mcpserver

import (
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// loadedEstimator has read five 100-second jobs of alice's and five
// 5000-second jobs of bob's.
func loadedEstimator() *runtimeest.Estimator {
	est := runtimeest.New(runtimeest.Config{})
	b := runtimeest.NewBatch()
	for i := range 5 {
		at := time.Unix(1_000_000+int64(i), 0)
		b.Add(runtimeest.Completion{Features: runtimeest.Features{Owner: "alice", ClusterID: int64(100 + i), Cmd: "sim"}, Runtime: 100, Completed: at})
		b.Add(runtimeest.Completion{Features: runtimeest.Features{Owner: "bob", ClusterID: int64(200 + i), Cmd: "sim"}, Runtime: 5000, Completed: at})
	}
	est.Ingest(b)
	return est
}

func getJobStructured(t *testing.T, result interface{}) map[string]interface{} {
	t.Helper()
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is %T", result)
	}
	sc, ok := m["structuredContent"].(map[string]interface{})
	if !ok {
		t.Fatalf("structuredContent is %T", m["structuredContent"])
	}
	return sc
}

func resultText(t *testing.T, result interface{}) string {
	t.Helper()
	content := result.(map[string]interface{})["content"].([]map[string]interface{})
	return content[0]["text"].(string)
}

// get_job carries the caller's job's estimate, built from that owner's
// history, when the server runs the estimator -- and nothing when it
// does not.
func TestGetJobRuntimeEstimate(t *testing.T) {
	f := newActionScopeFixture(t)
	alice := f.as(t, "alice", "mcp:read")

	out, err := f.server.toolGetJob(alice, map[string]interface{}{"job_id": "1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := getJobStructured(t, out)["runtime_estimate"]; ok {
		t.Error("runtime_estimate present with no estimator")
	}

	f.server.runtimeEst = loadedEstimator()
	// A running job of alice's, with a start time.
	running := fakeschedd.JobAd(3, 0, "alice", 2)
	running.InsertAttr("JobCurrentStartDate", time.Now().Unix()-30)
	f.schedd.AddJobs(running)

	out, err = f.server.toolGetJob(alice, map[string]interface{}{"job_id": "3.0"})
	if err != nil {
		t.Fatal(err)
	}
	sc := getJobStructured(t, out)
	est, ok := sc["runtime_estimate"].(runtimeest.Result)
	if !ok {
		t.Fatalf("runtime_estimate is %T", sc["runtime_estimate"])
	}
	if !est.Available || est.EstimateSeconds != 100 || est.RemainingSeconds == nil {
		t.Errorf("estimate = %+v; want alice's 100s with time remaining", est)
	}
	// The job carries no command, so only alice's jobs in general answer:
	// a rough guess.
	if !est.Rough {
		t.Errorf("an owner-level estimate is not marked rough: %+v", est)
	}
	text := resultText(t, out)
	if !strings.Contains(text, "Runtime estimate: roughly 1m") || !strings.Contains(text, "remaining") {
		t.Errorf("text does not carry the estimate:\n%s", text)
	}
	validateStructured(t, "get_job", sc)

	// Bob's job is still not found for alice.
	if _, err := f.server.toolGetJob(alice, map[string]interface{}{"job_id": "2.0"}); err == nil {
		t.Error("alice read bob's job")
	}
}

// Every shape the field takes satisfies the published schema.
func TestRuntimeEstimateValidatesAgainstTheSchema(t *testing.T) {
	s := contractServer(t)
	elapsed, remaining := 30.0, 70.0
	for name, r := range map[string]runtimeest.Result{
		"unavailable": {Reason: runtimeest.ReasonWarmingUp},
		"idle": {Available: true, EstimateSeconds: 100, P10Seconds: 60, P90Seconds: 300,
			Basis: &runtimeest.Basis{Level: "template", SampleCount: 9},
			Model: runtimeest.Model{TrainedThrough: "2026-10-10T00:00:00Z", JobsIngested: 50}},
		"running": {Available: true, EstimateSeconds: 100, P10Seconds: 60, P90Seconds: 300,
			Basis: &runtimeest.Basis{Level: "owner", SampleCount: 3, NewCommand: true}, Rough: true,
			ElapsedSeconds: &elapsed, RemainingSeconds: &remaining},
		"exceeded": {Available: true, EstimateSeconds: 100, P10Seconds: 60, P90Seconds: 300,
			Basis: &runtimeest.Basis{Level: "cmd", SampleCount: 3}, ElapsedSeconds: &elapsed, ExceededHistory: true},
	} {
		t.Run(name, func(t *testing.T) {
			payload := map[string]interface{}{"job_id": "1.0", "job": map[string]interface{}{}, "runtime_estimate": r}
			validateStructured(t, "get_job", finalized(t, s, "get_job", structuredTextResult("", payload)))
		})
	}
}

func TestRenderRuntimeEstimate(t *testing.T) {
	elapsed, remaining := 600.0, 3000.0
	got := renderRuntimeEstimate(runtimeest.Result{
		Available: true, EstimateSeconds: 3600, P10Seconds: 1800, P90Seconds: 7200,
		Basis:          &runtimeest.Basis{Level: "template", SampleCount: 12},
		ElapsedSeconds: &elapsed, RemainingSeconds: &remaining,
	})
	for _, want := range []string{"about 1h0m", "between 30m and 2h0m", "based on 12 of your finished jobs with the same command and argument pattern",
		"Running 10m so far; about 50m remaining."} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	got = renderRuntimeEstimate(runtimeest.Result{
		Available: true, EstimateSeconds: 100, P10Seconds: 50, P90Seconds: 200,
		Basis: &runtimeest.Basis{Level: "cmd", SampleCount: 3}, ElapsedSeconds: &elapsed, ExceededHistory: true,
	})
	if !strings.Contains(got, "no estimate of the time remaining") {
		t.Errorf("exceeded: %q", got)
	}
	got = renderRuntimeEstimate(runtimeest.Result{
		Available: true, EstimateSeconds: 7200, P10Seconds: 900, P90Seconds: 21600, Rough: true,
		Basis: &runtimeest.Basis{Level: "owner", SampleCount: 40, NewCommand: true},
	})
	for _, want := range []string{"roughly 2h0m, a rough guess", "none of your recently finished jobs ran this program"} {
		if !strings.Contains(got, want) {
			t.Errorf("rough: missing %q in %q", want, got)
		}
	}
	if got := renderRuntimeEstimate(runtimeest.Result{Reason: runtimeest.ReasonInsufficientHistory}); !strings.Contains(got, "too few") {
		t.Errorf("insufficient: %q", got)
	}
}
