package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

const bulkEstimatesPath = "/api/v1/jobs/runtime-estimates"

type bulkEstimatesBody struct {
	Available bool                                  `json:"available"`
	Reason    string                                `json:"reason"`
	Estimates map[string]map[string]json.RawMessage `json:"estimates"`
	Model     *runtimeest.Model                     `json:"model"`
}

func (f *twoOwnerFixture) bulkEstimates(t *testing.T, auth func(*http.Request), ids ...string) (int, bulkEstimatesBody, string) {
	t.Helper()
	body, err := json.Marshal(map[string][]string{"jobs": ids})
	if err != nil {
		t.Fatal(err)
	}
	w := f.do(t, http.MethodPost, bulkEstimatesPath, string(body), auth)
	var out bulkEstimatesBody
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decoding %s: %v", w.Body.String(), err)
		}
	}
	return w.Code, out, w.Body.String()
}

func estimateField[T any](t *testing.T, est map[string]json.RawMessage, name string) (T, bool) {
	t.Helper()
	var v T
	raw, ok := est[name]
	if !ok {
		return v, false
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v, true
}

// Each caller gets estimates for exactly the jobs the single-job endpoint
// would answer for: their own, waiting or running. Another owner's job,
// a missing one and a held one are simply absent.
func TestBulkRuntimeEstimatesScope(t *testing.T) {
	f := runtimeFixture(t)
	running := fakeschedd.JobAd(3, 0, "alice", 2)
	running.InsertAttr("JobCurrentStartDate", time.Now().Unix()-40)
	held := fakeschedd.JobAd(4, 0, "alice", 5)
	f.schedd.AddJobs(running, held, fakeschedd.JobAd(3, 1, "alice", 1))

	code, body, raw := f.bulkEstimates(t, f.bearer(t, "alice"), "1.0", "2.0", "3.0", "4.0", "999.0", "1.0")
	if code != http.StatusOK || !body.Available {
		t.Fatalf("status %d: %s", code, raw)
	}
	if len(body.Estimates) != 2 {
		t.Fatalf("alice got estimates for %d jobs, want her waiting 1.0 and running 3.0 (3.1 was not asked for): %s",
			len(body.Estimates), raw)
	}
	idle, ok := body.Estimates["1.0"]
	if !ok {
		t.Fatalf("no estimate for alice's waiting job: %s", raw)
	}
	if v, _ := estimateField[float64](t, idle, "estimate_seconds"); v != 100 {
		t.Errorf("1.0 estimate = %v, want alice's 100s", v)
	}
	if _, ok := idle["elapsed_seconds"]; ok {
		t.Errorf("a waiting job has an elapsed time: %s", raw)
	}
	if rough, _ := estimateField[bool](t, idle, "rough"); !rough {
		t.Errorf("an owner-level estimate is not rough: %s", raw)
	}
	run := body.Estimates["3.0"]
	if rem, ok := estimateField[float64](t, run, "remaining_seconds"); !ok || rem < 50 || rem > 61 {
		t.Errorf("3.0 remaining = %v, want about 60: %s", rem, raw)
	}
	for _, est := range body.Estimates {
		if _, ok := est["model"]; ok {
			t.Errorf("an estimate repeats the model: %s", raw)
		}
	}
	if body.Model == nil || body.Model.JobsIngested != 10 {
		t.Errorf("model = %+v", body.Model)
	}

	_, body, raw = f.bulkEstimates(t, f.bearer(t, "bob"), "1.0", "2.0")
	if len(body.Estimates) != 1 {
		t.Fatalf("bob: %s", raw)
	}
	if v, _ := estimateField[float64](t, body.Estimates["2.0"], "estimate_seconds"); v != 5000 {
		t.Errorf("bob's estimate came from someone else's history: %s", raw)
	}

	// Nothing asked, nothing answered -- and still available.
	code, body, raw = f.bulkEstimates(t, f.bearer(t, "alice"))
	if code != http.StatusOK || !body.Available || len(body.Estimates) != 0 || !strings.Contains(raw, `"estimates":{}`) {
		t.Errorf("empty request: %d %s", code, raw)
	}
}

// Many clusters are asked about in more than one schedd query, and
// every requested job still comes back once.
func TestBulkRuntimeEstimatesChunks(t *testing.T) {
	f := runtimeFixture(t)
	var ids []string
	for c := 1000; c < 1000+bulkRuntimeEstimateClusters+20; c++ {
		f.schedd.AddJobs(fakeschedd.JobAd(c, 0, "alice", 1))
		ids = append(ids, fmt.Sprintf("%d.0", c))
	}
	before, _ := f.schedd.JobQueries()
	code, body, raw := f.bulkEstimates(t, f.bearer(t, "alice"), ids...)
	if code != http.StatusOK || len(body.Estimates) != len(ids) {
		t.Fatalf("status %d, %d estimates for %d jobs: %.300s", code, len(body.Estimates), len(ids), raw)
	}
	if after, last := f.schedd.JobQueries(); after-before != 2 || !strings.Contains(last, "member(ClusterId") {
		t.Errorf("%d schedd queries for %d clusters, last %q", after-before, len(ids), last)
	}
}

func TestBulkRuntimeEstimatesLimits(t *testing.T) {
	f := runtimeFixture(t)
	alice := f.bearer(t, "alice")

	ids := make([]string, maxBulkRuntimeEstimates+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("%d.0", i+1)
	}
	if code, _, raw := f.bulkEstimates(t, alice, ids...); code != http.StatusRequestEntityTooLarge {
		t.Errorf("%d ids: status %d %s", len(ids), code, raw)
	}
	if code, body, _ := f.bulkEstimates(t, alice, ids[:maxBulkRuntimeEstimates]...); code != http.StatusOK || len(body.Estimates) != 1 {
		t.Errorf("%d ids: status %d, %d estimates", maxBulkRuntimeEstimates, code, len(body.Estimates))
	}
	for _, bad := range []string{"nonsense", "1", "0.0", "-1.0"} {
		if code, _, _ := f.bulkEstimates(t, alice, bad); code != http.StatusBadRequest {
			t.Errorf("id %q: status %d", bad, code)
		}
	}
	if w := f.do(t, http.MethodPost, bulkEstimatesPath, "{", alice); w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: status %d", w.Code)
	}
	if w := f.do(t, http.MethodGet, bulkEstimatesPath, "", alice); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status %d", w.Code)
	}
	if code, _, _ := f.bulkEstimates(t, func(*http.Request) {}, "1.0"); code == http.StatusOK {
		t.Error("an unauthenticated request was answered")
	}
}

// Off or not loaded yet: one shape, the single endpoint's reasons, and
// no schedd query.
func TestBulkRuntimeEstimatesUnavailable(t *testing.T) {
	f := twoOwnerScheddServer(t)
	alice := f.bearer(t, "alice")
	before, _ := f.schedd.JobQueries()

	w := f.do(t, http.MethodPost, bulkEstimatesPath, `{"jobs":["1.0"]}`, alice)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"available":false,"reason":"disabled"}` {
		t.Errorf("disabled: %d %s", w.Code, w.Body.String())
	}
	f.s.runtimeEst = runtimeest.New(runtimeest.Config{})
	w = f.do(t, http.MethodPost, bulkEstimatesPath, `{"jobs":["1.0"]}`, alice)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"available":false,"reason":"model_warming_up"}` {
		t.Errorf("warming up: %d %s", w.Code, w.Body.String())
	}
	if after, _ := f.schedd.JobQueries(); after != before {
		t.Errorf("an unavailable estimator queried the schedd %d times", after-before)
	}

	// Loaded with nothing comparable: the job is there, without an
	// estimate.
	f.s.runtimeEst.Ingest(runtimeest.NewBatch())
	_, body, raw := f.bulkEstimates(t, alice, "1.0")
	if a, _ := estimateField[bool](t, body.Estimates["1.0"], "available"); a || !strings.Contains(raw, runtimeest.ReasonInsufficientHistory) {
		t.Errorf("no history: %s", raw)
	}
}

// It reads, so a read-only credential may use it, POST or not.
func TestBulkRuntimeEstimatesIsARead(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, bulkEstimatesPath, nil)
	if got := condorScopeForRequest(r); got != condorScopeRead {
		t.Errorf("scope = %q, want %q", got, condorScopeRead)
	}
	r = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs/hold", nil)
	if got := condorScopeForRequest(r); got != condorScopeWrite {
		t.Errorf("bulk hold scope = %q", got)
	}
	if got := classifyRoute(bulkEstimatesPath); got != bulkEstimatesPath {
		t.Errorf("classifyRoute = %q", got)
	}
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(openAPISchema), &doc); err != nil {
		t.Fatalf("openapi does not parse: %v", err)
	}
	if _, ok := doc.Paths["/jobs/runtime-estimates"]; !ok {
		t.Error("/jobs/runtime-estimates missing from the OpenAPI paths")
	}
}
