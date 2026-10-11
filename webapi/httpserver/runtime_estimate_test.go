package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// fakeRuntimeHistory is a history archive in memory: newest first, the
// limit honoured, the way the mirror's archive answers.
type fakeRuntimeHistory struct {
	mu     sync.Mutex
	rows   []*classad.ClassAd
	err    error
	sinces []int64
}

func (f *fakeRuntimeHistory) add(ads ...*classad.ClassAd) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, ads...)
}

func (f *fakeRuntimeHistory) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeRuntimeHistory) History(_ context.Context, since int64, limit int, yield func(*classad.ClassAd)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sinces = append(f.sinces, since)
	if f.err != nil {
		return f.err
	}
	var match []*classad.ClassAd
	for _, ad := range f.rows {
		if runtimeEnteredHistory(ad) >= since {
			match = append(match, ad)
		}
	}
	sort.SliceStable(match, func(i, j int) bool {
		return runtimeEnteredHistory(match[i]) > runtimeEnteredHistory(match[j])
	})
	for i, ad := range match {
		if i >= limit {
			break
		}
		yield(ad)
	}
	return nil
}

// historyRecordText is a clean completion that entered history at
// entered, in the old ClassAd syntax the mirror stores.
func historyRecordText(owner string, cluster int, runtime, entered int64) string {
	return fmt.Sprintf(`Owner = %q
ClusterId = %d
ProcId = 0
QDate = %d
GlobalJobId = "ap#%d.0#%d"
Cmd = "/home/%s/sim"
JobStatus = 4
ExitCode = 0
ExitBySignal = false
JobUniverse = 5
RemoteWallClockTime = %d
CompletionDate = %d
EnteredHistoryTime = %d`, owner, cluster, entered-runtime-10, cluster, entered-runtime-10, owner, runtime, entered, entered)
}

func historyRecord(t *testing.T, owner string, cluster int, runtime, entered int64) *classad.ClassAd {
	t.Helper()
	ad, err := classad.ParseOld(historyRecordText(owner, cluster, runtime, entered))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return ad
}

func testRefresher(t *testing.T, src runtimeHistorySource, now time.Time) *runtimeRefresher {
	t.Helper()
	r := newRuntimeRefresher(runtimeest.New(runtimeest.Config{}), src, time.Minute, 24*time.Hour, testLogger(t))
	r.now = func() time.Time { return now }
	return r
}

var refreshNow = time.Unix(1_800_000_000, 0)

// The startup read covers the backfill window and nothing older.
func TestRuntimeRefresherBackfillWindow(t *testing.T) {
	src := &fakeRuntimeHistory{}
	n := refreshNow.Unix()
	src.add(
		historyRecord(t, "alice", 1, 100, n-3600),
		historyRecord(t, "alice", 2, 100, n-3500),
		historyRecord(t, "alice", 3, 100, n-3400),
		historyRecord(t, "alice", 4, 99999, n-48*3600), // outside the window
	)
	r := testRefresher(t, src, refreshNow)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := n - 24*3600; src.sinces[0] != want {
		t.Errorf("since = %d, want now - backfill = %d", src.sinces[0], want)
	}
	if got := r.est.Stats().JobsIngested; got != 3 {
		t.Errorf("ingested %d, want 3", got)
	}
	res := r.est.Estimate(runtimeest.Query{Features: runtimeest.Features{Owner: "alice", Cmd: "/home/alice/sim"}})
	if !res.Available || res.EstimateSeconds != 100 {
		t.Errorf("estimate = %+v", res)
	}
	if last, _, _ := r.status(); !last.Equal(refreshNow) {
		t.Errorf("last success = %v", last)
	}
}

// After the first read each refresh reads from the newest
// EnteredHistoryTime seen, inclusive, and skips the records it already
// has at that second -- while still taking new ones that land in it.
func TestRuntimeRefresherWatermarkDedupe(t *testing.T) {
	src := &fakeRuntimeHistory{}
	n := refreshNow.Unix()
	src.add(
		historyRecord(t, "alice", 1, 100, n-20),
		historyRecord(t, "alice", 2, 100, n-10),
		historyRecord(t, "alice", 3, 100, n-10),
	)
	r := testRefresher(t, src, refreshNow)
	ctx := context.Background()
	jobs := func() int64 { return r.est.Stats().JobsIngested }

	if err := r.Refresh(ctx); err != nil || jobs() != 3 {
		t.Fatalf("first refresh: err %v, jobs %d", err, jobs())
	}
	if r.watermark != n-10 {
		t.Fatalf("watermark = %d, want %d", r.watermark, n-10)
	}

	if err := r.Refresh(ctx); err != nil || jobs() != 3 {
		t.Fatalf("nothing new: err %v, jobs %d (the boundary second was re-ingested)", err, jobs())
	}
	if src.sinces[1] != n-10 {
		t.Errorf("second read since %d, want the watermark %d", src.sinces[1], n-10)
	}

	// A late arrival in the boundary second.
	src.add(historyRecord(t, "alice", 4, 100, n-10))
	if err := r.Refresh(ctx); err != nil || jobs() != 4 {
		t.Fatalf("late arrival at the boundary: err %v, jobs %d", err, jobs())
	}
	if err := r.Refresh(ctx); err != nil || jobs() != 4 {
		t.Fatalf("the late arrival was ingested twice: jobs %d", jobs())
	}

	// A newer second moves the watermark.
	src.add(historyRecord(t, "alice", 5, 100, n-5))
	if err := r.Refresh(ctx); err != nil || jobs() != 5 {
		t.Fatalf("newer record: err %v, jobs %d", err, jobs())
	}
	if r.watermark != n-5 || len(r.boundary) != 1 {
		t.Errorf("watermark %d boundary %v", r.watermark, r.boundary)
	}
	if err := r.Refresh(ctx); err != nil || jobs() != 5 {
		t.Fatalf("after the move: jobs %d", jobs())
	}
}

// A failed read applies nothing and moves nothing: the estimator keeps
// answering from what it had, and the next read covers the same window.
func TestRuntimeRefresherErrorKeepsState(t *testing.T) {
	src := &fakeRuntimeHistory{}
	n := refreshNow.Unix()
	src.add(
		historyRecord(t, "alice", 1, 100, n-30),
		historyRecord(t, "alice", 2, 100, n-20),
		historyRecord(t, "alice", 3, 100, n-10),
	)
	r := testRefresher(t, src, refreshNow)
	ctx := context.Background()
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	before := r.est.Stats()
	wm := r.watermark

	src.setErr(errors.New("mirror unreachable"))
	src.add(historyRecord(t, "alice", 4, 100, n-5))
	if err := r.Refresh(ctx); err == nil {
		t.Fatal("the error was swallowed")
	}
	if after := r.est.Stats(); after.JobsIngested != before.JobsIngested {
		t.Errorf("a failed refresh changed the estimator: %d -> %d", before.JobsIngested, after.JobsIngested)
	}
	if r.watermark != wm {
		t.Errorf("a failed refresh moved the watermark")
	}
	if _, errs, _ := r.status(); errs != 1 {
		t.Errorf("errors = %d", errs)
	}
	res := r.est.Estimate(runtimeest.Query{Features: runtimeest.Features{Owner: "alice", Cmd: "x"}})
	if !res.Available {
		t.Errorf("estimates stopped after a failed refresh: %+v", res)
	}

	src.setErr(nil)
	if err := r.Refresh(ctx); err != nil || r.est.Stats().JobsIngested != 4 {
		t.Errorf("recovery: err %v, jobs %d", err, r.est.Stats().JobsIngested)
	}
}

// A read that fails before anything was ever loaded leaves the
// estimator warming up.
func TestRuntimeRefresherNeverLoaded(t *testing.T) {
	src := &fakeRuntimeHistory{err: errors.New("no mirror")}
	r := testRefresher(t, src, refreshNow)
	_ = r.Refresh(context.Background())
	if res := r.est.Estimate(runtimeest.Query{}); res.Reason != runtimeest.ReasonWarmingUp {
		t.Errorf("reason = %q", res.Reason)
	}
}

// Hitting the row cap keeps the newest records and says so.
func TestRuntimeRefresherRowCap(t *testing.T) {
	src := &fakeRuntimeHistory{}
	n := refreshNow.Unix()
	src.add(
		historyRecord(t, "alice", 1, 100, n-30),
		historyRecord(t, "alice", 2, 200, n-20),
		historyRecord(t, "alice", 3, 300, n-10),
	)
	r := testRefresher(t, src, refreshNow)
	r.maxRows = 2
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.est.Stats().JobsIngested; got != 2 {
		t.Errorf("ingested %d, want the cap", got)
	}
	if _, _, truncs := r.status(); truncs != 1 {
		t.Errorf("truncations = %d", truncs)
	}
}

// Eviction runs with the backfill window: a group with nothing newer is
// dropped once a refresh has moved past it.
func TestRuntimeRefresherEvicts(t *testing.T) {
	src := &fakeRuntimeHistory{}
	n := refreshNow.Unix()
	src.add(historyRecord(t, "alice", 1, 100, n-3600))
	r := testRefresher(t, src, refreshNow)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.est.Stats().Owners != 1 {
		t.Fatal("alice was not loaded")
	}
	r.now = func() time.Time { return refreshNow.Add(48 * time.Hour) }
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := r.est.Stats(); st.Owners != 0 || st.Keys["owner"] != 0 {
		t.Errorf("stale owner kept: %+v", st)
	}
}

// Interval 0 turns the feature off, and so does having no mirror to read
// history from. Either way nothing is started.
func TestRuntimeEstimatesDisabled(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("COLLECTOR_HOST", "127.0.0.1:1")
	withMirror := dbmirror.NewLocatorWithOptions(nil, cfg, dbmirror.Options{Address: "<127.0.0.1:1>"})
	if !withMirror.Enabled() {
		t.Fatal("test locator is not enabled")
	}

	h := &Handler{logger: testLogger(t), dbMirror: withMirror}
	h.initRuntimeEstimates(HandlerConfig{RuntimeEstimateInterval: 0})
	if h.runtimeEst != nil || h.runtimeRefresher != nil {
		t.Error("interval 0 built an estimator")
	}
	h.startRuntimeEstimates(context.Background()) // must not start anything or panic

	h = &Handler{logger: testLogger(t)}
	h.initRuntimeEstimates(HandlerConfig{RuntimeEstimateInterval: time.Minute})
	if h.runtimeEst != nil {
		t.Error("an estimator was built with no mirror to read from")
	}

	h = &Handler{logger: testLogger(t), dbMirror: withMirror}
	h.initRuntimeEstimates(HandlerConfig{RuntimeEstimateInterval: time.Minute})
	if h.runtimeEst == nil || h.runtimeRefresher == nil {
		t.Fatal("enabled with a mirror, but no estimator")
	}
	if h.runtimeRefresher.backfill != defaultRuntimeEstimateBackfill {
		t.Errorf("backfill = %v", h.runtimeRefresher.backfill)
	}
}

// The mirror source refuses to read a mirror the history policy
// declines, rather than build estimates from stale or gapped history.
func TestMirrorRuntimeHistoryHonoursTheGate(t *testing.T) {
	cfg := config.NewEmpty()
	loc := dbmirror.NewLocatorWithOptions(nil, cfg, dbmirror.Options{})
	err := mirrorRuntimeHistory{locator: loc, gate: runtimeHistoryGate}.History(context.Background(), 0, 10, func(*classad.ClassAd) {})
	if err == nil {
		t.Error("an unconfigured mirror was read")
	}
	if d := runtimeHistoryGate(&dbmirror.Info{Address: "<x>"}); d.Use {
		t.Errorf("a never-synced mirror passed the gate: %+v", d)
	}
}

type estimateBody struct {
	JobID string `json:"job_id"`
	runtimeest.Result
}

func (f *twoOwnerFixture) estimate(t *testing.T, id string, auth func(*http.Request)) (int, estimateBody) {
	t.Helper()
	w := f.do(t, http.MethodGet, "/api/v1/jobs/"+id+"/runtime-estimate", "", auth)
	var body estimateBody
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding %s: %v", w.Body.String(), err)
		}
	}
	return w.Code, body
}

// runtimeFixture is the two-owner server with an estimator that has
// read alice's 100-second jobs and bob's 5000-second ones.
func runtimeFixture(t *testing.T) *twoOwnerFixture {
	t.Helper()
	f := twoOwnerScheddServer(t)
	est := runtimeest.New(runtimeest.Config{})
	b := runtimeest.NewBatch()
	for i := range 5 {
		b.AddAd(historyRecord(t, "alice", 100+i, 100, 1_000_000+int64(i)))
		b.AddAd(historyRecord(t, "bob", 200+i, 5000, 1_000_000+int64(i)))
	}
	est.Ingest(b)
	f.s.runtimeEst = est
	return f
}

func TestRuntimeEstimateEndpointOwnerScope(t *testing.T) {
	f := runtimeFixture(t)
	alice := f.bearer(t, "alice")

	code, body := f.estimate(t, "1.0", alice)
	if code != http.StatusOK {
		t.Fatalf("alice's own job: status %d", code)
	}
	if !body.Available || body.EstimateSeconds != 100 || body.Basis == nil || body.Basis.Level != "owner" {
		t.Errorf("alice's estimate came from someone else's history: %+v", body)
	}
	if body.JobID != "1.0" || body.Model.JobsIngested != 10 {
		t.Errorf("envelope: %+v", body)
	}

	// Bob's job is not found for alice, the same as any other job read.
	if code, _ := f.estimate(t, "2.0", alice); code != http.StatusNotFound {
		t.Errorf("alice asking about bob's job: status %d, want 404", code)
	}
	code, body = f.estimate(t, "2.0", f.bearer(t, "bob"))
	if code != http.StatusOK || body.EstimateSeconds != 5000 {
		t.Errorf("bob's own job: status %d, %+v", code, body)
	}
	if code, _ := f.estimate(t, "999.0", alice); code != http.StatusNotFound {
		t.Errorf("missing job: status %d", code)
	}
	if code, _ := f.estimate(t, "nonsense", alice); code != http.StatusBadRequest {
		t.Errorf("bad id: status %d", code)
	}
}

func TestRuntimeEstimateEndpointRunningJob(t *testing.T) {
	f := runtimeFixture(t)
	running := fakeschedd.JobAd(3, 0, "alice", 2)
	running.InsertAttr("JobCurrentStartDate", time.Now().Unix()-40)
	f.schedd.AddJobs(running)

	code, body := f.estimate(t, "3.0", f.bearer(t, "alice"))
	if code != http.StatusOK || !body.Available {
		t.Fatalf("status %d, %+v", code, body)
	}
	if body.ElapsedSeconds == nil || *body.ElapsedSeconds < 39 || *body.ElapsedSeconds > 50 {
		t.Errorf("elapsed = %v, want about 40", body.ElapsedSeconds)
	}
	if body.RemainingSeconds == nil || *body.RemainingSeconds < 50 || *body.RemainingSeconds > 61 {
		t.Errorf("remaining = %v, want about 60", body.RemainingSeconds)
	}

	// An idle job has neither.
	_, body = f.estimate(t, "1.0", f.bearer(t, "alice"))
	if body.ElapsedSeconds != nil || body.RemainingSeconds != nil {
		t.Errorf("idle job: %+v", body)
	}
}

func TestRuntimeEstimateEndpointUnavailable(t *testing.T) {
	f := twoOwnerScheddServer(t)
	alice := f.bearer(t, "alice")

	// Disabled: one shape, available false.
	code, body := f.estimate(t, "1.0", alice)
	if code != http.StatusOK || body.Available || body.Reason != runtimeest.ReasonDisabled {
		t.Errorf("disabled: status %d, %+v", code, body)
	}

	// Enabled but nothing read yet.
	f.s.runtimeEst = runtimeest.New(runtimeest.Config{})
	code, body = f.estimate(t, "1.0", alice)
	if code != http.StatusOK || body.Available || body.Reason != runtimeest.ReasonWarmingUp {
		t.Errorf("warming up: status %d, %+v", code, body)
	}

	// Read, but nothing comparable.
	f.s.runtimeEst.Ingest(runtimeest.NewBatch())
	_, body = f.estimate(t, "1.0", alice)
	if body.Available || body.Reason != runtimeest.ReasonInsufficientHistory {
		t.Errorf("no history: %+v", body)
	}

	// Still authenticated first.
	if code, _ := f.estimate(t, "1.0", func(*http.Request) {}); code == http.StatusOK {
		t.Error("an unauthenticated request was answered")
	}
}

func TestRuntimeEstimateRouteIsClassified(t *testing.T) {
	if got := classifyRoute("/api/v1/jobs/12.0/runtime-estimate"); got != "/api/v1/jobs/{id}/runtime-estimate" {
		t.Errorf("classifyRoute = %q", got)
	}
}

func TestRuntimeEstimateIsDocumented(t *testing.T) {
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(openAPISchema), &doc); err != nil {
		t.Fatalf("openapi does not parse: %v", err)
	}
	if _, ok := doc.Paths["/jobs/{jobId}/runtime-estimate"]; !ok {
		t.Error("/jobs/{jobId}/runtime-estimate missing from the OpenAPI paths")
	}
}

// The metrics exist with the feature off, and follow the estimator when
// it is on.
func TestRuntimeEstimateMetrics(t *testing.T) {
	h := &Handler{}
	c := newRuntimeEstimateCollector(h)
	if n := testutil.CollectAndCount(c); n == 0 {
		t.Fatal("no series with the feature off")
	}
	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP htcondor_api_runtime_estimate_enabled 1 if runtime estimates are enabled on this server.
# TYPE htcondor_api_runtime_estimate_enabled gauge
htcondor_api_runtime_estimate_enabled 0
`), "htcondor_api_runtime_estimate_enabled"); err != nil {
		t.Error(err)
	}

	src := &fakeRuntimeHistory{}
	n := refreshNow.Unix()
	for i := range 5 {
		src.add(historyRecord(t, "alice", i+1, 100, n-int64(100-i)))
	}
	h.runtimeRefresher = testRefresher(t, src, refreshNow)
	h.runtimeEst = h.runtimeRefresher.est
	if err := h.runtimeRefresher.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP htcondor_api_runtime_estimate_jobs_ingested_total Completed jobs read into the runtime estimator.
# TYPE htcondor_api_runtime_estimate_jobs_ingested_total counter
htcondor_api_runtime_estimate_jobs_ingested_total 5
`), "htcondor_api_runtime_estimate_jobs_ingested_total"); err != nil {
		t.Error(err)
	}
	if err := testutil.CollectAndCompare(c, strings.NewReader(fmt.Sprintf(`
# HELP htcondor_api_runtime_estimate_last_refresh_timestamp_seconds When the runtime estimator last read the history successfully; 0 before the first time.
# TYPE htcondor_api_runtime_estimate_last_refresh_timestamp_seconds gauge
htcondor_api_runtime_estimate_last_refresh_timestamp_seconds %d
`, n)), "htcondor_api_runtime_estimate_last_refresh_timestamp_seconds"); err != nil {
		t.Error(err)
	}
	// Jobs 4 and 5 had three before them in the exact group.
	st := h.runtimeEst.Stats()
	if st.ScoredByLevel["exact"] != 2 || st.Within2xByLevel["exact"] != 2 {
		t.Errorf("self-evaluation: %+v", st)
	}
}
