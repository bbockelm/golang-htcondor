package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// Job resource-usage samples in multi-AP mode: GET
// /api/v1/metrics/job_metrics from the hub's federated job_metrics.
//
// The population repeats an id on purpose. alice's 1.0 is on both APs
// (peak memory 300 on ap1, 700 on ap2); bob's 1.0 is on ap1 too (9999),
// beside his 5.0 (8888). A read that dropped the AP merges alice's two;
// one that dropped the owner scope shows bob's numbers.

// metricsSourceAd is a federation_sources row whose job_metrics stream
// is in the given state: "ok", "absent" (no JobMetrics* attributes) or
// "failing" (not connected, with an error).
func metricsSourceAd(schedd, stream string) string {
	ad := fmt.Sprintf("ScheddName = %q\nState = \"fresh\"\nJobsConnected = true\nHistoryConnected = true\nStalenessSeconds = 1", schedd)
	switch stream {
	case "ok":
		ad += "\nJobMetricsConnected = true\nJobMetricsSynced = true\nJobMetricsSyncedAt = 1000"
	case "failing":
		ad += "\nJobMetricsConnected = false\nJobMetricsLastError = \"no such archive: job_metrics\""
	case "missing":
		ad += "\nJobMetricsMissing = true\nJobMetricsConnected = false\nJobMetricsSynced = false\n" +
			"JobMetricsLastError = \"the spoke has no job_metrics table (HTCONDORDB_JOB_METRICS is not enabled on it)\""
	}
	return ad
}

// metricsHub is multiAPHub with job_metrics federated from both APs and
// the samples above.
func metricsHub(t *testing.T, ap2Stream string) *multiaptest.DB {
	t.Helper()
	hub := multiAPHub(t)
	hub.EnableJobMetrics()
	for _, s := range []struct {
		schedd, user  string
		cluster, proc int
		run           int
		at            int64
		mem           int
	}{
		{ap1, "alice@d", 1, 0, 0, 900, 100},
		{ap1, "alice@d", 1, 0, 0, 1000, 300},
		{ap1, "alice@d", 2, 0, 0, 900, 50},
		{ap2, "alice@d", 1, 0, 0, 900, 700},
		{ap2, "alice@d", 1, 0, 1, 1900, 650},
		{ap1, "bob@d", 1, 0, 0, 900, 9999},
		{ap1, "bob@d", 5, 0, 0, 900, 8888},
	} {
		hub.PutMetric(s.schedd, s.user, s.cluster, s.proc, s.run, s.at, fmt.Sprintf("MemoryUsage = %d", s.mem))
	}
	hub.PutSourceAd(ap1, metricsSourceAd(ap1, "ok"))
	hub.PutSourceAd(ap2, metricsSourceAd(ap2, ap2Stream))
	return hub
}

func metricsServer(t *testing.T, hub *multiaptest.DB) *Server {
	t.Helper()
	return newMultiAPServer(t, multiAPService(t, hub, multiaptest.NewRegistry(ap1, ap2)))
}

// metricsBody is a decoded multi-AP metrics response.
type metricsBody struct {
	metricsResponse
	Sources *multiap.Sources `json:"sources"`
	Job     *metricsJob      `json:"job"`
}

func getMetrics(t *testing.T, srv http.Handler, user string, params url.Values) metricsBody {
	t.Helper()
	rec := doAs(t, srv, user, http.MethodGet, "/api/v1/metrics/job_metrics?"+params.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("%s as %s: %d %s", params.Encode(), user, rec.Code, rec.Body.String())
	}
	var b metricsBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return b
}

// rowsText renders the rows as "a|b|c" lines, sorted, string cells
// unquoted.
func rowsText(b metricsBody) []string {
	var out []string
	for _, r := range b.Rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = strings.Trim(c, `"`)
		}
		out = append(out, strings.Join(cells, "|"))
	}
	sort.Strings(out)
	return out
}

func columnNames(b metricsBody) []string {
	var out []string
	for _, c := range b.Columns {
		out = append(out, c.Name)
	}
	return out
}

func TestMultiAPMetricsOneJob(t *testing.T) {
	srv := metricsServer(t, metricsHub(t, "ok"))

	// The job page's query, for each AP's 1.0.
	for _, c := range []struct {
		job  string
		want []string
	}{
		{"1.0@" + ap1, []string{"0|900|300"}},
		{"1.0@" + ap2, []string{"0|900|700", "1|1800|650"}},
	} {
		b := getMetrics(t, srv, "alice", url.Values{"job_id": {c.job}, "group_by": {"RunInstanceID"},
			"bucket": {"900"}, "agg": {"max:MemoryUsage"}})
		if !b.Enabled {
			t.Fatalf("%s: enabled=false", c.job)
		}
		if got := rowsText(b); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: rows %v, want %v: that AP's samples of alice's job only", c.job, got, c.want)
		}
		if b.Job == nil || b.Job.JobID != c.job || b.Job.Cluster != 1 || b.Job.Proc != 0 {
			t.Errorf("%s: job = %+v, want the complete id", c.job, b.Job)
		}
		if b.Sources == nil || b.Sources.APs != 2 {
			t.Errorf("%s: sources = %+v", c.job, b.Sources)
		}
	}

	// bob's 1.0 on ap1 is his.
	b := getMetrics(t, srv, "bob", url.Values{"job_id": {"1.0@" + ap1}, "agg": {"max:MemoryUsage"}})
	if got := rowsText(b); strings.Join(got, ",") != "9999" {
		t.Errorf("bob's 1.0@%s = %v, want his 9999", ap1, got)
	}
}

func TestMultiAPMetricsBareJobID(t *testing.T) {
	srv := metricsServer(t, metricsHub(t, "ok"))

	// 1.0 is alice's on both APs: named, not merged.
	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/metrics/job_metrics?job_id=1.0&agg=max:MemoryUsage")
	if rec.Code != http.StatusConflict {
		t.Fatalf("bare 1.0 = %d %s, want 409", rec.Code, rec.Body.String())
	}
	var conflict struct {
		Candidates []multiap.JobRef `json:"candidates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &conflict); err != nil {
		t.Fatal(err)
	}
	var cands []string
	for _, c := range conflict.Candidates {
		cands = append(cands, c.JobID)
	}
	if strings.Join(cands, ",") != "1.0@"+ap1+",1.0@"+ap2 {
		t.Errorf("candidates = %v, want both APs' 1.0", cands)
	}

	// 2.0 is alice's on ap1 alone (bob's 1.0 there does not count).
	b := getMetrics(t, srv, "alice", url.Values{"job_id": {"2.0"}, "agg": {"max:MemoryUsage"}})
	if b.Job == nil || b.Job.Schedd != ap1 || b.Job.JobID != "2.0@"+ap1 {
		t.Errorf("bare 2.0 resolved to %+v, want 2.0@%s", b.Job, ap1)
	}
	if got := rowsText(b); strings.Join(got, ",") != "50" {
		t.Errorf("bare 2.0 = %v, want 50", got)
	}
	// bob has 1.0 on ap1 only, so his bare 1.0 is that one.
	b = getMetrics(t, srv, "bob", url.Values{"job_id": {"1.0"}, "agg": {"max:MemoryUsage"}})
	if b.Job == nil || b.Job.Schedd != ap1 || strings.Join(rowsText(b), ",") != "9999" {
		t.Errorf("bob's bare 1.0 = %+v %v, want 1.0@%s, 9999", b.Job, rowsText(b), ap1)
	}

	// A job that is not the caller's anywhere.
	if rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/metrics/job_metrics?job_id=5.0&agg=max:MemoryUsage"); rec.Code != http.StatusNotFound {
		t.Errorf("alice's bare 5.0 (bob's) = %d %s, want 404", rec.Code, rec.Body.String())
	}
	// A job_id and a schedd that disagree.
	if rec := doAs(t, srv, "alice", http.MethodGet,
		"/api/v1/metrics/job_metrics?agg=count:*&schedd="+ap2+"&job_id="+url.QueryEscape("1.0@"+ap1)); rec.Code != http.StatusBadRequest {
		t.Errorf("job_id on ap1 with schedd=ap2 = %d %s, want 400", rec.Code, rec.Body.String())
	}
	if rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/metrics/job_metrics?agg=count:*&job_id=x.y"); rec.Code != http.StatusBadRequest {
		t.Errorf("job_id x.y = %d %s, want 400", rec.Code, rec.Body.String())
	}
}

func TestMultiAPMetricsOwnerScope(t *testing.T) {
	srv := metricsServer(t, metricsHub(t, "ok"))
	all := url.Values{"group_by": {"ClusterId,ProcId"}, "agg": {"max:MemoryUsage"}}

	// ScheddName is grouped beside the job's numbers: alice's two 1.0s
	// stay two rows.
	b := getMetrics(t, srv, "alice", all)
	if got := strings.Join(columnNames(b), ","); got != "ScheddName,ClusterId,ProcId,max_MemoryUsage" {
		t.Errorf("columns = %s, want ScheddName before ClusterId", got)
	}
	want := []string{ap1 + "|1|0|300", ap1 + "|2|0|50", ap2 + "|1|0|700"}
	if got := rowsText(b); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("alice's jobs = %v, want %v", got, want)
	}
	b = getMetrics(t, srv, "bob", all)
	want = []string{ap1 + "|1|0|9999", ap1 + "|5|0|8888"}
	if got := rowsText(b); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("bob's jobs = %v, want %v", got, want)
	}

	// The caller's constraint cannot widen the scope.
	for _, c := range []string{`User == "bob@d" || true`, `true || User =!= "alice@d"`} {
		b := getMetrics(t, srv, "alice", url.Values{"constraint": {c}, "agg": {"max:MemoryUsage"}})
		if got := strings.Join(rowsText(b), ","); got != "700" {
			t.Errorf("constraint %q: max memory %s, want alice's 700", c, got)
		}
	}
	if rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/metrics/job_metrics?agg=count:*&constraint="+
		url.QueryEscape("true) || (true")); rec.Code != http.StatusBadRequest {
		t.Errorf("an unbalanced constraint = %d %s, want 400", rec.Code, rec.Body.String())
	}

	// Nor can a time window spliced beside it.
	b = getMetrics(t, srv, "alice", url.Values{"agg": {"count:*"}, "since": {"1000"}})
	if got := strings.Join(rowsText(b), ","); got != "2" {
		t.Errorf("since=1000: %s samples, want alice's 2", got)
	}
}

// TestMultiAPMetricsAdminsAreNotWidened: a web UI administrator who is
// a queue superuser on every AP still reads only their own samples, as
// on every other multi-AP read.
func TestMultiAPMetricsAdminsAreNotWidened(t *testing.T) {
	svc := multiAPService(t, metricsHub(t, "ok"), multiaptest.NewRegistry(ap1, ap2))
	srv, err := NewServer(Config{
		MultiAP: MultiAPConfig{ScheddConstraint: `regexp("^ap", Name)`, service: svc,
			queueSuperUser: func(string, string) bool { return true }},
		Logger:                   newTestLogger(t),
		UserHeader:               "X-Remote-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           writeTestSigningKey(t),
		TrustDomain:              "test.domain",
		UIDDomain:                "d",
		MCPAdminUsers:            []string{"alice"},
		OAuth2DBPath:             t.TempDir() + "/oauth2.db",
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.setupRoutes()
	b := getMetrics(t, srv, "alice", url.Values{"group_by": {"User"}, "agg": {"count:*"}})
	if got := strings.Join(rowsText(b), ","); got != "alice@d|5" {
		t.Errorf("an administrator read %s, want only their own 5 samples", got)
	}
}

func TestMultiAPMetricsGroupByScheddName(t *testing.T) {
	srv := metricsServer(t, metricsHub(t, "ok"))
	b := getMetrics(t, srv, "alice", url.Values{"group_by": {"ScheddName"}, "agg": {"count:*,max:MemoryUsage"}})
	want := []string{ap1 + "|3|300", ap2 + "|2|700"}
	if got := rowsText(b); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("per AP = %v, want %v", got, want)
	}
	if got := strings.Join(columnNames(b), ","); got != "ScheddName,count_*,max_MemoryUsage" {
		t.Errorf("columns = %s", got)
	}
	// ?schedd= reads one AP.
	b = getMetrics(t, srv, "alice", url.Values{"schedd": {ap2}, "agg": {"count:*"}})
	if got := strings.Join(rowsText(b), ","); got != "2" {
		t.Errorf("schedd=%s: %s samples, want 2", ap2, got)
	}
	if rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/metrics/job_metrics?agg=count:*&schedd=ap9.example.org"); rec.Code != http.StatusBadRequest {
		t.Errorf("a schedd outside the set = %d, want 400", rec.Code)
	}
}

func TestWithScheddGroup(t *testing.T) {
	for in, want := range map[string]string{
		"":                           "",
		"RunInstanceID":              "RunInstanceID",
		"ClusterId":                  "ScheddName,ClusterId",
		"Owner,ProcId,ClusterId":     "Owner,ScheddName,ProcId,ClusterId",
		"clusterid, procid":          "ScheddName,clusterid,procid",
		"ScheddName,ClusterId":       "ScheddName,ClusterId",
		"ClusterId,scheddname":       "ClusterId,scheddname",
		"GlobalJobId,RunInstanceID":  "GlobalJobId,RunInstanceID",
		"ProjectName,RunInstanceID ": "ProjectName,RunInstanceID ",
	} {
		if got := withScheddGroup(in); got != want {
			t.Errorf("withScheddGroup(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMultiAPMetricsDegradedAP: an AP whose job_metrics stream is not
// federated, or not connected, is named in sources -- its samples may be
// missing -- and the other AP's are served.
func TestMultiAPMetricsDegradedAP(t *testing.T) {
	for _, stream := range []string{"absent", "failing"} {
		t.Run(stream, func(t *testing.T) {
			srv := metricsServer(t, metricsHub(t, stream))
			b := getMetrics(t, srv, "alice", url.Values{"group_by": {"ScheddName"}, "agg": {"count:*"}})
			if !b.Enabled || b.Sources == nil {
				t.Fatalf("enabled=%v sources=%v", b.Enabled, b.Sources)
			}
			if b.Sources.APs != 2 || b.Sources.Fresh != 1 || len(b.Sources.Degraded) != 1 {
				t.Fatalf("sources = %+v, want ap2 alone degraded", b.Sources)
			}
			d := b.Sources.Degraded[0]
			if d.Schedd != ap2 || !strings.Contains(d.Reason, multiap.TableJobMetrics) {
				t.Errorf("degraded = %+v, want %s with a reason naming job_metrics", d, ap2)
			}
			if got := rowsText(b); len(got) == 0 || !strings.HasPrefix(got[0], ap1+"|") {
				t.Errorf("rows = %v, want ap1's", got)
			}
		})
	}
}

// TestMultiAPMetricsNotFederated: a hub with no job_metrics answers the
// single-AP "sampler off" shape, with the sources block naming why, for
// a sources table that lists no JobMetrics* and for one that lists it
// before the hub has created the archive.
func TestMultiAPMetricsNotFederated(t *testing.T) {
	t.Run("not listed", func(t *testing.T) {
		srv := metricsServer(t, multiAPHub(t))
		for _, q := range []string{"agg=max:MemoryUsage", "job_id=1.0&agg=max:MemoryUsage", "agg=bogus"} {
			b := getMetrics(t, srv, "alice", mustQuery(t, q))
			if b.Enabled || b.Table != multiap.TableJobMetrics || len(b.Rows) != 0 || len(b.Columns) != 0 {
				t.Errorf("%s: %+v, want enabled=false and nothing else", q, b.metricsResponse)
			}
			if b.Sources == nil || len(b.Sources.Degraded) != 2 {
				t.Errorf("%s: sources = %+v, want both APs named", q, b.Sources)
			}
		}
	})
	t.Run("listed, no archive", func(t *testing.T) {
		hub := multiAPHub(t)
		hub.PutSourceAd(ap1, metricsSourceAd(ap1, "ok"))
		srv := metricsServer(t, hub)
		b := getMetrics(t, srv, "alice", url.Values{"agg": {"max:MemoryUsage"}})
		if b.Enabled || b.Table != multiap.TableJobMetrics {
			t.Errorf("%+v, want enabled=false", b.metricsResponse)
		}
	})
}

func mustQuery(t *testing.T, q string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestMultiAPMetricsRefusesForeignDomain(t *testing.T) {
	srv := metricsServer(t, metricsHub(t, "ok"))
	for _, who := range []string{"alice@elsewhere", "bob@elsewhere"} {
		rec := doAs(t, srv, who, http.MethodGet, "/api/v1/metrics/job_metrics?agg=count:*")
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s = %d %s, want 403", who, rec.Code, rec.Body.String())
		}
	}
	if rec := doAs(t, srv, "", http.MethodGet, "/api/v1/metrics/job_metrics?agg=count:*"); rec.Code != http.StatusUnauthorized {
		t.Errorf("no identity = %d, want 401", rec.Code)
	}
	// The local domain spelled out is the same user.
	b := getMetrics(t, srv, "alice@d", url.Values{"agg": {"count:*"}})
	if got := strings.Join(rowsText(b), ","); got != "5" {
		t.Errorf("alice@d: %s samples, want 5", got)
	}
}

// TestMultiAPMetricsAllowlist: GET of job_metrics and nothing else under
// /api/v1/metrics/.
func TestMultiAPMetricsAllowlist(t *testing.T) {
	for _, c := range []struct {
		method, path string
		ok           bool
	}{
		{http.MethodGet, "/api/v1/metrics/job_metrics", true},
		{http.MethodHead, "/api/v1/metrics/job_metrics", false},
		{http.MethodPost, "/api/v1/metrics/job_metrics", false},
		{http.MethodPut, "/api/v1/metrics/job_metrics", false},
		{http.MethodDelete, "/api/v1/metrics/job_metrics", false},
		{http.MethodGet, "/api/v1/metrics/job_metrics/", false},
		{http.MethodGet, "/api/v1/metrics/job_metrics/x", false},
		{http.MethodGet, "/api/v1/metrics/history", false},
		{http.MethodGet, "/api/v1/metrics/", false},
		{http.MethodGet, "/api/v1/metrics", false},
	} {
		if got := multiAPAllowed(c.method, c.path); got != c.ok {
			t.Errorf("multiAPAllowed(%s %s) = %v, want %v", c.method, c.path, got, c.ok)
		}
	}
	srv := metricsServer(t, metricsHub(t, "ok"))
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/metrics/job_metrics?agg=count:*"},
		{http.MethodGet, "/api/v1/metrics/history?agg=count:*"},
	} {
		if rec := doAs(t, srv, "alice", c.method, c.path); rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s = %d %s, want 501", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	if n := srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times", n)
	}
}

// TestMetricsSingleAPShapeUnchanged pins single-AP mode's answers: the
// sampler-off body, and an enabled body, carry no multi-AP member.
func TestMetricsSingleAPShapeUnchanged(t *testing.T) {
	s := unidentifiedReadsServer(t)
	s.dbMirror = singleAPMirror(HandlerConfig{}, nil) // no mirror: the sampler is off
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/metrics/job_metrics?agg=count:*&job_id=1.0", nil)
	withSession(t, s, req, "alice")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"enabled":false,"table":"job_metrics"}` {
		t.Errorf("single-AP sampler off = %d %s, want exactly enabled=false and the table", rec.Code, rec.Body.String())
	}

	resp := metricsResult("job_metrics", metricsTables["job_metrics"], 900,
		[]metricsColumn{{Name: "ClusterId", Kind: "group"}, {Name: "SampleTime", Kind: "group", BucketSeconds: 900},
			{Name: "max_MemoryUsage", Kind: "metric", Func: "max", Attr: "MemoryUsage"}},
		[]dbrpc.AggRow{{Group: []string{"1", "900"}, Values: []string{"300"}}})
	got, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"enabled":true,"table":"job_metrics","time_attr":"SampleTime","bucket_seconds":900,` +
		`"columns":[{"name":"ClusterId","kind":"group"},{"name":"SampleTime","kind":"group","bucket_seconds":900},` +
		`{"name":"max_MemoryUsage","kind":"metric","func":"max","attr":"MemoryUsage"}],"rows":[["1","900","300"]]}`
	if string(got) != want {
		t.Errorf("single-AP body =\n%s\nwant\n%s", got, want)
	}
}

// TestMultiAPMetricsAPWithoutJobMetrics: an AP whose spoke keeps no
// job_metrics is named in not_kept, with the hub's reason, and is not a
// fault: it stays fresh and out of degraded.
func TestMultiAPMetricsAPWithoutJobMetrics(t *testing.T) {
	srv := metricsServer(t, metricsHub(t, "missing"))
	b := getMetrics(t, srv, "alice", url.Values{"group_by": {"ScheddName"}, "agg": {"count:*"}})
	if !b.Enabled || b.Sources == nil {
		t.Fatalf("enabled=%v sources=%v", b.Enabled, b.Sources)
	}
	if b.Sources.Fresh != 2 || len(b.Sources.Degraded) != 0 {
		t.Errorf("sources = %+v, want both fresh and nothing degraded", b.Sources)
	}
	if len(b.Sources.NotKept) != 1 || b.Sources.NotKept[0].Schedd != ap2 || b.Sources.NotKept[0].Table != multiap.TableJobMetrics ||
		!strings.Contains(b.Sources.NotKept[0].Reason, "HTCONDORDB_JOB_METRICS") {
		t.Errorf("not_kept = %+v, want ap2's job_metrics with the hub's reason", b.Sources.NotKept)
	}
}

// TestMultiAPMetricsServiceTrustsTheSourcesTable: the service reads
// samples only from a hub whose federation_sources list job_metrics,
// even when an archive of that name is there.
func TestMultiAPMetricsServiceTrustsTheSourcesTable(t *testing.T) {
	hub := multiAPHub(t)
	hub.EnableJobMetrics()
	hub.PutMetric(ap1, "alice@d", 1, 0, 0, 900, "MemoryUsage = 1")
	svc := multiAPService(t, hub, multiaptest.NewRegistry(ap1, ap2))
	res, err := svc.AggregateMetrics(context.Background(), multiap.MetricsRequest{
		User: "alice@d", Aggs: []dbrpc.AggSpec{{Func: dbrpc.AggCount, Arg: "*"}},
	})
	if !errors.Is(err, multiap.ErrMetricsNotFederated) || res == nil || len(res.Rows) != 0 || len(res.Sources.Degraded) != 2 {
		t.Errorf("AggregateMetrics = %+v, %v; want ErrMetricsNotFederated and both APs named", res, err)
	}
}
