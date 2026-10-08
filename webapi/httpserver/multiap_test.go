package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

const (
	ap1 = "ap1.example.org"
	ap2 = "ap2.example.org"
)

// multiAPHub is the standard population: alice has 1.0 on both APs and
// 2.0 on ap1; bob has 1.0 and 5.0 on ap1; alice has history on both.
func multiAPHub(t *testing.T) *multiaptest.DB {
	hub := multiaptest.NewHub(t)
	hub.PutJob(ap1, "alice@d", 1, 0, `Marker = "alice-ap1-1"`)
	hub.PutJob(ap1, "alice@d", 2, 0, `Marker = "alice-ap1-2"`)
	hub.PutJob(ap2, "alice@d", 1, 0, `Marker = "alice-ap2-1"`)
	hub.PutJob(ap1, "bob@d", 1, 0, `Marker = "bob-ap1-1"`)
	hub.PutJob(ap1, "bob@d", 5, 0, `Marker = "bob-ap1-5"`)
	hub.PutHistory(ap1, "alice@d", 7, 0, 1000)
	hub.PutHistory(ap2, "alice@d", 7, 0, 1000)
	hub.PutHistory(ap2, "alice@d", 8, 0, 900)
	hub.PutHistory(ap1, "bob@d", 9, 0, 2000)
	hub.PutSource(ap1, multiap.StateFresh, 2)
	hub.PutSource(ap2, multiap.StateFresh, 3)
	return hub
}

func multiAPService(t *testing.T, hub *multiaptest.DB, reg multiap.Registry) *multiap.Service {
	t.Helper()
	h := multiap.NewHub(hub.Dial, time.Hour)
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &multiap.Service{Registry: reg, Hub: h, Stale: multiap.StaleInclude, UIDDomain: "d"}
}

// newMultiAPServer builds a multi-AP server with routes installed, MCP
// and OAuth2 on, and the user header trusted from anywhere.
func newMultiAPServer(t *testing.T, svc *multiap.Service) *Server {
	t.Helper()
	srv, err := NewServer(Config{
		MultiAP:                  MultiAPConfig{ScheddConstraint: `regexp("^ap", Name)`, service: svc},
		Logger:                   newTestLogger(t),
		EnableMCP:                true,
		OAuth2DBPath:             t.TempDir() + "/oauth2.db",
		OAuth2Issuer:             "http://localhost:8080",
		UserHeader:               "X-Remote-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           writeTestSigningKey(t),
		TrustDomain:              "test.domain",
		UIDDomain:                "d",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.setupRoutes()
	return srv
}

func doAs(t *testing.T, h http.Handler, user, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	if user != "" {
		req.Header.Set("X-Remote-User", user)
	}
	req.Header.Set("Origin", "http://example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type listBody struct {
	Jobs          []map[string]any `json:"jobs"`
	Ads           []map[string]any `json:"ads"`
	HasMore       bool             `json:"has_more"`
	NextPageToken string           `json:"next_page_token"`
	Sources       multiap.Sources  `json:"sources"`
	Error         string           `json:"error"`
}

func decodeList(t *testing.T, rec *httptest.ResponseRecorder) listBody {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var b listBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	if b.Error != "" {
		t.Fatalf("response error: %s", b.Error)
	}
	return b
}

func jobIDs(rows []map[string]any) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r["job_id"].(string))
	}
	sort.Strings(out)
	return out
}

func TestMultiAPListJobsREST(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, multiAPHub(t), multiaptest.NewRegistry(ap1, ap2)))

	b := decodeList(t, doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs"))
	want := []string{"1.0@" + ap1, "1.0@" + ap2, "2.0@" + ap1}
	if got := jobIDs(b.Jobs); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("alice's jobs = %v, want %v", got, want)
	}
	for _, j := range b.Jobs {
		if j["User"] != "alice@d" {
			t.Errorf("another user's job: %v", j)
		}
		if _, ok := j["cluster"].(float64); !ok || j["schedd"] == "" {
			t.Errorf("row lacks schedd/cluster/proc: %v", j)
		}
	}
	if b.Sources.APs != 2 || b.Sources.Fresh != 2 || b.Sources.Degraded == nil {
		t.Errorf("sources = %+v", b.Sources)
	}

	// The per-AP filter.
	b = decodeList(t, doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs?schedd="+ap2))
	if got := jobIDs(b.Jobs); len(got) != 1 || got[0] != "1.0@"+ap2 || b.Jobs[0]["Marker"] != "alice-ap2-1" {
		t.Errorf("?schedd=ap2 = %v", got)
	}

	// A crafted constraint cannot reach bob's jobs.
	q := url.Values{"constraint": {`User == "bob@d" || true`}}
	b = decodeList(t, doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs?"+q.Encode()))
	for _, j := range b.Jobs {
		if j["User"] != "alice@d" {
			t.Errorf("crafted constraint widened the scope: %v", j)
		}
	}
	q = url.Values{"constraint": {`true) || (true`}}
	if rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs?"+q.Encode()); rec.Code != http.StatusBadRequest {
		t.Errorf("unbalanced constraint: %d %s", rec.Code, rec.Body.String())
	}

	// Pages with the db1: cursor; a hub1: token is refused.
	b = decodeList(t, doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs?limit=2"))
	if !b.HasMore || !strings.HasPrefix(b.NextPageToken, "db1:") {
		t.Fatalf("page 1 = %+v", b)
	}
	b2 := decodeList(t, doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs?limit=2&page_token="+url.QueryEscape(b.NextPageToken)))
	if got := append(jobIDs(b.Jobs), jobIDs(b2.Jobs)...); len(got) != 3 {
		t.Errorf("two pages = %v", got)
	}
	if rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs?page_token=hub1:e30"); rec.Code != http.StatusBadRequest {
		t.Errorf("hub1: token on jobs: %d", rec.Code)
	}

	// No identity, no rows.
	if rec := doAs(t, srv, "", http.MethodGet, "/api/v1/jobs"); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rec.Code)
	}
}

func TestMultiAPHistoryREST(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, multiAPHub(t), multiaptest.NewRegistry(ap1, ap2)))

	seen := map[string]int{}
	token := ""
	for range 10 {
		target := "/api/v1/jobs/archive?limit=1"
		if token != "" {
			target += "&page_token=" + url.QueryEscape(token)
		}
		b := decodeList(t, doAs(t, srv, "alice", http.MethodGet, target))
		for _, a := range b.Ads {
			seen[a["job_id"].(string)]++
			if a["archived"] != true {
				t.Errorf("record not marked archived: %v", a)
			}
		}
		if !b.HasMore {
			break
		}
		token = b.NextPageToken
	}
	if len(seen) != 3 || seen["7.0@"+ap1] != 1 || seen["7.0@"+ap2] != 1 || seen["8.0@"+ap2] != 1 {
		t.Errorf("history pages = %v, want 7.0 on both APs and 8.0 on ap2, once each", seen)
	}
	if rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/archive?before_cluster=7"); rec.Code != http.StatusBadRequest {
		t.Errorf("before_cluster in multi-AP mode: %d", rec.Code)
	}
	if rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/archive?page_token=db1:e30"); rec.Code != http.StatusBadRequest {
		t.Errorf("db1: token on history: %d", rec.Code)
	}
}

func TestMultiAPGetJobREST(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, multiAPHub(t), multiaptest.NewRegistry(ap1, ap2)))

	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/1.0@"+ap2)
	var job map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &job) != nil {
		t.Fatalf("complete id: %d %s", rec.Code, rec.Body.String())
	}
	if job["Marker"] != "alice-ap2-1" || job["schedd"] != ap2 || job["job_id"] != "1.0@"+ap2 || job["source"] != "hub" {
		t.Errorf("complete id served %v", job)
	}

	// Incomplete: one match is served with its complete id.
	rec = doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/2.0")
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &job) != nil || job["job_id"] != "2.0@"+ap1 {
		t.Errorf("2.0: %d %s", rec.Code, rec.Body.String())
	}
	// Two matches: 409 naming both.
	rec = doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/1.0")
	var conflict struct {
		Candidates []multiap.JobRef `json:"candidates"`
	}
	if rec.Code != http.StatusConflict || json.Unmarshal(rec.Body.Bytes(), &conflict) != nil || len(conflict.Candidates) != 2 {
		t.Errorf("1.0: %d %s", rec.Code, rec.Body.String())
	}
	// History-only, and absent.
	rec = doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/8.0")
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &job) != nil || job["archived"] != true {
		t.Errorf("8.0 (history): %d %s", rec.Code, rec.Body.String())
	}
	for _, id := range []string{"99.0", "5.0", "5.0@" + ap1, "1.0@ap9", "not-an-id"} {
		rec = doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/"+id)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", id, rec.Code, rec.Body.String())
		}
	}
}

func TestMultiAPAPsAndReadyz(t *testing.T) {
	reg := multiaptest.NewRegistry(ap1, ap2, "ap3.example.org")
	srv := newMultiAPServer(t, multiAPService(t, multiAPHub(t), reg))

	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/aps")
	var aps APsResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &aps) != nil {
		t.Fatalf("/api/v1/aps: %d %s", rec.Code, rec.Body.String())
	}
	if len(aps.APs) != 3 || aps.APs[2].Hub.State != multiap.StateAbsent || !aps.Hub.Reachable || len(aps.Sources.Degraded) != 1 {
		t.Errorf("aps = %+v", aps)
	}

	rec = doAs(t, srv, "", http.MethodGet, "/readyz")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ap3.example.org"`) {
		t.Errorf("readyz with one AP absent must stay ready: %d %s", rec.Code, rec.Body.String())
	}

	empty := newMultiAPServer(t, multiAPService(t, multiAPHub(t), multiaptest.NewRegistry()))
	if rec := doAs(t, empty, "", http.MethodGet, "/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz with no APs: %d %s", rec.Code, rec.Body.String())
	}
}

// TestMultiAPRefusesEverythingElse walks every route the server
// registered, with every method, and requires each request outside the
// allowlist to be a 501 -- and that nothing, allowed or refused, reached
// the single-schedd accessor, which has no answer in this mode.
func TestMultiAPRefusesEverythingElse(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, multiAPHub(t), multiaptest.NewRegistry(ap1, ap2)))
	if len(srv.routePatterns) < 40 {
		t.Fatalf("only %d routes recorded; the walk would prove little", len(srv.routePatterns))
	}

	var paths []string
	for _, p := range srv.routePatterns {
		paths = append(paths, p)
		if strings.HasSuffix(p, "/") {
			paths = append(paths, p+"x", p+"1.0@"+ap1+"/stdout")
		}
	}
	// The job sub-resources every action lives under.
	for _, sub := range []string{"input", "output", "stdout", "stderr", "hold", "release", "files", "ssh", "peek", "log", "watch", "proxy/x"} {
		paths = append(paths, "/api/v1/jobs/1.0@"+ap1+"/"+sub)
	}
	refused := 0
	for _, path := range paths {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			req := httptest.NewRequestWithContext(context.Background(), method, path, bytes.NewReader([]byte("{}")))
			req.Header.Set("X-Remote-User", "alice")
			req.Header.Set("Origin", "http://example.com")
			rec := httptest.NewRecorder()
			func() {
				// net/http would recover a handler panic; report it as
				// the route reaching code that has no schedd.
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("%s %s panicked: %v", method, path, p)
						rec.Code = http.StatusInternalServerError
					}
				}()
				srv.ServeHTTP(rec, req)
			}()
			if !multiAPAllowed(method, req.URL.Path) {
				refused++
				if rec.Code != http.StatusNotImplemented {
					t.Errorf("%s %s = %d, want 501", method, path, rec.Code)
				}
			}
		}
	}
	if refused < 100 {
		t.Errorf("only %d requests were refused; the allowlist is not doing its job", refused)
	}
	if n := srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times in multi-AP mode", n)
	}
	if n := srv.Handler.mcpServer.MultiAPScheddCalls(); n != 0 {
		t.Errorf("the MCP server's schedd accessor was called %d times in multi-AP mode", n)
	}

	// Named explicitly, so a regression reads as what it is.
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/jobs"},
		{http.MethodDelete, "/api/v1/jobs"},
		{http.MethodPatch, "/api/v1/jobs"},
		{http.MethodDelete, "/api/v1/jobs/1.0@" + ap1},
		{http.MethodPost, "/api/v1/jobs/1.0@" + ap1 + "/hold"},
		{http.MethodGet, "/api/v1/jobs/1.0@" + ap1 + "/stdout"},
		{http.MethodGet, "/api/v1/dashboard"},
		{http.MethodGet, "/api/v1/jobs/epochs"},
		{http.MethodGet, "/api/v1/creds/user"},
		{http.MethodPost, "/api/v1/interactive/terminal"},
		{http.MethodGet, "/api/v1/schedd/ping"},
	} {
		if rec := doAs(t, srv, "alice", c.method, c.path); rec.Code != http.StatusNotImplemented ||
			!strings.Contains(rec.Body.String(), "multi-AP mode") {
			t.Errorf("%s %s = %d %s, want 501", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}

// TestMultiAPMCPReadsOnly checks the MCP surface through the HTTP
// server's own wiring: the catalogue holds only read tools and a refused
// tool is refused.
func TestMultiAPMCPReadsOnly(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, multiAPHub(t), multiaptest.NewRegistry(ap1, ap2)))
	names := srv.Handler.mcpServer.ToolNames(context.Background())
	sort.Strings(names)
	for _, n := range names {
		switch {
		case n == "query_jobs", n == "get_job", n == "query_job_archive", n == "aggregate_jobs", n == "list_access_points",
			n == "whoami", n == "get_version", n == "doc_guide", n == "skills_list", n == "skills_get", strings.HasPrefix(n, "doc_"):
		default:
			t.Errorf("multi-AP catalogue offers %q", n)
		}
	}
	if len(names) < 5 {
		t.Errorf("catalogue = %v", names)
	}
}
