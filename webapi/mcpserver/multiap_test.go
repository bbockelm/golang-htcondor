package mcpserver

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

const (
	mAP1 = "ap1.example.org"
	mAP2 = "ap2.example.org"
)

func newMultiAPMCP(t *testing.T) *Server {
	t.Helper()
	hub := multiaptest.NewHub(t)
	hub.PutJob(mAP1, "alice@d", 1, 0, `Marker = "alice-ap1-1"`)
	hub.PutJob(mAP2, "alice@d", 1, 0, `Marker = "alice-ap2-1"`)
	hub.PutJob(mAP1, "alice@d", 2, 0, "")
	hub.PutJob(mAP1, "bob@d", 3, 0, "")
	hub.PutHistory(mAP2, "alice@d", 9, 0, 100)
	hub.PutSource(mAP1, multiap.StateFresh, 1)
	hub.PutSource(mAP2, multiap.StateStale, 400)
	h := multiap.NewHub(hub.Dial, time.Hour)
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc := &multiap.Service{
		Registry: multiaptest.NewRegistry(mAP1, mAP2), Hub: h,
		Codec: jobid.Default(), Stale: multiap.StaleInclude, UIDDomain: "d",
	}
	s, err := NewServer(Config{MultiAP: svc, MultiAPConstraint: `regexp("^ap", Name)`, Delegated: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

func callAs(t *testing.T, s *Server, user, tool string, args map[string]any) (map[string]any, error) {
	t.Helper()
	ctx := htcondor.WithAuthenticatedUser(context.Background(), user)
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": args})
	res, err := s.handleCallTool(ctx, params)
	if err != nil {
		return nil, err
	}
	m, _ := res.(map[string]interface{})
	sc, _ := m["structuredContent"].(map[string]interface{})
	return sc, nil
}

func TestMultiAPCatalogIsAnAllowlist(t *testing.T) {
	s := newMultiAPMCP(t)
	names := s.ToolNames(context.Background())
	sort.Strings(names)
	for _, n := range names {
		if !multiAPToolAllowed(n) {
			t.Errorf("multi-AP catalogue offers %q", n)
		}
	}
	for _, want := range []string{"query_jobs", "get_job", "query_job_archive", "aggregate_jobs", "list_access_points", "whoami"} {
		found := false
		for _, n := range names {
			found = found || n == want
		}
		if !found {
			t.Errorf("multi-AP catalogue lacks %q: %v", want, names)
		}
	}
	// Every single-AP tool outside the allowlist is refused when called.
	single, err := NewServer(Config{ScheddName: "x", ScheddAddr: "127.0.0.1:9618"})
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, n := range single.ToolNames(context.Background()) {
		if multiAPToolAllowed(n) {
			continue
		}
		refused++
		if _, err := callAs(t, s, "alice", n, map[string]any{}); err == nil || !strings.Contains(err.Error(), "multi-access-point") {
			t.Errorf("%s: err = %v, want a multi-AP refusal", n, err)
		}
	}
	if refused < 20 {
		t.Errorf("only %d tools refused", refused)
	}
	if n := s.MultiAPScheddCalls(); n != 0 {
		t.Errorf("getSchedd called %d times in multi-AP mode", n)
	}
	if !strings.Contains(*s.instructions.Load(), "list_access_points") {
		t.Errorf("instructions do not describe the AP set: %q", *s.instructions.Load())
	}
}

func TestMultiAPQueryJobsTool(t *testing.T) {
	s := newMultiAPMCP(t)
	sc, err := callAs(t, s, "alice", "query_jobs", map[string]any{"projection": []any{"Marker"}})
	if err != nil {
		t.Fatal(err)
	}
	jobs, _ := sc["jobs"].([]map[string]interface{})
	var ids []string
	for _, j := range jobs {
		ids = append(ids, j["job_id"].(string))
		if j["User"] != nil && j["User"] != "alice@d" {
			t.Errorf("another user's job: %v", j)
		}
	}
	sort.Strings(ids)
	if strings.Join(ids, " ") != "1.0@"+mAP1+" 1.0@"+mAP2+" 2.0@"+mAP1 {
		t.Errorf("alice's jobs = %v", ids)
	}
	src, _ := sc["sources"].(multiap.Sources)
	if len(src.Degraded) != 1 || src.Degraded[0].Schedd != mAP2 {
		t.Errorf("sources = %+v", sc["sources"])
	}

	sc, err = callAs(t, s, "alice", "query_jobs", map[string]any{"schedd": mAP2})
	if err != nil {
		t.Fatal(err)
	}
	if jobs, _ := sc["jobs"].([]map[string]interface{}); len(jobs) != 1 || jobs[0]["schedd"] != mAP2 {
		t.Errorf("schedd filter = %v", sc["jobs"])
	}
	if _, err := callAs(t, s, "alice@other.example", "query_jobs", nil); err == nil {
		t.Error("an identity in another domain must be refused, not read as alice@d")
	}
	if _, err := callAs(t, s, "", "query_jobs", nil); err == nil {
		t.Error("an unidentified caller must be refused")
	}
}

func TestMultiAPGetJobTool(t *testing.T) {
	s := newMultiAPMCP(t)
	sc, err := callAs(t, s, "alice", "get_job", map[string]any{"job_id": "2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if sc["job_id"] != "2.0@"+mAP1 || sc["schedd"] != mAP1 {
		t.Errorf("2.0 resolved to %v", sc)
	}
	if _, err := callAs(t, s, "alice", "get_job", map[string]any{"job_id": "1.0"}); err == nil ||
		!strings.Contains(err.Error(), "1.0@"+mAP1) || !strings.Contains(err.Error(), "1.0@"+mAP2) {
		t.Errorf("ambiguous 1.0: err = %v, want both candidates", err)
	}
	sc, err = callAs(t, s, "alice", "get_job", map[string]any{"schedd": mAP2, "cluster": float64(9), "proc": float64(0)})
	if err != nil || sc["archived"] != true {
		t.Errorf("9.0 on ap2 (history): %v %v", sc, err)
	}
	if _, err := callAs(t, s, "alice", "get_job", map[string]any{"job_id": "3.0@" + mAP1}); err == nil {
		t.Error("bob's job must not be readable by alice")
	}
}

func TestMultiAPAggregateAndAPs(t *testing.T) {
	s := newMultiAPMCP(t)
	sc, err := callAs(t, s, "alice", "aggregate_jobs", map[string]any{"group_by": []any{"ScheddName"}})
	if err != nil {
		t.Fatal(err)
	}
	groups, _ := sc["groups"].([]map[string]interface{})
	counts := map[string]string{}
	for _, g := range groups {
		key, _ := g["key"].([]string)
		counts[strings.Join(key, "/")] = g["count"].(string)
	}
	if counts[mAP1] != "2" || counts[mAP2] != "1" {
		t.Errorf("per-AP counts = %v", counts)
	}
	sc, err = callAs(t, s, "alice", "list_access_points", nil)
	if err != nil || sc["count"] != 2 {
		t.Errorf("list_access_points = %v %v", sc, err)
	}
}
