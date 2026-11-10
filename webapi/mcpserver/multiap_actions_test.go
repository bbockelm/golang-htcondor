package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// countingListener accepts and hangs up, counting connections: a call
// routed to an AP shows up there and nowhere else.
func countingListener(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	return "<" + ln.Addr().String() + ">", &n
}

type mcpAPs struct {
	srv      *Server
	accepted map[string]*atomic.Int64
	reg      *multiaptest.Registry
}

// newMultiAPActionMCP: alice has 1.0 on both APs and 2.0 on ap1; bob has
// 3.0 on ap1. Both APs are fresh. superusers lists, per AP, who is in its
// QUEUE_SUPER_USERS.
func newMultiAPActionMCP(t *testing.T, superusers map[string][]string) *mcpAPs {
	t.Helper()
	hub := multiaptest.NewHub(t)
	hub.PutJob(mAP1, "alice@d", 1, 0, "")
	hub.PutJob(mAP2, "alice@d", 1, 0, "")
	hub.PutJob(mAP1, "alice@d", 2, 0, "")
	hub.PutJob(mAP1, "bob@d", 3, 0, "")
	hub.PutSource(mAP1, multiap.StateFresh, 1)
	hub.PutSource(mAP2, multiap.StateFresh, 1)
	h := multiap.NewHub(hub.Dial, time.Hour)
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := &mcpAPs{accepted: map[string]*atomic.Int64{}}
	addrs := map[string]string{}
	for _, n := range []string{mAP1, mAP2} {
		addrs[n], a.accepted[n] = countingListener(t)
	}
	a.reg = multiaptest.NewRegistry(mAP1, mAP2).WithSchedds(func(n string) string { return addrs[n] })
	svc := &multiap.Service{
		Registry: a.reg, Hub: h, Codec: jobid.Default(), Stale: multiap.StaleInclude, UIDDomain: "d",
		BulkFresh: time.Minute,
		QueueSuperUser: func(ap, actor string) bool {
			for _, u := range superusers[ap] {
				if u == actor {
					return true
				}
			}
			return false
		},
	}
	keyPath := filepath.Join(t.TempDir(), "POOL")
	if err := os.WriteFile(keyPath, []byte("test pool signing key"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Config{MultiAP: svc, MultiAPConstraint: `regexp("^ap", Name)`,
		SigningKeyPath: keyPath, HTTPBaseURL: "https://api.example.org"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	a.srv = srv
	return a
}

func (a *mcpAPs) counts() map[string]int64 {
	return map[string]int64{mAP1: a.accepted[mAP1].Load(), mAP2: a.accepted[mAP2].Load()}
}

// callerCtx is alice with a credential attached, as the HTTP transport
// attaches one, and the given granted scopes.
func callerCtx(t *testing.T, scopes ...string) context.Context {
	t.Helper()
	sec, err := htcondor.NewClientSecurityConfigWithConfig(context.Background(), nil, "e30.e30.c2ln", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := htcondor.WithSecurityConfig(htcondor.WithAuthenticatedUser(context.Background(), "alice"), sec)
	if scopes != nil {
		ctx = WithGrantedScopes(ctx, scopes)
	}
	return ctx
}

func (a *mcpAPs) call(ctx context.Context, t *testing.T, tool string, args map[string]any) (map[string]any, error) {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": args})
	res, err := a.srv.handleCallTool(ctx, params)
	if err != nil {
		return nil, err
	}
	m, _ := res.(map[string]interface{})
	sc, _ := m["structuredContent"].(map[string]interface{})
	return sc, nil
}

var mcpActionCalls = []struct {
	tool string
	args map[string]any
}{
	{"remove_job", nil},
	{"hold_job", nil},
	{"release_job", nil},
	{"edit_job", map[string]any{"attributes": map[string]any{"Foo": 1}}},
	{"get_job_stdout", nil},
	{"get_job_stderr", nil},
	{"get_job_output", nil},
	{"upload_job_input", map[string]any{"files": []any{map[string]any{"name": "a.txt", "content": "x"}}}},
	{"create_output_download_url", nil},
	{"create_input_upload_url", nil},
	{"tail_job_output", nil},
	{"exec_in_job", map[string]any{"command": "true"}},
}

// Each single-job tool on 1.0@ap2 reaches ap2's schedd and never ap1's.
func TestMultiAPMCPActionsRouteToTheJobsAP(t *testing.T) {
	a := newMultiAPActionMCP(t, nil)
	for _, c := range mcpActionCalls {
		for _, ap := range []string{mAP1, mAP2} {
			other := mAP1
			if ap == mAP1 {
				other = mAP2
			}
			args := map[string]any{"job_id": "1.0@" + ap}
			for k, v := range c.args {
				args[k] = v
			}
			before := a.counts()
			_, err := a.call(callerCtx(t), t, c.tool, args)
			after := a.counts()
			if after[ap] == before[ap] {
				t.Errorf("%s on 1.0@%s never reached its schedd (%v)", c.tool, ap, err)
			}
			if after[other] != before[other] {
				t.Errorf("%s on 1.0@%s reached %s", c.tool, ap, other)
			}
			if err != nil && strings.Contains(err.Error(), "multi-access-point") {
				t.Errorf("%s is refused in multi-AP mode: %v", c.tool, err)
			}
		}
		// schedd alongside a bare id is the same job.
		before := a.counts()
		args := map[string]any{"job_id": "1.0", "schedd": mAP2}
		for k, v := range c.args {
			args[k] = v
		}
		_, _ = a.call(callerCtx(t), t, c.tool, args)
		if after := a.counts(); after[mAP2] == before[mAP2] || after[mAP1] != before[mAP1] {
			t.Errorf("%s with schedd=%s went %v -> %v", c.tool, mAP2, before, after)
		}
	}
	if n := a.srv.MultiAPScheddCalls(); n != 0 {
		t.Errorf("getSchedd called %d times", n)
	}
}

// A bare id is refused with the caller's candidates and reaches nothing.
func TestMultiAPMCPActionsRefuseBareIDs(t *testing.T) {
	a := newMultiAPActionMCP(t, nil)
	before := a.counts()
	for _, c := range mcpActionCalls {
		args := map[string]any{"job_id": "1.0"}
		for k, v := range c.args {
			args[k] = v
		}
		_, err := a.call(callerCtx(t), t, c.tool, args)
		if err == nil || !strings.Contains(err.Error(), "1.0@"+mAP1) || !strings.Contains(err.Error(), "1.0@"+mAP2) {
			t.Errorf("%s on bare 1.0: %v, want a refusal naming both candidates", c.tool, err)
		}
	}
	if _, err := a.call(callerCtx(t), t, "hold_job", map[string]any{"job_id": "1.0@ap9.example.org"}); err == nil ||
		!strings.Contains(err.Error(), "not an access point this server serves") {
		t.Errorf("unknown AP: %v", err)
	}
	if after := a.counts(); after[mAP1] != before[mAP1] || after[mAP2] != before[mAP2] {
		t.Errorf("a refused call reached a schedd: %v -> %v", before, after)
	}
}

// A call with no caller credential is refused rather than run as this
// server.
func TestMultiAPMCPScheddForNeedsACredential(t *testing.T) {
	a := newMultiAPActionMCP(t, nil)
	m, _ := a.reg.Get(mAP2)
	ctx := multiap.WithTarget(htcondor.WithAuthenticatedUser(context.Background(), "alice"),
		multiap.Target{Member: m, ID: jobid.ID{Schedd: mAP2, Cluster: 1}})
	if got := a.srv.scheddFor(ctx); got != multiap.NoSchedd {
		t.Errorf("scheddFor with no credential = %v", got)
	}
	if got := a.srv.scheddFor(callerCtxWithTarget(t, m)); got != m.Schedd {
		t.Errorf("scheddFor with a credential = %v, want ap2's", got)
	}
}

func callerCtxWithTarget(t *testing.T, m apregistry.Member) context.Context {
	return multiap.WithTarget(callerCtx(t), multiap.Target{Member: m, ID: jobid.ID{Schedd: m.Name, Cluster: 1}})
}

// mcp:superuser reaches other users' jobs only on an AP where the caller
// is a queue superuser.
func TestMultiAPMCPSuperuserIsPerAP(t *testing.T) {
	a := newMultiAPActionMCP(t, map[string][]string{mAP1: {"alice@d"}})
	ctx := callerCtx(t, "mcp:read", "mcp:write", "mcp:superuser")
	m1, _ := a.reg.Get(mAP1)
	m2, _ := a.reg.Get(mAP2)
	at := func(m apregistry.Member) context.Context {
		return multiap.WithTarget(ctx, multiap.Target{Member: m})
	}
	if !a.srv.allowsAllUsersByPolicy(ctx, "alice", tierMutate) {
		t.Fatal("mcp:superuser does not grant the mutate tier by policy")
	}
	if !a.srv.allowsAllUsers(at(m1), "alice", tierMutate) {
		t.Error("alice is a queue superuser on ap1 but cannot act on others' jobs there")
	}
	if a.srv.allowsAllUsers(at(m2), "alice", tierMutate) {
		t.Error("alice acts on others' jobs on ap2, where she is not a queue superuser")
	}
	if a.srv.allowsAllUsers(ctx, "alice", tierMutate) {
		t.Error("a call routed to no AP reaches other users' jobs")
	}
	c, err := a.srv.scopeToOwner(at(m2), "true", tierMutate)
	if err != nil || !strings.Contains(c, `User == "alice@d"`) {
		t.Errorf("ap2 scope = %q, %v", c, err)
	}
}

// remove_jobs fans out, reports per AP, and skips only an AP the hub
// proves empty.
func TestMultiAPMCPRemoveJobsFansOut(t *testing.T) {
	a := newMultiAPActionMCP(t, nil)
	// bob's 3.0 is the only match for "ClusterId == 3": alice's hub check
	// finds nothing on either AP, so neither is contacted.
	before := a.counts()
	sc, err := a.call(callerCtx(t), t, "remove_jobs", map[string]any{"constraint": "ClusterId == 3"})
	if err != nil {
		t.Fatal(err)
	}
	if after := a.counts(); after[mAP1] != before[mAP1] || after[mAP2] != before[mAP2] {
		t.Errorf("an AP the hub proves empty was contacted: %v -> %v", before, after)
	}
	if sc["complete"] != true {
		t.Errorf("complete = %v", sc["complete"])
	}
	// ClusterId == 2: only ap1 has one of alice's.
	before = a.counts()
	sc, err = a.call(callerCtx(t), t, "remove_jobs", map[string]any{"constraint": "ClusterId == 2"})
	if err != nil {
		t.Fatal(err)
	}
	after := a.counts()
	if after[mAP1] == before[mAP1] || after[mAP2] != before[mAP2] {
		t.Errorf("ClusterId == 2 contacted %v -> %v, want ap1 only", before, after)
	}
	aps, _ := sc["access_points"].([]multiap.BulkAPResult)
	status := map[string]string{}
	for _, r := range aps {
		status[r.Schedd] = r.Status
	}
	if status[mAP1] != multiap.BulkFailed || status[mAP2] != multiap.BulkSkipped || sc["complete"] != false {
		t.Errorf("per-AP report = %v complete=%v", status, sc["complete"])
	}
	if _, err := a.call(callerCtx(t), t, "remove_jobs", map[string]any{"constraint": "true) || (true"}); err == nil {
		t.Error("an unbalanced constraint was accepted")
	}
}

// A single-job tool this server just ran on an AP voids the hub's
// "nothing there" for that AP in a following remove_jobs.
func TestMultiAPMCPActionVoidsTheBulkSkip(t *testing.T) {
	a := newMultiAPActionMCP(t, nil)
	_, _ = a.call(callerCtx(t), t, "hold_job", map[string]any{"job_id": "1.0@" + mAP2})
	before := a.counts()
	if _, err := a.call(callerCtx(t), t, "remove_jobs", map[string]any{"constraint": "ClusterId == 3"}); err != nil {
		t.Fatal(err)
	}
	after := a.counts()
	if after[mAP2] == before[mAP2] {
		t.Error("ap2 was skipped on the hub's word right after hold_job acted there")
	}
	if after[mAP1] != before[mAP1] {
		t.Error("ap1, untouched and holding no match, was contacted")
	}
}

// A schedd argument that contradicts a complete job_id is refused, not
// silently dropped.
func TestMultiAPMCPScheddMustAgree(t *testing.T) {
	a := newMultiAPActionMCP(t, nil)
	before := a.counts()
	_, err := a.call(callerCtx(t), t, "hold_job", map[string]any{"job_id": "1.0@" + mAP1, "schedd": mAP2})
	if err == nil || !strings.Contains(err.Error(), "pass one") {
		t.Errorf("job_id on ap1 with schedd ap2: %v", err)
	}
	if after := a.counts(); after[mAP1] != before[mAP1] || after[mAP2] != before[mAP2] {
		t.Error("a contradictory call reached a schedd")
	}
}

// The routed AP's own verdict and its identification of the caller gate
// every routed tool call.
func TestMultiAPMCPRoutedChecks(t *testing.T) {
	a := newMultiAPActionMCP(t, nil)
	a.srv.multi.Admit = func(_ context.Context, m apregistry.Member, _ string) error {
		if m.Name == mAP2 {
			return errors.New("disabled there")
		}
		return nil
	}
	verified := map[string]string{}
	a.srv.multi.VerifyCaller = func(_ context.Context, m apregistry.Member, user string) error {
		verified[m.Name] = user
		return nil
	}
	before := a.counts()
	if _, err := a.call(callerCtx(t), t, "hold_job", map[string]any{"job_id": "1.0@" + mAP2}); err == nil ||
		multiap.ReasonOf(err) != multiap.ReasonDenied {
		t.Errorf("hold on ap2, which refuses alice: %v", err)
	}
	_, _ = a.call(callerCtx(t), t, "hold_job", map[string]any{"job_id": "1.0@" + mAP1})
	after := a.counts()
	if after[mAP2] != before[mAP2] || after[mAP1] == before[mAP1] {
		t.Errorf("connections %v -> %v, want ap1 only", before, after)
	}
	if verified[mAP1] != "alice@d" {
		t.Errorf("the caller was not verified against the routed AP: %v", verified)
	}
	a.srv.multi.VerifyCaller = func(context.Context, apregistry.Member, string) error { return errors.New("identified as bob@d") }
	if _, err := a.call(callerCtx(t), t, "hold_job", map[string]any{"job_id": "1.0@" + mAP1}); err == nil {
		t.Error("a caller the routed AP does not identify as themselves was let through")
	}
}
