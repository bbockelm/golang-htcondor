package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// The interactive session tools in multi-AP mode, over schedds that
// count connections: which AP a call reaches is the assertion. The
// session logic itself is tested against fake queues in
// webapi/interactive.

type sessionAPs struct {
	srv      *Server
	hub      *multiaptest.DB
	mapfile  string
	accepted map[string]*atomic.Int64
}

// newSessionAPs: three APs, a mapfile assignment, and a hub holding
// whatever sessions the test puts there.
func newSessionAPs(t *testing.T, mapfile string, sessions func(hub *multiaptest.DB)) *sessionAPs {
	t.Helper()
	a := &sessionAPs{hub: multiaptest.NewHub(t), accepted: map[string]*atomic.Int64{}}
	for _, n := range []string{mAP1, mAP2, mAP3} {
		a.hub.PutSource(n, multiap.StateFresh, 1)
	}
	if sessions != nil {
		sessions(a.hub)
	}
	h := multiap.NewHub(a.hub.Dial, time.Hour)
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	addrs := map[string]string{}
	for _, n := range []string{mAP1, mAP2, mAP3} {
		addrs[n], a.accepted[n] = countingListener(t)
	}
	reg := multiaptest.NewRegistry(mAP1, mAP2, mAP3).WithSchedds(func(n string) string { return addrs[n] })
	svc := &multiap.Service{Registry: reg, Hub: h, Codec: jobid.Default(), Stale: multiap.StaleInclude, UIDDomain: "d"}
	a.mapfile = filepath.Join(t.TempDir(), "assign.map")
	a.assign(t, mapfile)
	chain, err := apassign.Build(apassign.Config{Backends: []string{apassign.BackendMapfile}, Mapfile: a.mapfile},
		apassign.Options{InSet: svc.InSet, Usable: svc.Usable})
	if err != nil {
		t.Fatal(err)
	}
	svc.Assign = chain
	srv, err := NewServer(Config{MultiAP: svc, MultiAPConstraint: `regexp("^ap", Name)`})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)
	a.srv = srv
	return a
}

func (a *sessionAPs) assign(t *testing.T, mapfile string) {
	t.Helper()
	if err := os.WriteFile(a.mapfile, []byte(mapfile), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (a *sessionAPs) counts() map[string]int64 {
	out := map[string]int64{}
	for n, c := range a.accepted {
		out[n] = c.Load()
	}
	return out
}

func (a *sessionAPs) call(t *testing.T, tool string, args map[string]any) (map[string]any, string, error) {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": args})
	res, err := a.srv.handleCallTool(callerCtx(t), params)
	if err != nil {
		return nil, "", err
	}
	m, _ := res.(map[string]interface{})
	b, _ := json.Marshal(m["structuredContent"])
	var sc map[string]any
	_ = json.Unmarshal(b, &sc)
	text := ""
	if c, ok := m["content"].([]map[string]interface{}); ok && len(c) > 0 {
		text, _ = c[0]["text"].(string)
	}
	return sc, text, nil
}

const sessionBatch = `JobBatchName = "` + interactive.SessionBatchPrefix + `work"`

func TestMultiAPInteractiveToolsAreServed(t *testing.T) {
	a := newSessionAPs(t, "USER alice@d "+mAP2+"\n", nil)
	names := a.srv.ToolNames(context.Background())
	for n := range multiAPInteractiveTools {
		found := false
		for _, have := range names {
			found = found || have == n
		}
		if !found {
			t.Errorf("multi-AP catalogue lacks %s", n)
		}
	}
	for _, tool := range a.srv.toolsFor(context.Background()) {
		if tool.Name != "interactive_session_start" {
			continue
		}
		props, _ := tool.InputSchema["properties"].(map[string]interface{})
		if _, ok := props["schedd"]; !ok {
			t.Error("interactive_session_start has no schedd argument in multi-AP mode")
		}
	}
	if strings.Contains(*a.srv.instructions.Load(), "Interactive sessions and watches are not available") {
		t.Error("the instructions still say interactive sessions are not available")
	}
}

// A new session is submitted to the assigned AP and no other.
func TestMultiAPInteractiveStartLandsOnTheAssignedAP(t *testing.T) {
	a := newSessionAPs(t, "USER alice@d "+mAP2+" "+mAP3+"\n", nil)
	before := a.counts()
	_, _, err := a.call(t, "interactive_session_start", map[string]any{"session": "work"})
	reachedOnly(t, "interactive_session_start", before, a.counts(), mAP2)
	if err == nil || strings.Contains(err.Error(), "multi-access-point") {
		t.Errorf("start: %v, want the fake schedd's failure", err)
	}

	// schedd may name an alternate, and nothing else.
	before = a.counts()
	_, _, _ = a.call(t, "interactive_session_start", map[string]any{"session": "work", "schedd": mAP3})
	reachedOnly(t, "interactive_session_start to the alternate", before, a.counts(), mAP3)
	before = a.counts()
	_, _, err = a.call(t, "interactive_session_start", map[string]any{"session": "work", "schedd": mAP1})
	if err == nil || !strings.Contains(err.Error(), "you may submit to "+mAP2) {
		t.Errorf("start on a non-alternate: %v", err)
	}
	if after := a.counts(); after[mAP1] != before[mAP1] {
		t.Error("a refused target was contacted")
	}
	if n := a.srv.MultiAPScheddCalls(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times", n)
	}
}

// A session the hub places on ap2 is reached on ap2 even though the
// caller is now assigned to ap1; the failure names ap2.
func TestMultiAPInteractiveExecGoesToTheSessionsAP(t *testing.T) {
	a := newSessionAPs(t, "USER alice@d "+mAP1+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(mAP2, "alice@d", 7, 0, sessionBatch+"\nJobStatus = 2")
	})
	for _, tool := range []string{"interactive_session_exec", "interactive_session_stop"} {
		before := a.counts()
		_, _, err := a.call(t, tool, map[string]any{"session": "work", "command": "hostname"})
		reachedOnly(t, tool, before, a.counts(), mAP2)
		if err == nil || !strings.Contains(err.Error(), mAP2) {
			t.Errorf("%s: %v, want a failure naming %s", tool, err, mAP2)
		}
	}
	// The list reports it on ap2, from the hub, since ap2 cannot be asked.
	sc, text, err := a.call(t, "interactive_session_list", nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := sc["sessions"].([]any)
	if len(rows) != 1 {
		t.Fatalf("list = %v", sc)
	}
	row, _ := rows[0].(map[string]any)
	if row["schedd"] != mAP2 || row["job_id"] != "7.0@"+mAP2 || row["access_point_error"] == nil {
		t.Errorf("list row = %v, want 7.0@%s marked unreachable", row, mAP2)
	}
	if !strings.Contains(text, "on access point "+mAP2) {
		t.Errorf("list text does not name the AP: %s", text)
	}
	if n := a.srv.MultiAPScheddCalls(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times", n)
	}
}

// A name the hub shows on two APs is refused, and nothing is created on
// the assigned AP under that name.
func TestMultiAPInteractiveAmbiguousNameIsRefused(t *testing.T) {
	a := newSessionAPs(t, "USER alice@d "+mAP3+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(mAP1, "alice@d", 7, 0, sessionBatch+"\nJobStatus = 2")
		hub.PutJob(mAP2, "alice@d", 7, 0, sessionBatch+"\nJobStatus = 2")
	})
	_, _, err := a.call(t, "interactive_session_exec", map[string]any{"session": "work", "command": "true"})
	if err == nil || !strings.Contains(err.Error(), "7.0@"+mAP1) || !strings.Contains(err.Error(), "7.0@"+mAP2) {
		t.Errorf("exec on an ambiguous name: %v, want both jobs named", err)
	}
	_, _, err = a.call(t, "interactive_session_start", map[string]any{"session": "work"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("start of a name in use elsewhere: %v", err)
	}
}
