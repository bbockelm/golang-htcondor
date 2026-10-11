package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

const mAP3 = "ap3.example.org"

// submitAPs is three APs whose schedds count connections, an assignment
// chain over a mapfile, and a credd per AP.
type submitAPs struct {
	srv      *Server
	svc      *multiap.Service
	chain    *apassign.Chain
	mapfile  string
	accepted map[string]*atomic.Int64
	credds   map[string]*htcondor.InMemoryCredd
	// prepared records the AP each submit's credential preparation ran
	// for.
	mu       sync.Mutex
	prepared []string
}

func newSubmitAPs(t *testing.T, mapfile string) *submitAPs {
	t.Helper()
	hub := multiaptest.NewHub(t)
	hub.PutJob(mAP1, "alice@d", 1, 0, "")
	hub.PutSource(mAP1, multiap.StateFresh, 1)
	hub.PutSource(mAP2, multiap.StateFresh, 1)
	hub.PutSource(mAP3, multiap.StateFresh, 1)
	h := multiap.NewHub(hub.Dial, time.Hour)
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := &submitAPs{accepted: map[string]*atomic.Int64{}, credds: map[string]*htcondor.InMemoryCredd{}}
	addrs := map[string]string{}
	for _, n := range []string{mAP1, mAP2, mAP3} {
		addrs[n], a.accepted[n] = countingListener(t)
		a.credds[n] = htcondor.NewInMemoryCredd()
	}
	reg := multiaptest.NewRegistry(mAP1, mAP2, mAP3).WithSchedds(func(n string) string { return addrs[n] })
	a.svc = &multiap.Service{Registry: reg, Hub: h, Codec: jobid.Default(), Stale: multiap.StaleInclude, UIDDomain: "d"}
	a.mapfile = filepath.Join(t.TempDir(), "assign.map")
	if err := os.WriteFile(a.mapfile, []byte(mapfile), 0o600); err != nil {
		t.Fatal(err)
	}
	chain, err := apassign.Build(apassign.Config{Backends: []string{apassign.BackendMapfile}, Mapfile: a.mapfile},
		apassign.Options{InSet: a.svc.InSet, Usable: a.svc.Usable})
	if err != nil {
		t.Fatal(err)
	}
	a.chain, a.svc.Assign = chain, chain
	keyPath := filepath.Join(t.TempDir(), "POOL")
	if err := os.WriteFile(keyPath, []byte("test pool signing key"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Config{
		MultiAP: a.svc, MultiAPConstraint: `regexp("^ap", Name)`,
		SigningKeyPath: keyPath, HTTPBaseURL: "https://api.example.org",
		CreddFor: func(ctx context.Context) htcondor.CreddClient {
			t, ok := multiap.TargetFrom(ctx)
			if !ok {
				return nil
			}
			return a.credds[t.Member.Name]
		},
		EnsureCredentials: func(ctx context.Context) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.prepared = append(a.prepared, routedSchedd(ctx))
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	a.srv = srv
	return a
}

func (a *submitAPs) counts() map[string]int64 {
	out := map[string]int64{}
	for n, c := range a.accepted {
		out[n] = c.Load()
	}
	return out
}

func (a *submitAPs) call(ctx context.Context, t *testing.T, tool string, args map[string]any) (map[string]any, error) {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": args})
	res, err := a.srv.handleCallTool(ctx, params)
	if err != nil {
		return nil, err
	}
	m, _ := res.(map[string]interface{})
	// Through JSON, as a client sees it: some tools carry a struct.
	b, err := json.Marshal(m["structuredContent"])
	if err != nil {
		return nil, err
	}
	var sc map[string]any
	_ = json.Unmarshal(b, &sc)
	return sc, nil
}

// reachedOnly asserts the call between before and after connected to
// want's schedd and to no other.
func reachedOnly(t *testing.T, what string, before, after map[string]int64, want string) {
	t.Helper()
	for n := range after {
		switch {
		case n == want && after[n] == before[n]:
			t.Errorf("%s never reached %s", what, n)
		case n != want && after[n] != before[n]:
			t.Errorf("%s reached %s (%d connections)", what, n, after[n]-before[n])
		}
	}
}

const testSubmitFile = "executable = /bin/true\ntransfer_executable = false\nqueue\n"

var submitToolCalls = []struct {
	tool string
	args map[string]any
}{
	{"submit_job", map[string]any{"submit_file": testSubmitFile}},
	{"submit_dag", map[string]any{"dag": "JOB A {\n executable = /bin/true\n transfer_executable = false\n}\n"}},
	{"build_container", map[string]any{"definition": "Bootstrap: docker\nFrom: alpine\n", "name": "a.sif",
		"destination": "osdf:///x/a.sif"}},
}

// Every submitting tool lands on the caller's home AP and no other.
func TestMultiAPSubmitToolsLandOnTheAssignedAP(t *testing.T) {
	a := newSubmitAPs(t, "USER alice@d "+mAP2+" "+mAP3+"\n")
	for _, c := range submitToolCalls {
		before := a.counts()
		_, err := a.call(callerCtx(t), t, c.tool, c.args)
		reachedOnly(t, c.tool, before, a.counts(), mAP2)
		if err == nil || strings.Contains(err.Error(), "multi-access-point") {
			t.Errorf("%s: %v, want the fake schedd's failure", c.tool, err)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.prepared {
		if p != mAP2 {
			t.Errorf("credential preparation ran for %q, want %s", p, mAP2)
		}
	}
	if len(a.prepared) == 0 {
		t.Error("credential preparation never ran")
	}
	if n := a.srv.MultiAPScheddCalls(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times", n)
	}
}

// schedd may name the home AP or an alternate, and nothing else.
func TestMultiAPSubmitExplicitTarget(t *testing.T) {
	a := newSubmitAPs(t, "USER alice@d "+mAP2+" "+mAP3+"\n")
	args := map[string]any{"submit_file": testSubmitFile, "schedd": mAP3}
	before := a.counts()
	_, _ = a.call(callerCtx(t), t, "submit_job", args)
	reachedOnly(t, "submit_job to the alternate", before, a.counts(), mAP3)

	before = a.counts()
	args["schedd"] = mAP1
	_, err := a.call(callerCtx(t), t, "submit_job", args)
	if err == nil || !strings.Contains(err.Error(), "you may submit to "+mAP2) {
		t.Errorf("submit to an AP that is neither home nor alternate: %v", err)
	}
	if after := a.counts(); after[mAP1] != before[mAP1] || after[mAP2] != before[mAP2] || after[mAP3] != before[mAP3] {
		t.Errorf("a refused target was contacted: %v -> %v", before, after)
	}
}

// An assignment outside the AP set is refused and nothing is contacted.
func TestMultiAPSubmitOutsideTheSetIsRefused(t *testing.T) {
	a := newSubmitAPs(t, "USER alice@d elsewhere.example.org\n")
	before := a.counts()
	_, err := a.call(callerCtx(t), t, "submit_job", map[string]any{"submit_file": testSubmitFile})
	if err == nil || multiap.ReasonOf(err) != apassign.ReasonInvalid {
		t.Fatalf("got %v, want the invalid-assignment refusal", err)
	}
	if after := a.counts(); after[mAP1]+after[mAP2]+after[mAP3] != before[mAP1]+before[mAP2]+before[mAP3] {
		t.Errorf("an AP was contacted: %v -> %v", before, after)
	}
	// And an unassigned user is told so.
	carol := htcondor.WithAuthenticatedUser(callerCtx(t), "carol")
	_, err = a.call(carol, t, "submit_job", map[string]any{"submit_file": testSubmitFile})
	if err == nil || !strings.Contains(err.Error(), "no access point is assigned to you") {
		t.Errorf("unassigned user: %v", err)
	}
}

// An untrusted home AP is not submitted to.
func TestMultiAPSubmitUntrustedHomeIs503(t *testing.T) {
	a := newSubmitAPs(t, "USER alice@d "+mAP2+" "+mAP3+"\n")
	a.svc.Registry.(*multiaptest.Registry).Update(mAP2, func(m *apregistry.Member) {
		m.Trust = apregistry.Trust{State: apregistry.TrustUntrusted, Reason: "refused the probe token"}
	})
	before := a.counts()
	_, err := a.call(callerCtx(t), t, "submit_job", map[string]any{"submit_file": testSubmitFile})
	if err == nil || multiap.StatusOf(err) != 503 {
		t.Fatalf("got %v, want 503", err)
	}
	if after := a.counts(); after[mAP2] != before[mAP2] {
		t.Error("the untrusted AP was contacted")
	}
	// The alternate still takes work.
	before = a.counts()
	_, _ = a.call(callerCtx(t), t, "submit_job", map[string]any{"submit_file": testSubmitFile, "schedd": mAP3})
	reachedOnly(t, "submit to the alternate while home is untrusted", before, a.counts(), mAP3)
}

// Credential tools use the home AP's credd unless schedd names another.
func TestMultiAPCredentialToolsFollowTheAP(t *testing.T) {
	a := newSubmitAPs(t, "USER alice@d "+mAP2+"\n")
	ctx := callerCtx(t)
	sc, err := a.call(ctx, t, "store_service_credential", map[string]any{"service": "scitokens", "credential": `{"access_token":"x"}`})
	if err != nil {
		t.Fatal(err)
	}
	if sc["schedd"] != mAP2 {
		t.Errorf("stored via %v, want %s", sc["schedd"], mAP2)
	}
	for ap, want := range map[string]bool{mAP1: false, mAP2: true, mAP3: false} {
		st, err := a.credds[ap].GetServiceCredStatus(ctx, htcondor.CredTypeOAuth, "scitokens", "", "")
		if got := err == nil && st.Exists; got != want {
			t.Errorf("credd of %s holds the credential: %v, want %v", ap, got, want)
		}
	}
	sc, err = a.call(ctx, t, "get_credential_status", map[string]any{"service": "scitokens", "schedd": mAP1})
	if err != nil {
		t.Fatal(err)
	}
	if sc["exists"] == true || sc["schedd"] != mAP1 {
		t.Errorf("status on %s = %v", mAP1, sc)
	}
	sc, err = a.call(ctx, t, "get_credential_status", map[string]any{"service": "scitokens"})
	if err != nil || sc["exists"] != true {
		t.Errorf("status on the home AP = %v %v", sc, err)
	}
	if _, err := a.call(ctx, t, "list_service_credentials", map[string]any{"schedd": "nowhere.example.org"}); err == nil {
		t.Error("a credential tool accepted an AP outside the set")
	}
}

func TestMultiAPWhoamiReportsTheHomeAP(t *testing.T) {
	a := newSubmitAPs(t, "USER alice@d "+mAP2+" "+mAP3+"\n")
	sc, err := a.call(callerCtx(t), t, "whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	alts, _ := sc["alternate_access_points"].([]interface{})
	if sc["home_access_point"] != mAP2 || len(alts) != 1 || alts[0] != mAP3 || sc["assignment_source"] != "mapfile" {
		t.Errorf("whoami = %v", sc)
	}
}

// The answer names the AP and carries complete ids.
func TestNoteSubmitted(t *testing.T) {
	s := &Server{multi: &multiap.Service{Codec: jobid.Default()}}
	res := withStructured(map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": "Submitted"}},
		"metadata": map[string]interface{}{"job_ids": []string{"5.0", "5.1"}, "job_id": "5.0"},
	}, map[string]interface{}{"job_ids": []string{"5.0", "5.1"}, "job_id": "5.0"})
	out := s.noteSubmitted(res, mAP2, apassign.Assignment{Schedd: mAP2, Source: "mapfile"}).(map[string]interface{})
	sc := out["structuredContent"].(map[string]interface{})
	if ids := sc["job_ids"].([]string); ids[0] != "5.0@"+mAP2 || ids[1] != "5.1@"+mAP2 || sc["job_id"] != "5.0@"+mAP2 {
		t.Errorf("structured = %v", sc)
	}
	text := out["content"].([]map[string]interface{})[0]["text"].(string)
	if !strings.Contains(text, "submitted to access point "+mAP2) || !strings.Contains(text, "5.0@"+mAP2) {
		t.Errorf("text = %q", text)
	}
}
