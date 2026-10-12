package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// Review gaps in multiap_interactive_test.go: each test passes on the
// branch and fails on one named mutant of multiap_interactive.go.

// An identity in another UID domain is somebody else: the session tools
// refuse it rather than read it as alice@d. Kills: interactiveAPs.user
// mapping caller.Owner (the domain-stripped name) instead of caller.Actor.
func TestMultiAPInteractiveRefusesAForeignDomain(t *testing.T) {
	a := newSessionAPs(t, "USER alice@d "+mAP2+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(mAP2, "alice@d", 7, 0, sessionBatch+"\nJobStatus = 2")
	})
	for _, tool := range []string{"interactive_session_list", "interactive_session_start", "interactive_session_exec"} {
		before := a.counts()
		sc, err := callAs(t, a.srv, "alice@other.example", tool, map[string]any{"session": "work", "command": "true"})
		if err == nil {
			t.Errorf("%s as alice@other.example = %v, want a refusal", tool, sc)
		}
		for n, c := range a.counts() {
			if c != before[n] {
				t.Errorf("%s as alice@other.example reached %s", tool, n)
			}
		}
	}
}

// An existing session's AP is asked for its verdict on the caller before
// anything is sent there. Kills: interactiveAPs.Route skipping AdmitTo.
func TestMultiAPInteractiveExecHonorsTheAPsVerdict(t *testing.T) {
	a := newSessionAPs(t, "USER alice@d "+mAP1+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(mAP3, "alice@d", 7, 0, sessionBatch+"\nJobStatus = 2")
	})
	a.srv.multi.Admit = refuseOn(mAP3)
	before := a.counts()
	_, _, err := a.call(t, "interactive_session_exec", map[string]any{"session": "work", "command": "true"})
	if err == nil || !strings.Contains(err.Error(), "refused on "+mAP3) {
		t.Errorf("exec on a session whose AP refuses alice = %v, want that refusal", err)
	}
	if after := a.counts(); after[mAP3] != before[mAP3] {
		t.Errorf("a refusing AP was contacted (%d connections)", after[mAP3]-before[mAP3])
	}
}

// The AP's identity check runs when an existing session is reached with
// a credential. Kills: interactiveAPs.Route never running VerifyCaller.
func TestMultiAPInteractiveExecVerifiesTheCaller(t *testing.T) {
	a := newSessionAPs(t, "USER alice@d "+mAP1+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(mAP2, "alice@d", 7, 0, sessionBatch+"\nJobStatus = 2")
	})
	a.srv.multi.VerifyCaller = func(_ context.Context, m apregistry.Member, _ string) error {
		if m.Name == mAP2 {
			return errors.New("identity check failed on " + m.Name)
		}
		return nil
	}
	before := a.counts()
	_, _, err := a.call(t, "interactive_session_exec", map[string]any{"session": "work", "command": "true"})
	if err == nil || !strings.Contains(err.Error(), "identity check failed on "+mAP2) {
		t.Errorf("exec = %v, want the identity check's failure", err)
	}
	if after := a.counts(); after[mAP2] != before[mAP2] {
		t.Errorf("an unverified AP was contacted (%d connections)", after[mAP2]-before[mAP2])
	}
}

// restAssignByKind is an assignment service that places "interactive"
// work on interactive and everything else on other.
func restAssignByKind(t *testing.T, interactive, other string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap := other
		if r.URL.Query().Get("kind") == apassign.KindInteractive {
			ap = interactive
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"schedd": ap, "alternates": []string{}, "ttl_seconds": 1})
	}))
	t.Cleanup(ts.Close)
	return ts
}

// A new session is placed as interactive work, which a site's assignment
// may put somewhere other than batch jobs. Kills: Assign asking for kind
// "job".
func TestMultiAPInteractiveStartIsAssignedAsInteractiveWork(t *testing.T) {
	a := newSessionAPs(t, "USER alice@d "+mAP1+"\n", nil)
	ts := restAssignByKind(t, mAP3, mAP2)
	chain, err := apassign.Build(apassign.Config{Backends: []string{apassign.BackendREST}, RESTURL: ts.URL},
		apassign.Options{InSet: a.srv.multi.InSet, Usable: a.srv.multi.Usable})
	if err != nil {
		t.Fatal(err)
	}
	a.srv.multi.Assign = chain
	before := a.counts()
	_, _, _ = a.call(t, "interactive_session_start", map[string]any{"session": "work"})
	reachedOnly(t, "interactive_session_start under a per-kind assignment", before, a.counts(), mAP3)
}
