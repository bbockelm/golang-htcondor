package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// Review gaps in multiap_interactive_test.go: each test passes on the
// branch and fails on one or more named mutants.

// doAsWithBody is doAs with a JSON body, for the create endpoints.
func doAsWithBody(t *testing.T, h http.Handler, user, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	req.Header.Set("X-Remote-User", user)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// An identity in another UID domain is somebody else on every
// interactive surface: refused, never rewritten onto alice@d, and no AP
// is contacted. Kills: multiAssign / multiListApps / multiFindApp
// mapping the domain-stripped name.
func TestMultiAPInteractiveRESTRefusesAForeignDomain(t *testing.T) {
	stubJupyterHelper(t)
	s := newInteractiveServer(t, "USER alice@d "+ap2+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(ap2, "alice@d", 9, 0, appRow())
	})
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/interactive/terminal", `{}`},
		{http.MethodPost, "/api/v1/apps", `{}`},
		{http.MethodPost, "/api/v1/jupyter/instances", `{}`},
		{http.MethodGet, "/api/v1/apps", ""},
		{http.MethodGet, "/api/v1/apps/" + appHex, ""},
		{http.MethodDelete, "/api/v1/apps/" + appHex + "@" + ap2, ""},
		{http.MethodGet, "/api/v1/interactive/terminal", ""},
	} {
		before := s.aps.counts()
		rec := doAsWithBody(t, s.srv, "alice@other.example", c.method, c.path, c.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as alice@other.example = %d %s, want 403", c.method, c.path, rec.Code, rec.Body.String())
		}
		reachedNone(t, c.method+" "+c.path+" as alice@other.example", before, s.aps.counts())
	}
}

// An app's AP is asked for its verdict on the caller before the app is
// looked for there. Kills: multiRoute skipping AdmitTo.
func TestMultiAPAppOnARefusingAPIsNotReached(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap1+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(ap3, "alice@d", 9, 0, appRow())
	})
	s.svc.Admit = refuseOn(ap3)
	for _, id := range []string{appHex, appHex + "@" + ap3} {
		before := s.aps.counts()
		rec := doAlice(t, s.srv, http.MethodGet, "/api/v1/apps/"+id, "")
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET app %s on a refusing AP = %d %s, want 403", id, rec.Code, rec.Body.String())
		}
		reachedNone(t, "an app on a refusing AP", before, s.aps.counts())
	}
}

// The allowlist serves exactly the interactive routes and methods that
// have been taught their AP. Kills: widening any of multiAPInteractivePath's
// method or path bounds.
func TestMultiAPInteractiveAllowlistBounds(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodGet, "/api/v1/interactive/terminal", true},
		{http.MethodPost, "/api/v1/interactive/terminal", true},
		{http.MethodDelete, "/api/v1/interactive/terminal", false},
		{http.MethodPut, "/api/v1/interactive/terminal", false},
		{http.MethodGet, "/api/v1/apps/" + appHex, true},
		{http.MethodDelete, "/api/v1/apps/" + appHex, true},
		{http.MethodPost, "/api/v1/apps/" + appHex, false},
		{http.MethodPut, "/api/v1/apps/" + appHex, false},
		{http.MethodGet, "/api/v1/apps/" + appHex + "/extra", false},
		{http.MethodDelete, "/api/v1/apps/" + appHex + "/extra", false},
		{http.MethodDelete, "/api/v1/apps", false},
	} {
		if got := multiAPAllowed(c.method, c.path); got != c.want {
			t.Errorf("multiAPAllowed(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

// restAssignByKind answers interactive work with one AP, JupyterLab with
// another, and everything else with a third.
func restAssignByKind(t *testing.T, interactiveAP, jupyterAP, otherAP string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap := otherAP
		switch r.URL.Query().Get("kind") {
		case apassign.KindInteractive:
			ap = interactiveAP
		case apassign.KindJupyter:
			ap = jupyterAP
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"schedd": ap, "alternates": []string{}, "ttl_seconds": 1})
	}))
	t.Cleanup(ts.Close)
	return ts
}

// A site's assignment may place each kind of work differently: /aps?kind=
// reports the kind asked about, and JupyterLab and terminals are placed
// as their own kinds. Kills: ?kind= validated but not applied; JupyterLab
// assigned as kind "interactive".
func TestMultiAPInteractivePlacementIsPerKind(t *testing.T) {
	stubJupyterHelper(t)
	s := newInteractiveServer(t, "USER alice@d "+ap2+"\n", nil)
	ts := restAssignByKind(t, ap3, ap1, ap2)
	chain, err := apassign.Build(apassign.Config{Backends: []string{apassign.BackendREST}, RESTURL: ts.URL},
		apassign.Options{InSet: s.svc.InSet, Usable: s.svc.Usable})
	if err != nil {
		t.Fatal(err)
	}
	s.svc.Assign = chain

	for kind, want := range map[string]string{"": ap2, "interactive": ap3, "jupyter": ap1} {
		rec := doAlice(t, s.srv, http.MethodGet, "/api/v1/aps?kind="+kind, "")
		var body APsResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil ||
			body.Assignment == nil || body.Assignment.Schedd != want {
			t.Errorf("aps?kind=%s = %d %s, want %s", kind, rec.Code, rec.Body.String(), want)
		}
	}

	fakes := newAPJupyterSchedds(t, ap1, ap2, ap3)
	s.srv.jupyterScheddOverride = fakes
	rec := doAlice(t, s.srv, http.MethodPost, "/api/v1/jupyter/instances", `{}`)
	var created JupyterCreateResponse
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &created) != nil || created.Schedd != ap1 {
		t.Errorf("JupyterLab create = %d %s, want it on %s", rec.Code, rec.Body.String(), ap1)
	}

	before := s.aps.counts()
	_ = doAlice(t, s.srv, http.MethodPost, "/api/v1/interactive/terminal", `{}`)
	reachedOnlyAP(t, "a terminal under a per-kind assignment", before, s.aps.counts(), ap3)
}

// A JupyterLab row from a single-AP server has no job id in multi-AP
// mode: its job is on no known AP, so there is nothing to name. Kills:
// jupyterSummary formatting a complete id with an empty AP.
func TestMultiAPJupyterRowWithoutAnAPHasNoJobID(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap2+"\n", nil)
	s.srv.jupyterScheddOverride = newAPJupyterSchedds(t, ap1, ap2, ap3)
	if s.srv.jupyterSessionStore() == nil {
		t.Fatal("no application database")
	}
	if _, err := s.srv.db.ExecContext(context.Background(), `
		INSERT INTO jupyter_sessions (instance_id, owner, cluster_id, proc_id, image, next_nonce, created_at, expires_at)
		VALUES ('old-session', 'alice', 77, 0, '', x'00', ?, ?)`,
		time.Now().UTC(), time.Now().Add(time.Hour).UTC()); err != nil {
		t.Fatal(err)
	}
	rec := doAlice(t, s.srv, http.MethodGet, "/api/v1/jupyter/instances/old-session", "")
	var one JupyterInstanceSummary
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &one) != nil {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body.String())
	}
	if one.JobID != "" || one.Schedd != "" {
		t.Errorf("an AP-less row reports job_id %q schedd %q, want both empty", one.JobID, one.Schedd)
	}
}

// Single-AP mode keeps its wire shape: bare app ids, cluster.0 JupyterLab
// job ids, and no schedd keys. Kills: appIDText appending "@" without
// multi-AP; jupyterSummary's single-AP job id; dropping omitempty on the
// new schedd fields.
func TestSingleAPInteractiveShapeIsUnchanged(t *testing.T) {
	h := taggingHandler(t)
	if got := h.appIDText(appHex, ""); got != appHex {
		t.Errorf("single-AP app id = %q, want %q", got, appHex)
	}
	for name, v := range map[string]any{
		"AppSummary":                        AppSummary{ID: appHex, State: appStateRunning},
		"InteractiveCreateTerminalResponse": InteractiveCreateTerminalResponse{InstanceID: "x"},
		"InteractiveTerminalSummary":        InteractiveTerminalSummary{InstanceID: "x"},
		"JupyterCreateResponse":             JupyterCreateResponse{InstanceID: "x"},
		"JupyterInstanceSummary":            JupyterInstanceSummary{InstanceID: "x"},
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"schedd"`) || strings.Contains(string(b), `"access_point_error"`) {
			t.Errorf("single-AP %s carries a multi-AP key: %s", name, b)
		}
	}

	stubJupyterHelper(t)
	fake := newJupyterFakeSchedd()
	jh := newJupyterRestartHandler(t, t.TempDir()+"/app.db", fake)
	created := createJupyterSession(t, jh)
	list := listJupyterSessions(t, jh)
	if len(list) != 1 || list[0].JobID != created.ClusterID+".0" || list[0].Schedd != "" {
		t.Errorf("single-AP JupyterLab list = %+v, want job_id %s.0 and no schedd", list, created.ClusterID)
	}
}
