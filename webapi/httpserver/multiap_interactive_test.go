package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
	"github.com/bbockelm/golang-htcondor/webapi/sshgateway"
	"github.com/bbockelm/golang-htcondor/webapi/vscode"
)

// Interactive work in multi-AP mode: terminals, sessions (through the
// SSH gateway and its approval screen), JupyterLab and apps. The schedds
// are listeners that count connections, so which AP a call reaches is
// the assertion; JupyterLab, whose handlers take a stand-in schedd, is
// checked through a fake per AP that records the AP each call was routed
// to.

// interactiveServer is a three-AP server with a mapfile assignment and a
// hub populated by the test.
type interactiveServer struct {
	srv     *Server
	svc     *multiap.Service
	aps     *actionAPs
	hub     *multiaptest.DB
	mapfile string
}

func newInteractiveServer(t *testing.T, mapfile string, populate func(hub *multiaptest.DB)) *interactiveServer {
	t.Helper()
	aps := newActionAPs(t, ap1, ap2, ap3)
	s := &interactiveServer{aps: aps, hub: multiaptest.NewHub(t)}
	for _, n := range []string{ap1, ap2, ap3} {
		s.hub.PutSource(n, multiap.StateFresh, 1)
	}
	if populate != nil {
		populate(s.hub)
	}
	s.svc = multiAPService(t, s.hub, aps.reg)
	s.mapfile = filepath.Join(t.TempDir(), "assign.map")
	s.writeMap(t, mapfile)
	srv, err := NewServer(Config{
		MultiAP: MultiAPConfig{
			ScheddConstraint: `regexp("^ap", Name)`, service: s.svc,
			Assignment: apassign.Config{Backends: []string{apassign.BackendMapfile}, Mapfile: s.mapfile},
			creddFor:   func(string) htcondor.CreddClient { return nil },
		},
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
	// The counting schedds speak no CEDAR, so they cannot answer the
	// identity check; it has tests of its own.
	s.svc.VerifyCaller = func(context.Context, apregistry.Member, string) error { return nil }
	s.srv = srv
	t.Cleanup(func() {
		if n := srv.multi.scheddCalls.Load(); n != 0 {
			t.Errorf("the single-schedd accessor was called %d times in multi-AP mode", n)
		}
		if n := srv.Handler.mcpServer.MultiAPScheddCalls(); n != 0 {
			t.Errorf("the MCP server's schedd accessor was called %d times in multi-AP mode", n)
		}
	})
	return s
}

func (s *interactiveServer) writeMap(t *testing.T, text string) {
	t.Helper()
	if err := os.WriteFile(s.mapfile, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Duration(len(text)) * time.Second)
	if err := os.Chtimes(s.mapfile, future, future); err != nil {
		t.Fatal(err)
	}
	if s.srv != nil {
		s.srv.ReloadAPAssignment()
	}
}

// callerCtx is alice's request context with a credential, as the
// gateway and the approval screen build one.
func (s *interactiveServer) callerCtx(t *testing.T) context.Context {
	t.Helper()
	sec, err := htcondor.NewClientSecurityConfigWithConfig(context.Background(), nil, "e30.e30.c2ln", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	return htcondor.WithSecurityConfig(htcondor.WithAuthenticatedUser(context.Background(), "alice"), sec)
}

const sessionWork = `JobBatchName = "` + interactive.SessionBatchPrefix + `work"`

// --- terminals ----------------------------------------------------------------

// POST /api/v1/interactive/terminal lands on the assigned AP, or an
// alternate named with ?schedd=, and nothing else.
func TestMultiAPTerminalCreateLandsOnTheAssignedAP(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap2+" "+ap3+"\n", nil)
	before := s.aps.counts()
	rec := doAlice(t, s.srv, http.MethodPost, "/api/v1/interactive/terminal", `{}`)
	reachedOnlyAP(t, "POST /api/v1/interactive/terminal", before, s.aps.counts(), ap2)
	if rec.Code == http.StatusNotImplemented || rec.Code == http.StatusForbidden {
		t.Fatalf("terminal refused: %d %s", rec.Code, rec.Body.String())
	}

	before = s.aps.counts()
	_ = doAlice(t, s.srv, http.MethodPost, "/api/v1/interactive/terminal?schedd="+ap3, `{}`)
	reachedOnlyAP(t, "a terminal on the alternate", before, s.aps.counts(), ap3)

	before = s.aps.counts()
	rec = doAlice(t, s.srv, http.MethodPost, "/api/v1/interactive/terminal?schedd="+ap1, `{}`)
	if rec.Code != http.StatusForbidden || errorReason(t, rec) != apassign.ReasonTargetNotAllowed {
		t.Errorf("a terminal on a non-alternate = %d %s, want 403 %s", rec.Code, rec.Body.String(), apassign.ReasonTargetNotAllowed)
	}
	reachedNone(t, "a refused terminal", before, s.aps.counts())
}

// GET /api/v1/interactive/terminal lists the caller's terminals and
// sessions on every AP from the hub, each with its AP and complete id.
func TestMultiAPTerminalListComesFromTheHub(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap1+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(ap2, "alice@d", 4, 0, `JobBatchName = "`+interactiveTerminalBatchPrefix+`abc"`+"\nJobStatus = 2")
		hub.PutJob(ap1, "alice@d", 4, 0, sessionWork)
		hub.PutJob(ap1, "alice@d", 5, 0, `JobBatchName = "something else"`)
		hub.PutJob(ap1, "bob@d", 6, 0, sessionWork)
	})
	before := s.aps.counts()
	rec := doAlice(t, s.srv, http.MethodGet, "/api/v1/interactive/terminal", "")
	reachedNone(t, "a terminal listing", before, s.aps.counts())
	var body struct {
		Terminals []InteractiveTerminalSummary `json:"terminals"`
		Sources   multiap.Sources              `json:"sources"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}
	got := map[string]string{}
	for _, tm := range body.Terminals {
		got[tm.JobID] = tm.Kind + "/" + tm.Schedd
	}
	want := map[string]string{"4.0@" + ap2: "terminal/" + ap2, "4.0@" + ap1: "session/" + ap1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("terminals = %v, want %v", got, want)
	}
	if body.Sources.APs != 3 {
		t.Errorf("sources = %+v", body.Sources)
	}
}

// --- sessions through the SSH gateway -------------------------------------------

func gatewayTarget(t *testing.T, s *interactiveServer, user string) sshgateway.Target {
	t.Helper()
	tg, err := sshgateway.ParseTargetWith(s.srv.gatewayJobIDCodec(), user)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// ssh +work@gateway resolves to the AP the session is on (here ap2, from
// the hub), though the caller is now assigned to ap1: only ap2 is asked,
// and the answer names it.
func TestMultiAPSSHGatewaySessionTargetResolvesToItsAP(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap1+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(ap2, "alice@d", 7, 0, sessionWork+"\nJobStatus = 2")
		hub.PutJob(ap2, "alice@d", 8, 0, `JobBatchName = "`+interactive.SessionBatchPrefix+`default"`+"\nJobStatus = 2")
	})
	// +work names the session; a bare username is the default session.
	for _, user := range []string{"+work", "alice"} {
		before := s.aps.counts()
		_, err := s.srv.sshGatewayResolve(s.callerCtx(t), "alice", gatewayTarget(t, s, user), nil)
		reachedOnlyAP(t, "ssh "+user, before, s.aps.counts(), ap2)
		if err == nil || !strings.Contains(err.Error(), ap2) {
			t.Errorf("ssh %s = %v, want the session's AP %s named (it cannot be reached here)", user, err, ap2)
		}
	}
}

// A session target the caller has nowhere is created on the AP their
// assignment names, and nowhere else.
func TestMultiAPSSHGatewayNewSessionGoesToTheAssignedAP(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap3+"\n", nil)
	before := s.aps.counts()
	_, err := s.srv.sshGatewayResolve(s.callerCtx(t), "alice", gatewayTarget(t, s, "+fresh"), nil)
	reachedOnlyAP(t, "a new session through the gateway", before, s.aps.counts(), ap3)
	if err == nil || !strings.Contains(err.Error(), "starting session") {
		t.Errorf("new session = %v, want the fake schedd's submit failure", err)
	}
}

// Approving an SSH login with a workspace creates it through the
// assignment chain, with the groups the browser session recorded: a
// GROUP rule decides here.
func TestMultiAPSSHApprovalCreateUsesTheChain(t *testing.T) {
	s := newInteractiveServer(t, "GROUP physics "+ap3+"\nUSER alice@d "+ap1+"\n", nil)
	ctx := apassign.WithCaller(s.callerCtx(t), apassign.Caller{Subject: "alice", Groups: []string{"physics"}})
	before := s.aps.counts()
	_, _, err := s.srv.sshConsentCreateSession(ctx, "alice", "work", InteractiveCreateTerminalRequest{})
	reachedOnlyAP(t, "an approval's workspace", before, s.aps.counts(), ap3)
	if err == nil {
		t.Error("the counting schedd accepted a session")
	}

	// And without the group, the USER rule.
	before = s.aps.counts()
	_, _, _ = s.srv.sshConsentCreateSession(s.callerCtx(t), "alice", "work", InteractiveCreateTerminalRequest{})
	reachedOnlyAP(t, "an approval's workspace without groups", before, s.aps.counts(), ap1)
}

// --- apps -------------------------------------------------------------------

const appHex = "0123456789abcdef"

func appRow() string {
	return fmt.Sprintf("%s = %q\nJobBatchName = %q\nJobStatus = 2", vscode.AppAttr, vscode.AppAttrValue, vscode.BatchName(appHex))
}

func TestMultiAPAppCreateLandsOnTheAssignedAP(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap2+"\n", nil)
	before := s.aps.counts()
	rec := doAlice(t, s.srv, http.MethodPost, "/api/v1/apps", `{}`)
	reachedOnlyAP(t, "POST /api/v1/apps", before, s.aps.counts(), ap2)
	if rec.Code == http.StatusNotImplemented || rec.Code == http.StatusForbidden {
		t.Fatalf("app refused: %d %s", rec.Code, rec.Body.String())
	}
}

// An app is listed from the hub with an id naming its AP, and reached on
// that AP -- by the id with its AP, or by the bare id through the hub --
// whatever the caller's assignment says now.
func TestMultiAPAppIsReachedOnItsAP(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap1+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(ap2, "alice@d", 9, 0, appRow())
		hub.PutJob(ap1, "bob@d", 9, 0, appRow())
	})
	before := s.aps.counts()
	rec := doAlice(t, s.srv, http.MethodGet, "/api/v1/apps", "")
	reachedNone(t, "an app listing", before, s.aps.counts())
	var list struct {
		Apps []AppSummary `json:"apps"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Apps) != 1 {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}
	app := list.Apps[0]
	full := "9.0@" + ap2
	if app.ID != appHex+"@"+ap2 || app.JobID != full || app.Schedd != ap2 ||
		app.URL != "/api/v1/jobs/"+full+"/proxy/unix/"+vscode.SocketName+"/" {
		t.Errorf("app = %+v", app)
	}

	for _, c := range []struct{ method, id string }{
		{http.MethodGet, appHex}, {http.MethodGet, app.ID}, {http.MethodDelete, appHex}, {http.MethodDelete, app.ID},
	} {
		before := s.aps.counts()
		rec := doAlice(t, s.srv, c.method, "/api/v1/apps/"+c.id, "")
		reachedOnlyAP(t, c.method+" "+c.id, before, s.aps.counts(), ap2)
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusNotImplemented {
			t.Errorf("%s %s = %d %s", c.method, c.id, rec.Code, rec.Body.String())
		}
	}
	// An app the hub does not have is not looked for anywhere.
	before = s.aps.counts()
	if rec := doAlice(t, s.srv, http.MethodGet, "/api/v1/apps/feedfacefeedface", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown app = %d %s", rec.Code, rec.Body.String())
	}
	reachedNone(t, "an unknown app", before, s.aps.counts())
}

// A bare app id on two APs is refused, not resolved to one.
func TestMultiAPAppAmbiguousIDIsRefused(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap1+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(ap1, "alice@d", 9, 0, appRow())
		hub.PutJob(ap2, "alice@d", 9, 0, appRow())
	})
	before := s.aps.counts()
	rec := doAlice(t, s.srv, http.MethodDelete, "/api/v1/apps/"+appHex, "")
	if rec.Code != http.StatusConflict {
		t.Errorf("DELETE of an ambiguous app = %d %s, want 409", rec.Code, rec.Body.String())
	}
	reachedNone(t, "an ambiguous DELETE", before, s.aps.counts())
}

// --- JupyterLab -------------------------------------------------------------

// apJupyterSchedds is a JupyterLab stand-in schedd per AP: each call goes
// to the fake of the AP its context was routed to, and a call with no
// route is a test failure.
type apJupyterSchedds struct {
	t      *testing.T
	mu     sync.Mutex
	byAP   map[string]*jupyterFakeSchedd
	misses int
}

func newAPJupyterSchedds(t *testing.T, names ...string) *apJupyterSchedds {
	a := &apJupyterSchedds{t: t, byAP: map[string]*jupyterFakeSchedd{}}
	for i, n := range names {
		f := newJupyterFakeSchedd()
		f.nextCluster = 1000 * (i + 1)
		a.byAP[n] = f
	}
	return a
}

func (a *apJupyterSchedds) at(ctx context.Context) *jupyterFakeSchedd {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, ok := a.byAP[routedSchedd(ctx)]
	if !ok {
		a.misses++
		a.t.Errorf("a JupyterLab schedd call was not routed to an AP (routed to %q)", routedSchedd(ctx))
		return newJupyterFakeSchedd()
	}
	return f
}

func (a *apJupyterSchedds) SubmitRemote(ctx context.Context, submitFile string) (int, []*classad.ClassAd, error) {
	return a.at(ctx).SubmitRemote(ctx, submitFile)
}

func (a *apJupyterSchedds) SpoolJobFilesFromFS(ctx context.Context, procAds []*classad.ClassAd, fsys fs.FS) error {
	return a.at(ctx).SpoolJobFilesFromFS(ctx, procAds, fsys)
}

func (a *apJupyterSchedds) QueryWithOptions(ctx context.Context, constraint string, opts *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error) {
	return a.at(ctx).QueryWithOptions(ctx, constraint, opts)
}

func (a *apJupyterSchedds) queries(ap string) int {
	f := a.byAP[ap]
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.constraints)
}

func (a *apJupyterSchedds) submits(ap string) int {
	f := a.byAP[ap]
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.submitted)
}

func jupyterAs(t *testing.T, s *interactiveServer, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doAlice(t, s.srv, method, path, body)
}

// A JupyterLab session is submitted to the AP its assignment names, the
// AP is recorded on the instance and its row, and after a reassignment
// every read of its job still goes to that AP -- in this process and in
// a restarted one that adopts it from the row.
func TestMultiAPJupyterKeepsItsAP(t *testing.T) {
	stubJupyterHelper(t)
	s := newInteractiveServer(t, "USER alice@d "+ap2+"\n", nil)
	fakes := newAPJupyterSchedds(t, ap1, ap2, ap3)
	s.srv.Handler.jupyterScheddOverride = fakes

	rec := jupyterAs(t, s, http.MethodPost, "/api/v1/jupyter/instances", `{}`)
	var created JupyterCreateResponse
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &created) != nil {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	if created.Schedd != ap2 || fakes.submits(ap2) != 1 || fakes.submits(ap1)+fakes.submits(ap3) != 0 {
		t.Fatalf("created on %q; submissions ap1=%d ap2=%d ap3=%d", created.Schedd,
			fakes.submits(ap1), fakes.submits(ap2), fakes.submits(ap3))
	}
	row, err := s.srv.Handler.jupyterSessionStore().Get(context.Background(), created.InstanceID)
	if err != nil || row.Schedd != ap2 {
		t.Fatalf("stored row = %+v, %v; want schedd %s", row, err, ap2)
	}
	cluster, _ := strconv.Atoi(created.ClusterID)
	fakes.byAP[ap2].setStatus(cluster, 2)

	s.writeMap(t, "USER alice@d "+ap1+"\n")
	check := func(what string) {
		t.Helper()
		q1, q2, q3 := fakes.queries(ap1), fakes.queries(ap2), fakes.queries(ap3)
		rec := jupyterAs(t, s, http.MethodGet, "/api/v1/jupyter/instances", "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), created.InstanceID) {
			t.Fatalf("%s: list = %d %s", what, rec.Code, rec.Body.String())
		}
		rec = jupyterAs(t, s, http.MethodGet, "/api/v1/jupyter/instances/"+created.InstanceID, "")
		var one JupyterInstanceSummary
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &one) != nil || one.Schedd != ap2 || one.JobStatus != 2 {
			t.Fatalf("%s: get = %d %s", what, rec.Code, rec.Body.String())
		}
		if fakes.queries(ap2) != q2+2 || fakes.queries(ap1) != q1 || fakes.queries(ap3) != q3 {
			t.Errorf("%s: status queries went ap1+%d ap2+%d ap3+%d, want ap2 only", what,
				fakes.queries(ap1)-q1, fakes.queries(ap2)-q2, fakes.queries(ap3)-q3)
		}
	}
	check("after reassignment")

	// A restarted process: a fresh registry adopting from the row.
	h := s.srv.Handler
	h.jupyterRegistryMu.Lock()
	h.jupyterRegistry = nil
	h.jupyterRegistryMu.Unlock()
	check("after a restart")
}

// A row written by a single-AP server (no schedd) is listed in multi-AP
// mode, but its job is not looked for on any AP -- not the first member,
// not the caller's assignment -- and it is not reaped for want of one.
func TestMultiAPJupyterRowWithoutAnAPIsNotRouted(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap2+"\n", nil)
	fakes := newAPJupyterSchedds(t, ap1, ap2, ap3)
	s.srv.Handler.jupyterScheddOverride = fakes
	store := s.srv.Handler.jupyterSessionStore()
	if store == nil {
		t.Fatal("no application database")
	}
	// As a single-AP server wrote it: no schedd column in the insert.
	if _, err := s.srv.Handler.db.ExecContext(context.Background(), `
		INSERT INTO jupyter_sessions (instance_id, owner, cluster_id, proc_id, image, next_nonce, created_at, expires_at)
		VALUES ('old-session', 'alice', 77, 0, '', x'00', ?, ?)`,
		time.Now().UTC(), time.Now().Add(time.Hour).UTC()); err != nil {
		t.Fatal(err)
	}
	row, err := store.Get(context.Background(), "old-session")
	if err != nil || row.Schedd != "" || row.ClusterID != 77 {
		t.Fatalf("old row = %+v, %v; want schedd \"\"", row, err)
	}
	for _, path := range []string{"/api/v1/jupyter/instances", "/api/v1/jupyter/instances/old-session"} {
		rec := jupyterAs(t, s, http.MethodGet, path, "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "old-session") {
			t.Errorf("GET %s = %d %s, want the old session listed", path, rec.Code, rec.Body.String())
		}
	}
	for _, ap := range []string{ap1, ap2, ap3} {
		if n := fakes.queries(ap); n != 0 {
			t.Errorf("the schedd-less session's job was looked for on %s (%d queries)", ap, n)
		}
	}
}
