package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// ssh +work@gateway with work on two APs is refused naming both jobs,
// not attached to whichever AP sorts first.
func TestMultiAPSSHGatewayRefusesAnAmbiguousSessionName(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap3+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(ap1, "alice@d", 7, 0, sessionWork+"\nJobStatus = 2")
		hub.PutJob(ap2, "alice@d", 7, 0, sessionWork+"\nJobStatus = 2")
	})
	before := s.aps.counts()
	_, err := s.srv.sshGatewayResolve(s.callerCtx(t), "alice", gatewayTarget(t, s, "+work"), nil)
	if err == nil || !strings.Contains(err.Error(), "more than one job") ||
		!strings.Contains(err.Error(), "7.0@"+ap1) || !strings.Contains(err.Error(), "7.0@"+ap2) {
		t.Fatalf("ssh +work on two APs = %v, want the ambiguity naming both", err)
	}
	if after := s.aps.counts(); after[ap3] != before[ap3] {
		t.Errorf("an ambiguous name started a session on %s", ap3)
	}
}

// While a known session starts, the gateway re-reads it on its own AP
// only -- not the hub and every AP each tick.
func TestMultiAPSSHGatewayPollsOnlyTheSessionsAP(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap1+"\n", nil)
	mgr := s.srv.interactiveManagerOrNil()
	info := interactive.Info{Name: "work", JobID: "7.0@" + ap2, Schedd: ap2, ClusterID: 7, JobStatus: 1, Status: "starting"}
	ctx, cancel := context.WithTimeout(s.callerCtx(t), 10*time.Second)
	defer cancel()
	before := s.aps.counts()
	_, err := s.srv.sshGatewayAwaitRunning(ctx, mgr, interactive.Caller{Actor: "alice", Owner: "alice"}, "work", info, nil)
	if err == nil || !strings.Contains(err.Error(), "re-reading session") {
		t.Fatalf("await = %v, want the counting schedd's failure re-reading the session", err)
	}
	reachedOnlyAP(t, "the gateway's poll", before, s.aps.counts(), ap2)
}

// consentFlow is a pending SSH login against s's OAuth2 storage, and a
// browser session for alice with groups.
type consentFlow struct {
	s        *interactiveServer
	userCode string
	cookie   *http.Cookie
}

func newConsentFlow(t *testing.T, s *interactiveServer, user string, groups ...string) *consentFlow {
	t.Helper()
	storage := s.srv.oauth2Provider.GetStorage()
	client := &fosite.DefaultClient{
		ID:         sshGatewayClientID,
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
		Scopes:     sshGatewayScopes,
		Public:     true,
	}
	if err := storage.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}
	dh := NewDeviceCodeHandler(storage, &fosite.Config{AccessTokenIssuer: "http://localhost:8080"})
	resp, err := dh.HandleDeviceAuthorizationRequest(context.Background(), client, sshGatewayScopes, "work")
	if err != nil {
		t.Fatalf("device authorization: %v", err)
	}
	sid, _, err := s.srv.sessionStore.Create(user, groups)
	if err != nil {
		t.Fatal(err)
	}
	return &consentFlow{s: s, userCode: resp.UserCode, cookie: &http.Cookie{Name: sessionCookieName, Value: sid}} //nolint:gosec // test cookie
}

func (f *consentFlow) do(t *testing.T, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	req.AddCookie(f.cookie)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	f.s.srv.ServeHTTP(rec, req)
	return rec
}

// Approving an SSH login with a workspace, through the HTTP endpoints,
// places it with the groups the browser session recorded: a GROUP rule
// decides, and the screen names that AP.
func TestMultiAPSSHApprovalPassesTheSessionsGroups(t *testing.T) {
	s := newInteractiveServer(t, "GROUP physics "+ap3+"\nUSER alice@d "+ap1+"\n", nil)
	f := newConsentFlow(t, s, "alice", "physics")
	rec := f.do(t, http.MethodGet, sshConsentReadPath+"?user_code="+f.userCode, "")
	var view sshConsentView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &view) != nil {
		t.Fatalf("read = %d %s", rec.Code, rec.Body.String())
	}
	if view.Schedd != ap3 {
		t.Errorf("the screen says a new workspace goes to %q, want %s", view.Schedd, ap3)
	}
	body, _ := json.Marshal(sshConsentDecision{UserCode: f.userCode, Action: "approve",
		ApprovalToken: view.ApprovalToken, Create: &InteractiveCreateTerminalRequest{}})
	before := s.aps.counts()
	rec = f.do(t, http.MethodPost, sshConsentApprovePath, string(body))
	reachedOnlyAP(t, "an approval's workspace", before, s.aps.counts(), ap3)
	if rec.Code == http.StatusOK {
		t.Errorf("approve succeeded though the counting schedd cannot take a session: %s", rec.Body.String())
	}
}

// The approval screen refuses an identity in another UID domain, read
// and approve alike, before anything is looked for.
func TestMultiAPSSHApprovalScreenRefusesAForeignDomain(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap2+"\n", func(hub *multiaptest.DB) {
		hub.PutJob(ap2, "alice@d", 7, 0, sessionWork+"\nJobStatus = 2")
	})
	f := newConsentFlow(t, s, "alice@other.example")
	before := s.aps.counts()
	rec := f.do(t, http.MethodGet, sshConsentReadPath+"?user_code="+f.userCode, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("read as alice@other.example = %d %s, want 403", rec.Code, rec.Body.String())
	}
	body, _ := json.Marshal(sshConsentDecision{UserCode: f.userCode, Action: "approve", ApprovalToken: "x",
		Create: &InteractiveCreateTerminalRequest{}})
	rec = f.do(t, http.MethodPost, sshConsentApprovePath, string(body))
	if rec.Code != http.StatusForbidden {
		t.Errorf("approve as alice@other.example = %d %s, want 403", rec.Code, rec.Body.String())
	}
	reachedNone(t, "the approval screen for alice@other.example", before, s.aps.counts())
	if !s.srv.oauth2Provider.GetStorage().DeviceCodeIsPending(context.Background(), f.userCode) {
		t.Error("the login was approved for an identity in another domain")
	}
}

// After a rollback to one schedd, a row a multi-AP server wrote for
// another AP is not looked for on this schedd (its cluster id there is
// some other job), while a row naming this schedd, or none, still is.
func TestSingleAPJupyterRowOfAnotherAPIsNotQueried(t *testing.T) {
	stubJupyterHelper(t)
	fake := newJupyterFakeSchedd()
	h := newJupyterRestartHandler(t, t.TempDir()+"/app.db", fake)
	h.schedd = htcondor.NewSchedd("ap-own.example.org", "<127.0.0.1:1>")
	for _, row := range []struct{ id, schedd string }{{"foreign", "ap-other.example.org"}, {"own", "AP-OWN.example.org"}, {"legacy", ""}} {
		if _, err := h.db.ExecContext(context.Background(), `
			INSERT INTO jupyter_sessions (instance_id, owner, cluster_id, proc_id, image, schedd, next_nonce, created_at, expires_at)
			VALUES (?, 'alice', 77, 0, '', ?, x'00', ?, ?)`,
			row.id, row.schedd, time.Now().UTC(), time.Now().Add(time.Hour).UTC()); err != nil {
			t.Fatal(err)
		}
	}
	fake.setStatus(77, 2)
	got := map[string]JupyterInstanceSummary{}
	for _, inst := range listJupyterSessions(t, h) {
		got[inst.InstanceID] = inst
	}
	if f := got["foreign"]; f.InstanceID == "" || f.JobID != "" || f.JobStatus != 0 {
		t.Errorf("the other AP's row = %+v, want it listed with no job id and no status", f)
	}
	for _, id := range []string{"own", "legacy"} {
		if r := got[id]; r.JobID != "77.0" || r.JobStatus != 2 {
			t.Errorf("row %s = %+v, want job 77.0 read from this schedd", id, r)
		}
	}
	// One query for the own-named row and one for the legacy row (they
	// group by recorded AP); none for the other AP's.
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.constraints) != 2 {
		t.Errorf("status queries = %q, want two (none for the other AP's row)", fake.constraints)
	}
}

// One AP that never answers does not stall the JupyterLab list: it is
// given up on, its session listed unread and not reaped, and the other
// AP's session is read.
func TestMultiAPJupyterListSurvivesAHangingAP(t *testing.T) {
	stubJupyterHelper(t)
	prev := jupyterAPTimeout
	jupyterAPTimeout = 200 * time.Millisecond
	t.Cleanup(func() { jupyterAPTimeout = prev })
	s := newInteractiveServer(t, "USER alice@d "+ap1+"\n", nil)
	fakes := newAPJupyterSchedds(t, ap1, ap2, ap3)
	s.srv.jupyterScheddOverride = fakes
	create := func() JupyterCreateResponse {
		rec := doAlice(t, s.srv, http.MethodPost, "/api/v1/jupyter/instances", `{}`)
		var c JupyterCreateResponse
		if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &c) != nil {
			t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
		}
		return c
	}
	on1 := create()
	s.writeMap(t, "USER alice@d "+ap2+"\n")
	on2 := create()
	if on1.Schedd != ap1 || on2.Schedd != ap2 {
		t.Fatalf("sessions on %s and %s", on1.Schedd, on2.Schedd)
	}
	c1, _ := strconv.Atoi(on1.ClusterID)
	fakes.byAP[ap1].setStatus(c1, 2)
	fakes.mu.Lock()
	fakes.hang = map[string]bool{ap2: true}
	fakes.mu.Unlock()

	start := time.Now()
	rec := doAlice(t, s.srv, http.MethodGet, "/api/v1/jupyter/instances", "")
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the list took %s with one AP hanging", elapsed)
	}
	var list struct {
		Instances []JupyterInstanceSummary `json:"instances"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Instances) != 2 {
		t.Fatalf("list = %d %s, want both sessions", rec.Code, rec.Body.String())
	}
	for _, inst := range list.Instances {
		if inst.InstanceID == on1.InstanceID && inst.JobStatus != 2 {
			t.Errorf("%s's session was not read: %+v", ap1, inst)
		}
	}
}
