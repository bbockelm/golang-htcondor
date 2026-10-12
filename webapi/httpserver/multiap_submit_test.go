package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

const ap3 = "ap3.example.org"

// submitServer is a multi-AP server over three counting schedds, with
// the assignment read from a mapfile and a fake credd per AP.
type submitServer struct {
	srv     *Server
	svc     *multiap.Service
	aps     *actionAPs
	mapfile string
	credds  map[string]*fakeCredd
}

func newSubmitServer(t *testing.T, mapfile string, required ...string) *submitServer {
	t.Helper()
	aps := newActionAPs(t, ap1, ap2, ap3)
	svc := multiAPService(t, multiAPHub(t), aps.reg)
	s := &submitServer{svc: svc, aps: aps, credds: map[string]*fakeCredd{}}
	for _, n := range []string{ap1, ap2, ap3} {
		s.credds[n] = newFakeCredd()
	}
	s.mapfile = filepath.Join(t.TempDir(), "assign.map")
	s.writeMap(t, mapfile)
	srv, err := NewServer(Config{
		MultiAP: MultiAPConfig{
			ScheddConstraint: `regexp("^ap", Name)`, service: svc,
			Assignment: apassign.Config{Backends: []string{apassign.BackendMapfile}, Mapfile: s.mapfile},
			creddFor: func(ap string) htcondor.CreddClient {
				if c, ok := s.credds[ap]; ok {
					return c
				}
				return nil
			},
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
		RequiredCredentials:      required,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.setupRoutes()
	// The counting schedds speak no CEDAR, so they cannot answer the
	// identity check; it has tests of its own.
	svc.VerifyCaller = func(context.Context, apregistry.Member, string) error { return nil }
	s.srv = srv
	return s
}

func (s *submitServer) writeMap(t *testing.T, text string) {
	t.Helper()
	if err := os.WriteFile(s.mapfile, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	// A new mtime, whatever the filesystem's resolution.
	future := time.Now().Add(time.Duration(len(text)) * time.Second)
	if err := os.Chtimes(s.mapfile, future, future); err != nil {
		t.Fatal(err)
	}
}

func (s *submitServer) reload(t *testing.T) {
	t.Helper()
	s.srv.ReloadAPAssignment()
}

func reachedOnlyAP(t *testing.T, what string, before, after map[string]int64, want string) {
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

func reachedNone(t *testing.T, what string, before, after map[string]int64) {
	t.Helper()
	for n := range after {
		if after[n] != before[n] {
			t.Errorf("%s reached %s (%d connections)", what, n, after[n]-before[n])
		}
	}
}

const submitJSON = `{"submit_file":"executable = /bin/true\ntransfer_executable = false\nqueue\n"}`

func errorReason(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.Reason
}

// POST /api/v1/jobs lands on the caller's home AP and no other; the
// credential bootstrap asks that AP's credd and no other.
//
// The counting schedds cannot accept a job, so the 201 body (complete
// job_ids, schedd, jobs, assignment) is asserted end to end, in
// e2eSubmitTwoStep.
func TestMultiAPRESTSubmitLandsOnTheAssignedAP(t *testing.T) {
	s := newSubmitServer(t, "USER alice@d "+ap2+" "+ap3+"\n", "scitokens")
	before := s.aps.counts()
	rec := doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs", submitJSON)
	reachedOnlyAP(t, "POST /api/v1/jobs", before, s.aps.counts(), ap2)
	if rec.Code == http.StatusNotImplemented || rec.Code == http.StatusForbidden {
		t.Fatalf("submit refused: %d %s", rec.Code, rec.Body.String())
	}
	if n := s.credds[ap2].checkCount(); n == 0 {
		t.Error("the target AP's credd was not asked for the job's credentials")
	}
	for _, other := range []string{ap1, ap3} {
		if st, _ := s.credds[other].counts(); st != 0 || s.credds[other].checkCount() != 0 {
			t.Errorf("the credd of %s was asked about a submission to %s", other, ap2)
		}
	}
	if n := s.srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times", n)
	}
}

// ?schedd= is honored for the home AP and its alternates only.
func TestMultiAPRESTSubmitExplicitTarget(t *testing.T) {
	s := newSubmitServer(t, "USER alice@d "+ap2+" "+ap3+"\n", "scitokens")
	before := s.aps.counts()
	_ = doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs?schedd="+ap3, submitJSON)
	reachedOnlyAP(t, "submit to the alternate", before, s.aps.counts(), ap3)
	// The cache of present credentials is per credd: having checked ap2
	// (or not) says nothing about ap3.
	if s.credds[ap3].checkCount() == 0 {
		t.Error("the alternate's credd was not asked")
	}

	before = s.aps.counts()
	rec := doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs?schedd="+ap1, submitJSON)
	reachedNone(t, "submit to a non-alternate", before, s.aps.counts())
	if rec.Code != http.StatusForbidden || errorReason(t, rec) != apassign.ReasonTargetNotAllowed {
		t.Errorf("submit to %s = %d %s, want 403 %s", ap1, rec.Code, rec.Body.String(), apassign.ReasonTargetNotAllowed)
	}
}

// Required credentials are cached per credd: a submission to ap2 then to
// ap3 asks both credds, and a second to ap2 asks ap2's no more.
func TestMultiAPRequiredCredentialsPerCredd(t *testing.T) {
	s := newSubmitServer(t, "USER alice@d "+ap2+" "+ap3+"\n", "scitokens")
	_ = doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs", submitJSON)
	st2, puts2 := s.credds[ap2].counts()
	if st2 == 0 || puts2 != 1 {
		t.Fatalf("ap2's credd: %d status checks, %d puts; want the bootstrap", st2, puts2)
	}
	_ = doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs?schedd="+ap3, submitJSON)
	if st3, puts3 := s.credds[ap3].counts(); st3 == 0 || puts3 != 1 {
		t.Errorf("ap3's credd: %d status checks, %d puts; a credential on ap2's credd was taken to be on ap3's", st3, puts3)
	}
	_ = doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs", submitJSON)
	if st, _ := s.credds[ap2].counts(); st != st2 {
		t.Errorf("ap2's credd was asked again within the cache's lifetime (%d -> %d)", st2, st)
	}
	if st, _ := s.credds[ap1].counts(); st != 0 {
		t.Errorf("ap1's credd was asked %d times", st)
	}
}

// Assignment outside the AP set, no assignment, and an absent AP.
func TestMultiAPRESTSubmitRefusals(t *testing.T) {
	s := newSubmitServer(t, "USER alice@d elsewhere.example.org\nUSER bob@d "+ap1+"\n")
	before := s.aps.counts()
	rec := doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs", submitJSON)
	reachedNone(t, "an assignment outside the set", before, s.aps.counts())
	if rec.Code != http.StatusServiceUnavailable || errorReason(t, rec) != apassign.ReasonInvalid {
		t.Errorf("outside the set = %d %s, want 503 %s", rec.Code, rec.Body.String(), apassign.ReasonInvalid)
	}

	rec = doAs(t, s.srv, "carol", http.MethodPost, "/api/v1/jobs")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty body = %d", rec.Code)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs", strings.NewReader(submitJSON))
	req.Header.Set("X-Remote-User", "carol")
	req.Header.Set("Origin", "http://example.com")
	rec = httptest.NewRecorder()
	s.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "no access point is assigned to you") {
		t.Errorf("unassigned user = %d %s", rec.Code, rec.Body.String())
	}

	// bob's home AP leaves the collector.
	s.aps.reg.Update(ap1, func(m *apregistry.Member) { m.Present = false })
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs", strings.NewReader(submitJSON))
	req.Header.Set("X-Remote-User", "bob")
	req.Header.Set("Origin", "http://example.com")
	rec = httptest.NewRecorder()
	before = s.aps.counts()
	s.srv.ServeHTTP(rec, req)
	reachedNone(t, "a submission to an absent AP", before, s.aps.counts())
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("absent home AP = %d %s, want 503", rec.Code, rec.Body.String())
	}
}

// The second step of a two-step submit is routed by the job's id: a
// change to the assignment between the steps does not move it.
func TestMultiAPTwoStepInputIsNotReassigned(t *testing.T) {
	s := newSubmitServer(t, "USER alice@d "+ap2+"\n")
	before := s.aps.counts()
	_ = doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs", submitJSON)
	reachedOnlyAP(t, "step one", before, s.aps.counts(), ap2)

	// The site moves alice to ap1 between the steps. Nothing watches the
	// file in this harness (the background check runs only in a started
	// server), so only the reconfigure-time reload can pick it up: the
	// next submission landing on ap1 proves the reload took effect.
	s.writeMap(t, "USER alice@d "+ap1+"\n")
	s.reload(t)
	before = s.aps.counts()
	_ = doAlice(t, s.srv, http.MethodPost, "/api/v1/jobs", submitJSON)
	reachedOnlyAP(t, "a new submission after the move", before, s.aps.counts(), ap1)

	for _, step := range []struct{ method, sub string }{
		{http.MethodPut, "/input"},
		{http.MethodPost, "/input/multipart"},
		{http.MethodPost, "/input/share"},
	} {
		before = s.aps.counts()
		rec := doAlice(t, s.srv, step.method, "/api/v1/jobs/1.0@"+ap2+step.sub, "x")
		reachedOnlyAP(t, step.method+" "+step.sub+" of the ap2 job", before, s.aps.counts(), ap2)
		if rec.Code == http.StatusForbidden || rec.Code == http.StatusNotImplemented {
			t.Errorf("%s %s = %d %s", step.method, step.sub, rec.Code, clip(rec.Body.String(), 200))
		}
	}
}

// The credential endpoints act on the home AP's credd, or ?schedd='s.
func TestMultiAPCredentialEndpointsFollowTheAP(t *testing.T) {
	s := newSubmitServer(t, "USER alice@d "+ap2+"\n")
	stores := map[string]*htcondor.InMemoryCredd{}
	for _, n := range []string{ap1, ap2, ap3} {
		stores[n] = htcondor.NewInMemoryCredd()
	}
	s.srv.multi.credds.override = func(ap string) htcondor.CreddClient { return stores[ap] }

	rec := doAlice(t, s.srv, http.MethodPost, "/api/v1/creds/service/scitokens",
		`{"cred_type":"oauth","credential":"{\"access_token\":\"x\"}"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("store = %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-HTCondor-Access-Point"); got != ap2 {
		t.Errorf("stored via %q, want %s", got, ap2)
	}
	exists := func(target string) bool {
		rec := doAlice(t, s.srv, http.MethodGet, target, "")
		var st credentialStatusResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil {
			t.Fatalf("GET %s = %d %s", target, rec.Code, rec.Body.String())
		}
		return st.Exists
	}
	if !exists("/api/v1/creds/service/scitokens") {
		t.Error("the home AP's credd does not hold the credential")
	}
	if exists("/api/v1/creds/service/scitokens?schedd=" + ap1) {
		t.Error("ap1's credd holds a credential stored on the home AP")
	}
	rec = doAlice(t, s.srv, http.MethodGet, "/api/v1/creds/service?schedd=nowhere.example.org", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("an AP outside the set = %d %s", rec.Code, rec.Body.String())
	}
	// An AP that advertises no credd.
	s.srv.multi.credds.override = func(string) htcondor.CreddClient { return nil }
	rec = doAlice(t, s.srv, http.MethodGet, "/api/v1/creds/service", "")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), ap2) {
		t.Errorf("no credd = %d %s", rec.Code, rec.Body.String())
	}
}

// /api/v1/aps marks where the caller may submit; whoami names the home AP.
func TestMultiAPReportsTheAssignment(t *testing.T) {
	s := newSubmitServer(t, "USER alice@d "+ap2+" "+ap3+"\n")
	rec := doAlice(t, s.srv, http.MethodGet, "/api/v1/aps", "")
	var aps APsResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &aps) != nil {
		t.Fatalf("aps = %d %s", rec.Code, rec.Body.String())
	}
	if aps.Assignment == nil || aps.Assignment.Schedd != ap2 || strings.Join(aps.Assignment.Alternates, ",") != ap3 ||
		aps.Assignment.Source != "mapfile" {
		t.Errorf("assignment = %+v", aps.Assignment)
	}
	want := map[string][2]bool{ap1: {false, false}, ap2: {true, true}, ap3: {true, false}}
	for _, a := range aps.APs {
		if w := want[a.Schedd]; a.Submit != w[0] || a.Home != w[1] {
			t.Errorf("%s: submit=%v home=%v, want %v", a.Schedd, a.Submit, a.Home, w)
		}
	}

	rec = doAlice(t, s.srv, http.MethodGet, "/api/v1/whoami", "")
	var who WhoAmIResponse
	if json.Unmarshal(rec.Body.Bytes(), &who) != nil || who.Assignment == nil || who.Assignment.Schedd != ap2 {
		t.Errorf("whoami = %s", rec.Body.String())
	}
	rec = doAs(t, s.srv, "carol", http.MethodGet, "/api/v1/whoami")
	if json.Unmarshal(rec.Body.Bytes(), &who) != nil || who.Assignment == nil || who.Assignment.Reason != apassign.ReasonNoAssignment {
		t.Errorf("whoami for an unassigned user = %s", rec.Body.String())
	}
}

// /api/v1/auth/me reports the browser session's home AP.
func TestMultiAPAuthMeReportsTheAssignment(t *testing.T) {
	s := newSubmitServer(t, "GROUP physics "+ap3+"\n")
	sessID, _, err := s.srv.sessionStore.Create("alice", []string{"physics"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessID, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rec := httptest.NewRecorder()
	s.srv.ServeHTTP(rec, req)
	var me AuthMeResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &me) != nil {
		t.Fatalf("auth/me = %d %s", rec.Code, rec.Body.String())
	}
	if !me.MultiAP || me.Assignment == nil || me.Assignment.Schedd != ap3 {
		t.Errorf("auth/me = %s; want the group's AP %s", rec.Body.String(), ap3)
	}
}

// A chain that cannot be built, and a server-wide credd, refuse to start.
func TestMultiAPAssignmentStartupRefusals(t *testing.T) {
	svc := multiAPService(t, multiAPHub(t), newActionAPs(t, ap1).reg)
	for _, tc := range []struct {
		name string
		mc   MultiAPConfig
		cfg  func(*Config)
		want string
	}{
		{name: "mapfile missing", mc: MultiAPConfig{Assignment: apassign.Config{Backends: []string{"mapfile"},
			Mapfile: filepath.Join(t.TempDir(), "missing.map")}}, want: "HTTP_API_AP_ASSIGNMENT_MAPFILE"},
		{name: "rest over plain http", mc: MultiAPConfig{Assignment: apassign.Config{Backends: []string{"rest"},
			RESTURL: "http://assign.example.org"}}, want: "https"},
		{name: "static not last", mc: MultiAPConfig{Assignment: apassign.Config{Backends: []string{"static", "rest"},
			RESTURL: "https://assign.example.org"}}, want: "never be asked"},
		{name: "one credd for every AP", cfg: func(c *Config) { c.CreddAddress = "<1.2.3.4:9620>" }, want: "HTTP_API_CREDD_ADDRESS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mc := tc.mc
			mc.ScheddConstraint, mc.service = `regexp("^ap", Name)`, svc
			svc.Assign = nil
			cfg := Config{MultiAP: mc, Logger: newTestLogger(t), OAuth2DBPath: t.TempDir() + "/o.db", UIDDomain: "d",
				SigningKeyPath: writeTestSigningKey(t), TrustDomain: "test.domain"}
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			if _, err := NewServer(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("NewServer: %v, want an error naming %q", err, tc.want)
			}
		})
	}
}
