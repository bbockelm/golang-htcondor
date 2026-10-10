package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
)

// REST job reads are owner-scoped by who the caller is, not by whether a
// session cookie came with the request. These drive the endpoints through
// ServeHTTP against a fake CEDAR schedd holding one job, one history
// record and one epoch record each for alice and bob. The schedd applies
// no owner filter to reads (a real one does not either), so whatever comes
// back is what the constraint this server sent admits.

// staticGroups is a system group source answering from a map.
type staticGroups map[string][]string

func (g staticGroups) LookupGroups(_ context.Context, user string) ([]string, error) {
	return g[user], nil
}

func (g staticGroups) Name() string { return "static" }

type twoOwnerFixture struct {
	s       *Server
	schedd  *fakeschedd.Schedd
	keyFile string
}

// twoOwnerScheddServer is a server whose schedd holds alice's job 1.0 and
// bob's job 2.0, history records 11.0 (alice) and 12.0 (bob), and epoch
// records 21.0 (alice) and 22.0 (bob). The Web UI admin group is
// condor-admins, and groups are read from the "system", where root is in
// it and nobody else is.
func twoOwnerScheddServer(t *testing.T) *twoOwnerFixture {
	t.Helper()
	keyFile := writeTestSigningKey(t)
	fs := fakeschedd.Start(t, keyFile, "test.domain")
	fs.AddJobs(fakeschedd.JobAd(1, 0, "alice", 1), fakeschedd.JobAd(2, 0, "bob", 1))
	fs.AddHistory(fakeschedd.JobAd(11, 0, "alice", 4), fakeschedd.JobAd(12, 0, "bob", 4))
	fs.AddEpochs(fakeschedd.JobAd(21, 0, "alice", 4), fakeschedd.JobAd(22, 0, "bob", 4))

	cfg := newTestConfig(t)
	cfg.ScheddAddr = fs.Addr()
	cfg.SigningKeyPath = keyFile
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "test.domain"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.webuiAdminGroups = newGroupSet("condor-admins")
	s.localIdentity = &localIdentity{groups: staticGroups{"root": {"condor-admins"}}}
	s.setupRoutes()
	return &twoOwnerFixture{s: s, schedd: fs, keyFile: keyFile}
}

// bearer returns an auth func presenting an IDTOKEN for user@test.domain
// that the schedd accepts and this server already knows as that user.
// scopes, when given, are the grant's scopes, as an OAuth2 access token
// this server issued would carry them.
func (f *twoOwnerFixture) bearer(t *testing.T, user string, scopes ...string) func(*http.Request) {
	t.Helper()
	now := time.Now().Unix()
	identity := user + "@test.domain"
	tok, err := security.GenerateJWT(filepath.Dir(f.keyFile), filepath.Base(f.keyFile), identity, "test.domain", now, now+3600, nil)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	if _, err := f.s.tokenCache.Add(tok); err != nil {
		t.Fatalf("caching the bearer: %v", err)
	}
	f.s.tokenCache.MarkValidated(tok, identity)
	if len(scopes) > 0 {
		f.s.tokenCache.SetCondorCredential(tok, tok, scopes)
	}
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

// session returns an auth func attaching a browser session for user.
func (f *twoOwnerFixture) session(t *testing.T, user string, groups ...string) func(*http.Request) {
	t.Helper()
	return func(r *http.Request) { withSession(t, f.s, r, user, groups...) }
}

// armedSuperuser returns an auth func attaching a session for user that
// has armed superuser mode with global scope.
func (f *twoOwnerFixture) armedSuperuser(t *testing.T, user string) func(*http.Request) {
	t.Helper()
	h := f.s.Handler
	h.initSuperuserMode(HandlerConfig{SuperuserGroup: "condor-su"}, h.logger)
	if !h.superuserModeAvailable() {
		t.Fatal("superuser mode did not come up")
	}
	sid, _, err := h.sessionStore.Create(user, []string{"condor-su"})
	if err != nil {
		t.Fatal(err)
	}
	h.superuserArmed.Arm(sid, armedSession{identity: user + "@test.domain"})
	return func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec // test cookie
	}
}

func (f *twoOwnerFixture) do(t *testing.T, method, path, body string, auth func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequestWithContext(ctx, method, path, nil)
	} else {
		req = httptest.NewRequestWithContext(ctx, method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	auth(req)
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, req)
	return w
}

// owners runs a GET that returns ads under key and lists their Owners,
// sorted.
func (f *twoOwnerFixture) owners(t *testing.T, path, key string, auth func(*http.Request)) []string {
	t.Helper()
	w := f.do(t, http.MethodGet, path, "", auth)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, w.Code, w.Body.String())
	}
	var resp map[string]json.RawMessage
	var ads []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GET %s: decoding %s: %v", path, w.Body.String(), err)
	}
	if err := json.Unmarshal(resp[key], &ads); err != nil {
		t.Fatalf("GET %s: decoding %q of %s: %v", path, key, w.Body.String(), err)
	}
	var got []string
	for _, ad := range ads {
		owner, _ := ad["Owner"].(string)
		got = append(got, owner)
	}
	slices.Sort(got)
	return got
}

// TestRESTBearerReadIsOwnerScoped: a bearer for bob reads only bob's jobs,
// history and epochs, whatever owned_by_me says, and alice's job by id is
// not found.
func TestRESTBearerReadIsOwnerScoped(t *testing.T) {
	f := twoOwnerScheddServer(t)
	bob := f.bearer(t, "bob")

	if w := f.do(t, http.MethodGet, "/api/v1/jobs/1.0", "", bob); w.Code != http.StatusNotFound {
		t.Errorf("bob's bearer GET alice's job 1.0: status %d, want 404: %s", w.Code, w.Body.String())
	}
	if w := f.do(t, http.MethodGet, "/api/v1/jobs/2.0", "", bob); w.Code != http.StatusOK {
		t.Errorf("bob's bearer GET his own job 2.0: status %d, want 200: %s", w.Code, w.Body.String())
	}

	for _, tc := range []struct{ path, key string }{
		{"/api/v1/jobs?owned_by_me=false&limit=*", "jobs"},
		{"/api/v1/jobs/archive?owned_by_me=false", "ads"},
		{"/api/v1/jobs/epochs?owned_by_me=false", "ads"},
	} {
		if got := f.owners(t, tc.path, tc.key, bob); !slices.Equal(got, []string{"bob"}) {
			t.Errorf("bob's bearer GET %s read owners %v, want [bob]", tc.path, got)
		}
	}
}

// An administrator by identity is unconfined on a bearer too: root's
// system groups include the Web UI admin group.
func TestRESTAdminBearerReadsEveryone(t *testing.T) {
	f := twoOwnerScheddServer(t)
	root := f.bearer(t, "root")

	if w := f.do(t, http.MethodGet, "/api/v1/jobs/1.0", "", root); w.Code != http.StatusOK {
		t.Errorf("admin bearer GET alice's job: status %d: %s", w.Code, w.Body.String())
	}
	for _, tc := range []struct{ path, key string }{
		{"/api/v1/jobs?owned_by_me=false&limit=*", "jobs"},
		{"/api/v1/jobs/archive", "ads"},
		{"/api/v1/jobs/epochs", "ads"},
	} {
		if got := f.owners(t, tc.path, tc.key, root); !slices.Equal(got, []string{"alice", "bob"}) {
			t.Errorf("admin bearer GET %s read owners %v, want both", tc.path, got)
		}
	}
}

// A grant carrying mcp:admin reads everyone's jobs on REST as it does on
// MCP, and does not thereby gain the power to act on them.
func TestRESTMCPAdminGrantReadsButDoesNotAct(t *testing.T) {
	f := twoOwnerScheddServer(t)
	carol := f.bearer(t, "carol", "mcp:read", "mcp:write", "mcp:admin")

	if got := f.owners(t, "/api/v1/jobs?owned_by_me=false&limit=*", "jobs", carol); !slices.Equal(got, []string{"alice", "bob"}) {
		t.Errorf("mcp:admin grant read owners %v, want both", got)
	}
	if w := f.do(t, http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"true"}`, carol); w.Code != http.StatusNotFound {
		t.Errorf("mcp:admin grant bulk hold: status %d, want 404 (carol owns nothing): %s", w.Code, w.Body.String())
	}
	if held := f.schedd.ActedOn(); len(held) != 0 {
		t.Errorf("mcp:admin grant held %v; the read tier must not act on other users' jobs", held)
	}
}

// A non-admin browser session is confined as it always was, and an admin
// session and an armed superuser are not.
func TestRESTSessionReadScope(t *testing.T) {
	f := twoOwnerScheddServer(t)

	if got := f.owners(t, "/api/v1/jobs?owned_by_me=false&limit=*", "jobs", f.session(t, "alice")); !slices.Equal(got, []string{"alice"}) {
		t.Errorf("alice's session read owners %v, want [alice]", got)
	}
	if got := f.owners(t, "/api/v1/jobs/archive?owned_by_me=false", "ads", f.session(t, "alice")); !slices.Equal(got, []string{"alice"}) {
		t.Errorf("alice's session read history owners %v, want [alice]", got)
	}
	if got := f.owners(t, "/api/v1/jobs?owned_by_me=false&limit=*", "jobs", f.session(t, "root", "condor-admins")); !slices.Equal(got, []string{"alice", "bob"}) {
		t.Errorf("admin session read owners %v, want both", got)
	}
	armed := f.armedSuperuser(t, "dave")
	if got := f.owners(t, "/api/v1/jobs?owned_by_me=false&limit=*", "jobs", armed); !slices.Equal(got, []string{"alice", "bob"}) {
		t.Errorf("armed superuser session read owners %v, want both", got)
	}
	if w := f.do(t, http.MethodGet, "/api/v1/jobs/1.0", "", armed); w.Code != http.StatusOK {
		t.Errorf("armed superuser GET alice's job: status %d: %s", w.Code, w.Body.String())
	}
}

// Bulk hold and single-job edit are confined to the caller's own jobs for
// a non-admin bearer, and the protected-attribute override is refused.
func TestRESTBearerMutationsAreOwnerScoped(t *testing.T) {
	f := twoOwnerScheddServer(t)
	bob := f.bearer(t, "bob")

	w := f.do(t, http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"true"}`, bob)
	if w.Code != http.StatusOK {
		t.Fatalf("bob's bulk hold: status %d: %s", w.Code, w.Body.String())
	}
	if held := f.schedd.ActedOn(); !slices.Equal(held, []string{"2.0"}) {
		t.Errorf("bob's bulk hold of constraint=true acted on %v, want only his own 2.0", held)
	}

	w = f.do(t, http.MethodPatch, "/api/v1/jobs/1.0", `{"attributes":{"Foo":1}}`, bob)
	if w.Code != http.StatusNotFound {
		t.Errorf("bob's PATCH of alice's job 1.0: status %d, want 404: %s", w.Code, w.Body.String())
	}
	// His own job gets past the scope; the fake has no QMGMT, so the
	// edit itself then fails, which is not what this asserts.
	w = f.do(t, http.MethodPatch, "/api/v1/jobs/2.0", `{"attributes":{"Foo":1}}`, bob)
	if w.Code == http.StatusNotFound {
		t.Errorf("bob's PATCH of his own job 2.0 was not found: %s", w.Body.String())
	}

	for _, option := range []string{"allow_protected_attrs", "force"} {
		w = f.do(t, http.MethodPatch, "/api/v1/jobs",
			`{"constraint":"true","attributes":{"Foo":1},"options":{"`+option+`":true}}`, bob)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "only to administrators") {
			t.Errorf("bob's bulk edit with %s: status %d, want 403 refusing the option: %s", option, w.Code, w.Body.String())
		}
	}
}

// seesAllJobs is the one place the rule lives; pin each clause of it.
func TestSeesAllJobsRule(t *testing.T) {
	f := twoOwnerScheddServer(t)
	h := f.s.Handler
	h.mcpAdminUsers = []string{"lister@test.domain"}

	bearerCtx := func(actor string, scopes ...string) context.Context {
		ctx := htcondor.WithAuthenticatedUser(context.Background(), actor)
		return withAPIKeyScopes(ctx, scopes)
	}
	bare := func() *http.Request {
		return httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
	}
	for _, tc := range []struct {
		name         string
		ctx          context.Context
		read, mutate bool
	}{
		{"plain bearer", bearerCtx("bob@test.domain"), false, false},
		{"admin by system groups", bearerCtx("root@test.domain"), true, true},
		{"admin name in another realm", bearerCtx("root@elsewhere.org"), false, false},
		{"mcp:admin grant", bearerCtx("carol@test.domain", "mcp:read", "mcp:admin"), true, false},
		{"mcp:superuser grant", bearerCtx("carol@test.domain", "mcp:write", "mcp:superuser"), false, true},
		{"MCP_ADMIN_USERS, unscoped credential", bearerCtx("lister@test.domain"), true, false},
		{"MCP_ADMIN_USERS, scoped credential withholding mcp:admin", bearerCtx("lister@test.domain", "mcp:read"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.seesAllJobs(tc.ctx, bare(), jobScopeRead); got != tc.read {
				t.Errorf("read tier = %v, want %v", got, tc.read)
			}
			if got := h.seesAllJobs(tc.ctx, bare(), jobScopeMutate); got != tc.mutate {
				t.Errorf("mutate tier = %v, want %v", got, tc.mutate)
			}
		})
	}
}
