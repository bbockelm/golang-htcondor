package httpserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/templates"
)

// gateRefusal is the text requireCondorScope refuses an OAuth2 bearer with,
// which tells its 403 apart from any the handler behind it might give.
const gateRefusal = "lacks the condor:/"

// restAs sends one request through ServeHTTP with a bearer.
func restAs(t *testing.T, s *Server, method, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, method, path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

// jobAccessRoutes connect to a running job and run the caller's code there,
// so they need WRITE whatever the method. The Jupyter proxy in particular
// never asks the schedd anything, so nothing behind it would refuse a
// read-only credential.
var jobAccessRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/jupyter/instances/abc123/proxy/api/kernels"},
	{http.MethodGet, "/api/v1/jobs/1.0/proxy/80/"},
	{http.MethodGet, "/api/v1/jobs/1.0/ssh"},
	{http.MethodPost, "/api/v1/jobs/1.0/warm"},
}

// An OAuth2 access token is held to its grant on REST, as an API key is. A
// read-only grant used to pass the gate untouched -- it applied to API keys
// alone -- and could open the user's notebook kernel with a GET.
func TestReadOnlyOAuth2GrantCannotReachIntoAJob(t *testing.T) {
	for _, grant := range [][]string{
		{"openid", "condor:/READ"},
		{"openid", "mcp:read"},
	} {
		s := newMCPScopeServer(t, false)
		tok := mintMCPAccessToken(t, s, grant)
		for _, route := range jobAccessRoutes {
			t.Run(strings.Join(grant, "+")+" "+route.method+" "+route.path, func(t *testing.T) {
				rec := restAs(t, s, route.method, route.path, tok)
				if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), gateRefusal+"WRITE") {
					t.Errorf("status %d, want the gate's 403 for WRITE: %s", rec.Code, rec.Body.String())
				}
			})
		}
	}
}

// The other direction: a grant carrying WRITE gets past the gate on every
// one of those routes, and a read-only grant still reads.
func TestWriteOAuth2GrantReachesJobAccessRoutes(t *testing.T) {
	for _, grant := range [][]string{
		{"openid", "condor:/READ", "condor:/WRITE"},
		{"openid", "mcp:read", "mcp:write"},
	} {
		s := newMCPScopeServer(t, false)
		tok := mintMCPAccessToken(t, s, grant)
		for _, route := range jobAccessRoutes {
			t.Run(strings.Join(grant, "+")+" "+route.method+" "+route.path, func(t *testing.T) {
				if rec := restAs(t, s, route.method, route.path, tok); strings.Contains(rec.Body.String(), gateRefusal) {
					t.Errorf("a grant with WRITE was refused by the gate: %d %s", rec.Code, rec.Body.String())
				}
			})
		}
	}

	s := newMCPScopeServer(t, false)
	reader := mintMCPAccessToken(t, s, []string{"openid", "condor:/READ"})
	if rec := restAs(t, s, http.MethodGet, "/api/v1/jupyter/instances", reader); strings.Contains(rec.Body.String(), gateRefusal) {
		t.Errorf("a read-only grant was refused a read: %d %s", rec.Code, rec.Body.String())
	}
	if rec := restAs(t, s, http.MethodPost, "/api/v1/jupyter/instances", reader); !strings.Contains(rec.Body.String(), gateRefusal+"WRITE") {
		t.Errorf("a read-only grant was not refused a write: %d %s", rec.Code, rec.Body.String())
	}
}

// A grant approved for nothing is a scoped credential granted nothing, not a
// bearer with no scope model. It is refused both on the request that first
// sees it and once the token cache knows it -- the cached path read the
// grant's scope list by its length and lost the distinction.
func TestEmptyOAuth2GrantIsRefusedOnREST(t *testing.T) {
	for _, grant := range [][]string{{}, {"openid"}} {
		t.Run("grant="+strings.Join(grant, "+"), func(t *testing.T) {
			s := newMCPScopeServer(t, false)
			tok := mintMCPAccessToken(t, s, grant)

			if rec := restAs(t, s, http.MethodGet, "/api/v1/jobs", tok); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), gateRefusal) {
				t.Errorf("first request: status %d, want the gate's 403: %s", rec.Code, rec.Body.String())
			}

			// An identity-only route caches the bearer, as any first
			// request to one would.
			restAs(t, s, http.MethodGet, "/api/v1/whoami", tok)
			if _, ok := s.tokenCache.Get(tok); !ok {
				t.Fatal("precondition: the bearer was not cached")
			}
			if rec := restAs(t, s, http.MethodGet, "/api/v1/jobs", tok); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), gateRefusal) {
				t.Errorf("cached request: status %d, want the gate's 403: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// The handlers that read the scope set themselves see an empty grant as
// scoped too. The SSH certificate endpoint issued a 12-hour WRITE credential
// to any bearer it thought unscoped.
func TestEmptyOAuth2GrantGetsNoSSHCertificate(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"public_key": userPublicKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	post := func(s *Server, tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/api/v1/ssh/certificate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}

	s := newMCPScopeServer(t, false)
	s.sshCASigner = signer
	if rec := post(s, mintMCPAccessToken(t, s, []string{})); rec.Code != http.StatusForbidden {
		t.Errorf("an empty grant: status %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if rec := post(s, mintMCPAccessToken(t, s, []string{"condor:/WRITE"})); rec.Code != http.StatusOK {
		t.Errorf("a WRITE grant: status %d, want a certificate: %s", rec.Code, rec.Body.String())
	}
}

// identityKeyServer is a server whose API keys can be given a schedd
// credential, with alice's private template in its library.
func identityKeyServer(t *testing.T) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.TrustDomain = testTrustDomain
	cfg.UIDDomain = "example.org"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()
	if s.templateLibrary == nil {
		t.Fatal("precondition: no template library")
	}
	if _, err := s.templateLibrary.Save(templates.Template{
		ID: "alices-private", Name: "Alice's private template", Contents: "executable = /bin/true\nqueue\n",
	}, "alice"); err != nil {
		t.Fatalf("seeding a template: %v", err)
	}
	return s
}

// A metrics-only API key is the scrape credential. It used to act as the
// admin who minted it on every route that needs only an identity, and so
// could read, overwrite and delete their templates.
func TestMetricsKeyDoesNotActAsItsCreator(t *testing.T) {
	s := identityKeyServer(t)
	key := gateTestKey(t, s.Handler, []string{"metrics"})

	rec := restAs(t, s, http.MethodGet, "/api/v1/templates", key)
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "alices-private") {
		t.Errorf("GET templates: status %d, the creator's private template must not be listed: %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/templates",
		strings.NewReader(`{"id":"planted","name":"x","contents":"queue"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code < 400 {
		t.Errorf("POST templates: status %d, want a refusal: %s", rec.Code, rec.Body.String())
	}
	if _, ok := s.templateLibrary.Get("planted", "alice"); ok {
		t.Error("a metrics key saved a template as its creator")
	}
	rec = restAs(t, s, http.MethodDelete, "/api/v1/templates/alices-private", key)
	if rec.Code < 400 {
		t.Errorf("DELETE template: status %d, want a refusal: %s", rec.Code, rec.Body.String())
	}
	if _, ok := s.templateLibrary.Get("alices-private", "alice"); !ok {
		t.Error("a metrics key deleted its creator's template")
	}

	rec = restAs(t, s, http.MethodGet, "/api/v1/whoami", key)
	if strings.Contains(rec.Body.String(), `"authenticated":true`) || strings.Contains(rec.Body.String(), "alice") {
		t.Errorf("whoami names the creator to a metrics key: %s", rec.Body.String())
	}
	if rec := restAs(t, s, http.MethodGet, "/api/v1/version", key); rec.Code != http.StatusUnauthorized {
		t.Errorf("version: status %d, want 401", rec.Code)
	}
}

// The other direction: a key with a condor:/* scope still is its creator,
// and the metrics key still scrapes /metrics.
func TestCondorScopedKeyActsAsItsCreator(t *testing.T) {
	s := identityKeyServer(t)
	key := gateTestKey(t, s.Handler, []string{condorScopeRead})
	rec := restAs(t, s, http.MethodGet, "/api/v1/templates", key)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alices-private") {
		t.Errorf("a condor:/READ key does not see its creator's templates: %d %s", rec.Code, rec.Body.String())
	}

	s.metricsPublic = false
	if s.httpMetricsState == nil {
		t.Skip("metrics are not enabled on this server")
	}
	metrics := gateTestKey(t, s.Handler, []string{"metrics"})
	if rec := restAs(t, s, http.MethodGet, "/metrics", metrics); rec.Code != http.StatusOK {
		t.Errorf("a metrics key cannot scrape /metrics: %d %s", rec.Code, rec.Body.String())
	}
}

// /readyz answers anybody. What it tells anybody is a status per daemon,
// not the mirror's name or address or the error text of a failed dial.
func TestReadyzWithholdsDetailsFromAnonymousCallers(t *testing.T) {
	s := identityKeyServer(t)
	s.dbMirror = dbmirror.NewLocatorWithOptions(
		htcondor.NewCollector("collector.invalid"), config.NewEmpty(),
		dbmirror.Options{Name: "db-internal-name", Address: "<10.0.0.5:9619>"})

	rec := restAs(t, s, http.MethodGet, "/readyz", "")
	body := rec.Body.String()
	for _, leak := range []string{"address", "pinned_address", "last_error", "10.0.0.5", "db-internal-name"} {
		if strings.Contains(body, leak) {
			t.Errorf("anonymous /readyz contains %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, `"dbmirror":{"status":`) || !strings.Contains(body, `"schedd":{"status":`) {
		t.Errorf("anonymous /readyz lost the statuses: %s", body)
	}

	// A metrics key, the monitoring credential, sees the details.
	key := gateTestKey(t, s.Handler, []string{"metrics"})
	if body := restAs(t, s, http.MethodGet, "/readyz", key).Body.String(); !strings.Contains(body, `"pinned_address"`) || !strings.Contains(body, "10.0.0.5") {
		t.Errorf("/readyz to a metrics key is missing the mirror details: %s", body)
	}
	// Another key does not.
	other := gateTestKey(t, s.Handler, []string{condorScopeRead})
	if body := restAs(t, s, http.MethodGet, "/readyz", other).Body.String(); strings.Contains(body, "10.0.0.5") {
		t.Errorf("/readyz to a key without metrics shows the mirror details: %s", body)
	}
}

// The admin session sees the details too, as on /api/v1/dbmirror/status.
func TestReadyzShowsDetailsToAnAdminSession(t *testing.T) {
	s := identityKeyServer(t)
	s.webuiAdminGroups = newGroupSet("condor-admins")
	s.dbMirror = dbmirror.NewLocatorWithOptions(
		htcondor.NewCollector("collector.invalid"), config.NewEmpty(),
		dbmirror.Options{Address: "<10.0.0.5:9619>"})

	for _, tc := range []struct {
		groups []string
		want   bool
	}{{[]string{"condor-admins"}, true}, {[]string{"users"}, false}} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil)
		withSession(t, s, req, "root", tc.groups...)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if got := strings.Contains(rec.Body.String(), "10.0.0.5"); got != tc.want {
			t.Errorf("groups %v: details shown = %v, want %v: %s", tc.groups, got, tc.want, rec.Body.String())
		}
	}
}

// Registration accepts only the condor levels a token from this server can
// carry. Anything else was accepted, rendered pre-ticked on the consent
// page, and granted nothing.
func TestRegistrationRefusesCondorLevelsNeverGranted(t *testing.T) {
	s := newMCPScopeServer(t, false)
	register := func(scopes ...string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]any{
			"redirect_uris":  []string{"http://localhost:8080/callback"},
			"grant_types":    []string{"authorization_code"},
			"response_types": []string{"code"},
			"scope":          strings.Join(scopes, " "),
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			OAuth2EndpointPath("register"), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}

	for _, level := range []string{"condor:/ADMINISTRATOR", "condor:/DAEMON", "condor:/ADVERTISE_STARTD", "condor:/read"} {
		if rec := register("openid", "mcp:read", level); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400: %s", level, rec.Code, rec.Body.String())
		}
	}
	if rec := register("openid", "mcp:read", "condor:/READ", "condor:/WRITE"); rec.Code != http.StatusCreated {
		t.Errorf("READ and WRITE: status %d, want 201: %s", rec.Code, rec.Body.String())
	}
}

// The consent page offers neither a level this server never grants nor
// condor:/WRITE to a user the write group denies mcp:write.
func TestConsentPageOffersOnlyGrantableCondorLevels(t *testing.T) {
	render := func(h *Handler, groups []string) string {
		rec := httptest.NewRecorder()
		h.renderConsentPage(context.Background(), rec, groups, consentPageParams{
			Title:    "Authorize",
			Username: "alice",
			ClientID: "c",
			RequestedScopes: []string{"openid", "mcp:read", "mcp:write",
				"condor:/READ", "condor:/WRITE", "condor:/ADMINISTRATOR"},
			FormAction: "/mcp/oauth2/consent",
		})
		return rec.Body.String()
	}

	open := &Handler{logger: testLogger(t)}
	page := render(open, nil)
	if strings.Contains(page, "condor:/ADMINISTRATOR") {
		t.Error("the consent page offers condor:/ADMINISTRATOR, which grants nothing")
	}
	for _, want := range []string{`value="condor:/READ"`, `value="condor:/WRITE"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the consent page does not offer %s", want)
		}
	}

	gated := &Handler{logger: testLogger(t), mcpWriteGroups: newGroupSet("writers")}
	if page := render(gated, []string{"readers"}); strings.Contains(page, `value="condor:/WRITE"`) || strings.Contains(page, `value="mcp:write"`) {
		t.Error("the consent page offers WRITE to a user the write group denies")
	}
	if page := render(gated, []string{"writers"}); !strings.Contains(page, `value="condor:/WRITE"`) {
		t.Error("the consent page does not offer condor:/WRITE to a member of the write group")
	}
}

// condor:/WRITE mints the same authorization as mcp:write, so it follows the
// same group policy -- in any spelling the mapping to a level accepts.
func TestCondorWriteFollowsTheWriteGroup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		h      *Handler
		groups []string
		want   bool
	}{
		{"no groups configured", &Handler{}, nil, true},
		{"write group, member", &Handler{mcpWriteGroups: newGroupSet("writers")}, []string{"writers"}, true},
		{"write group, not a member", &Handler{mcpWriteGroups: newGroupSet("writers")}, []string{"readers"}, false},
		{"access group only, not a member", &Handler{mcpAccessGroups: newGroupSet("login")}, []string{"other"}, false},
		{"access group only, member", &Handler{mcpAccessGroups: newGroupSet("login")}, []string{"login"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, spelling := range []string{"condor:/WRITE", "condor:/write"} {
				got := tc.h.getScopesForGroups(tc.groups, []string{"condor:/READ", spelling})
				granted := false
				for _, s := range got {
					if s == spelling {
						granted = true
					}
				}
				if granted != tc.want {
					t.Errorf("%s granted = %v, want %v (got %v)", spelling, granted, tc.want, got)
				}
				if len(got) == 0 || got[0] != "condor:/READ" {
					t.Errorf("condor:/READ was not granted: %v", got)
				}
			}
		})
	}
}

// A grant whose condor:/* scopes map to no authorization is refused by
// the minter. That is the token's doing, so MCP answers 403
// insufficient_scope rather than a 500 that reads as a broken server; a
// grant that does map still gets in.
func TestMCPRefusedMintIsForbidden(t *testing.T) {
	for _, useSDK := range []bool{false, true} {
		t.Run(transportName(useSDK), func(t *testing.T) {
			s := newMCPScopeServer(t, useSDK)
			tok := mintMCPAccessToken(t, s, []string{"mcp:write", "condor:/ADVERTISE_STARTD"})
			code, resp := mcpRPC(t, s, tok, rpcToolsList)
			if code != http.StatusForbidden || !strings.Contains(resp, "insufficient_scope") {
				t.Errorf("unmappable grant: got %d, want 403 insufficient_scope:\n%s", code, resp)
			}

			ok := mintMCPAccessToken(t, s, []string{"mcp:write", "condor:/WRITE"})
			if code, resp := mcpRPC(t, s, ok, rpcToolsList); code != http.StatusOK {
				t.Errorf("mappable grant: got %d, want 200:\n%s", code, resp)
			}
		})
	}
}
