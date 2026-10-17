package httpserver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// OAuth2 is served whenever the web UI or MCP is; MCP gates only MCP.
//
// This has regressed more than once: the provider was created under
// EnableMCP, so a web UI with MCP off had no metadata, no login callback
// and no device flow, and every later fix moved one piece out of that
// block and left the rest. These tests pin the whole surface for every
// combination, so putting any of it back under EnableMCP fails here.

// newSurfaceServer builds a server with the given surfaces and its routes
// registered, without starting it (see newMCPPathServer).
func newSurfaceServer(t *testing.T, webUI, mcp bool) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.EnableMCP = mcp
	cfg.WebUIEnabled = webUI
	cfg.OAuth2Issuer = "https://api.example.org"
	cfg.HTTPBaseURL = "https://api.example.org"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()
	return s
}

// routed reports whether path has a route of its own, rather than falling
// through to the catch-all at "/" (the SPA, or the welcome page) or the
// /.well-known/ 404. Asking the mux, rather than reading a status code,
// is what keeps a catch-all's 200 from passing for a route.
func routed(s *Server, method, path string) bool {
	req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	_, pattern := s.mux.Handler(req)
	return pattern != "" && pattern != "/" && pattern != "/.well-known/"
}

func surfaceName(webUI, mcp bool) string {
	return map[bool]string{true: "webui", false: "no-webui"}[webUI] + "/" +
		map[bool]string{true: "mcp", false: "no-mcp"}[mcp]
}

func TestOAuth2IsServedWithTheWebUIOrMCP(t *testing.T) {
	for _, webUI := range []bool{false, true} {
		for _, mcp := range []bool{false, true} {
			t.Run(surfaceName(webUI, mcp), func(t *testing.T) {
				s := newSurfaceServer(t, webUI, mcp)
				oauth := webUI || mcp

				if got := s.oauth2Provider != nil; got != oauth {
					t.Fatalf("OAuth2 provider present = %v, want %v", got, oauth)
				}

				// Authorization server metadata (RFC 8414).
				req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
					"/.well-known/oauth-authorization-server", nil)
				w := httptest.NewRecorder()
				s.ServeHTTP(w, req)
				wantStatus := http.StatusNotFound
				if oauth {
					wantStatus = http.StatusOK
				}
				if w.Code != wantStatus {
					t.Fatalf("authorization server metadata: %d, want %d (%s)", w.Code, wantStatus, w.Body.String())
				}

				// The plain OAuth2 endpoints, the callback and the device
				// verification page: whenever OAuth2 is.
				for _, path := range []string{
					"/oauth2/token",
					"/oauth2/authorize",
					"/oauth2/device/authorize",
					"/oauth2/register",
					"/oauth2/introspect",
					"/oauth2/revoke",
					"/oauth2/consent",
					webUICallbackPath,
					webUIDeviceVerifyPath,
					wellKnownProtectedResource,
				} {
					if got := routed(s, http.MethodPost, path); got != oauth {
						t.Errorf("%s routed = %v, want %v", path, got, oauth)
					}
				}

				// MCP, its /mcp/ spelling of the OAuth2 endpoints and the
				// documents describing /mcp: only with MCP.
				for _, path := range []string{
					mcpPath,
					mcpMessagePath,
					"/mcp/oauth2/token",
					"/mcp/oauth2/device/authorize",
					"/mcp/oauth2/register",
					mcpCallbackPath,
					mcpDeviceVerifyPath,
					wellKnownProtectedResource + mcpPath,
					wellKnownProtectedResource + mcpMessagePath,
				} {
					if got := routed(s, http.MethodPost, path); got != mcp {
						t.Errorf("%s routed = %v, want %v", path, got, mcp)
					}
				}

				if !oauth {
					return
				}
				var md map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &md); err != nil {
					t.Fatalf("decoding metadata: %v (%s)", err, w.Body.String())
				}

				// Every endpoint the metadata names is one this server
				// routes. Advertising a path that is not routed is the
				// failure a client cannot recover from by itself.
				for _, field := range []string{
					"authorization_endpoint", "token_endpoint", "introspection_endpoint",
					"revocation_endpoint", "device_authorization_endpoint", "registration_endpoint",
				} {
					raw, _ := md[field].(string)
					u, err := url.Parse(raw)
					if raw == "" || err != nil {
						t.Errorf("%s = %q", field, raw)
						continue
					}
					if !routed(s, http.MethodPost, u.Path) {
						t.Errorf("%s advertises %s, which is not routed", field, u.Path)
					}
				}

				// The /mcp/ spelling is advertised only where MCP is all
				// there is; that is what MCP clients of such a server
				// have always discovered.
				wantToken := "https://api.example.org/oauth2/token"
				if mcp && !webUI {
					wantToken = "https://api.example.org/mcp/oauth2/token"
				}
				if got := md["token_endpoint"]; got != wantToken {
					t.Errorf("token_endpoint = %v, want %s", got, wantToken)
				}

				// mcp:read and mcp:write only with MCP; the rest always.
				scopes := metadataScopes(t, md)
				for _, scope := range []string{"mcp:read", "mcp:write"} {
					if got := slices.Contains(scopes, scope); got != mcp {
						t.Errorf("scopes_supported has %s = %v, want %v (%v)", scope, got, mcp, scopes)
					}
				}
				for _, scope := range []string{
					"openid", "profile", "email", "offline_access",
					"mcp:admin", "mcp:superuser", "condor:/READ", "condor:/WRITE",
				} {
					if !slices.Contains(scopes, scope) {
						t.Errorf("scopes_supported lacks %s (%v)", scope, scopes)
					}
				}
			})
		}
	}
}

// With MCP on, the advertisement is exactly what it was before OAuth2
// was separated from MCP: MCP clients such as claude.ai discovered it,
// and a scope dropped from it stops being requestable by a CIMD client.
func TestMCPMetadataScopesAreUnchanged(t *testing.T) {
	for _, webUI := range []bool{false, true} {
		s := newSurfaceServer(t, webUI, true)
		if got := s.advertisedScopes(); !slices.Equal(got, oauth2AdvertisedScopes) {
			t.Errorf("web UI %v: advertised %v, want %v", webUI, got, oauth2AdvertisedScopes)
		}
	}
}

// The protected-resource document for the REST API is served with OAuth2,
// and names the same scopes as the authorization server.
func TestProtectedResourceMetadataWithoutMCP(t *testing.T) {
	s := newSurfaceServer(t, true, false)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, wellKnownProtectedResource, nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", wellKnownProtectedResource, w.Code, w.Body.String())
	}
	var md map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	if got := metadataScopes(t, md); slices.Contains(got, "mcp:read") || slices.Contains(got, "mcp:write") {
		t.Errorf("scopes_supported advertises MCP scopes without MCP: %v", got)
	}
	if doc, _ := md["resource_documentation"].(string); strings.HasSuffix(doc, "/mcp") {
		t.Errorf("resource_documentation = %q, which is not served without MCP", doc)
	}
}

func metadataScopes(t *testing.T, md map[string]any) []string {
	t.Helper()
	raw, ok := md["scopes_supported"].([]any)
	if !ok {
		t.Fatalf("scopes_supported is %T", md["scopes_supported"])
	}
	scopes := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		scopes = append(scopes, s)
	}
	return scopes
}

// The device flow end to end on a web UI with MCP off: discover the
// endpoints, register, authorize a device, approve it as a person, and
// redeem the code for a token. Every step goes through the router, so a
// route left under the MCP gate fails here rather than in production.
func TestDeviceFlowWithWebUIAndWithoutMCP(t *testing.T) {
	srv := startSurfaceServer(t, true, false)

	// Discovery.
	md := surfaceGetJSON(t, srv, "/.well-known/oauth-authorization-server")
	endpoint := func(field string) string {
		t.Helper()
		raw, _ := md[field].(string)
		u, err := url.Parse(raw)
		if raw == "" || err != nil {
			t.Fatalf("%s = %q", field, raw)
		}
		if strings.HasPrefix(u.Path, "/mcp/") {
			t.Fatalf("%s = %q, which is under /mcp/ on a server without MCP", field, raw)
		}
		return u.Path
	}

	// Registration (RFC 7591).
	body := `{"client_name":"no-mcp-device","redirect_uris":["http://127.0.0.1/callback"],` +
		`"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"token_endpoint_auth_method":"none"}`
	w := surfaceRequest(t, srv, http.MethodPost, endpoint("registration_endpoint"), "application/json", body, "")
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("registration: %d %s", w.Code, w.Body.String())
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil || reg.ClientID == "" {
		t.Fatalf("registration gave no client_id: %v (%s)", err, w.Body.String())
	}

	// Device authorization (RFC 8628).
	form := url.Values{"client_id": {reg.ClientID}, "scope": {"openid"}}
	w = surfaceRequest(t, srv, http.MethodPost, endpoint("device_authorization_endpoint"),
		"application/x-www-form-urlencoded", form.Encode(), "")
	if w.Code != http.StatusOK {
		t.Fatalf("device authorization: %d %s", w.Code, w.Body.String())
	}
	var dev struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &dev); err != nil || dev.DeviceCode == "" || dev.UserCode == "" {
		t.Fatalf("device authorization response: %v (%s)", err, w.Body.String())
	}
	verify, err := url.Parse(dev.VerificationURI)
	if err != nil || verify.Path != webUIDeviceVerifyPath {
		t.Fatalf("verification_uri = %q, want path %s", dev.VerificationURI, webUIDeviceVerifyPath)
	}

	// A person approves it at the page they were sent to.
	approve := url.Values{
		"user_code":      {dev.UserCode},
		"action":         {"approve"},
		consentCSRFField: {srv.consentCSRFToken(deviceVerifyTestUser, dev.UserCode)},
	}
	w = surfaceRequest(t, srv, http.MethodPost, verify.Path, "application/x-www-form-urlencoded",
		approve.Encode(), deviceVerifyTestUser)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Authorization Complete") {
		t.Fatalf("approval: %d %s", w.Code, w.Body.String())
	}

	// The device redeems the code.
	redeem := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {dev.DeviceCode},
		"client_id":   {reg.ClientID},
	}
	w = surfaceRequest(t, srv, http.MethodPost, endpoint("token_endpoint"),
		"application/x-www-form-urlencoded", redeem.Encode(), "")
	if w.Code != http.StatusOK {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("no access token: %v (%s)", err, w.Body.String())
	}
}

// startSurfaceServer starts a server with the given surfaces and the user
// header, so a test can arrive as an identified browser user.
func startSurfaceServer(t *testing.T, webUI, mcp bool) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.Logger = testLogger(t)
	cfg.EnableMCP = mcp
	cfg.WebUIEnabled = webUI
	cfg.SigningKeyPath = writeSigningKey(t)
	cfg.TrustDomain = "flock.example.org"
	cfg.UIDDomain = "example.org"
	cfg.UserHeader = "X-Test-User"
	cfg.UserHeaderTrustAnyUnsafe = true // single-host test, no proxy in front
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := s.Handler.Start(t.Context(), ln, "http"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

func surfaceRequest(t *testing.T, srv *Server, method, path, contentType, body, user string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func surfaceGetJSON(t *testing.T, srv *Server, path string) map[string]any {
	t.Helper()
	w := surfaceRequest(t, srv, http.MethodGet, path, "", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET %s: %v (%s)", path, err, w.Body.String())
	}
	return out
}
