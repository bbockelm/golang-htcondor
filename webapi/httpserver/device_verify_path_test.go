package httpserver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Both paths answer, whichever one this build advertises.
//
// A device code lives ten minutes and carries the URL it was issued with,
// so a restart or an upgrade that moved the path would strand whoever was
// mid-login. The callback has the same property for the same reason.
func TestBothDeviceVerifyPathsAreServed(t *testing.T) {
	s := startDeviceVerifyServer(t)
	for _, path := range []string{"/mcp/oauth2/device/verify", "/oauth2/device/verify"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)

			// Unauthenticated, so the answer is a refusal or a redirect to
			// the IDP -- either way it reached the handler. 404 would mean
			// the route is not registered, which is the regression.
			if w.Code == http.StatusNotFound {
				t.Fatalf("%s is not routed: %d %s", path, w.Code, w.Body.String())
			}
		})
	}
}

// startDeviceVerifyServer brings up a server with OAuth2 and its routes.
//
// Routes are built in Start, after initializeOAuth2 settles the provider,
// so a server that has only been constructed has no OAuth2 routes at all
// -- checking the provider before Start passes while testing nothing.
func startDeviceVerifyServer(t *testing.T) *Server {
	t.Helper()
	return startDeviceVerifyServerWith(t, false, true)
}

// startDeviceVerifyServerWith is startDeviceVerifyServer serving the
// given surfaces.
func startDeviceVerifyServerWith(t *testing.T, webUI, mcp bool) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.Logger = testLogger(t)
	cfg.EnableMCP = mcp
	cfg.WebUIEnabled = webUI
	cfg.OAuth2DBPath = t.TempDir() + "/oauth2.db"
	cfg.SigningKeyPath = writeSigningKey(t)
	cfg.TrustDomain = "flock.example.org"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Routes are built in Start, after initializeOAuth2 settles the
	// provider -- so a server that has only been constructed has no
	// OAuth2 routes at all, and checking the provider before Start would
	// pass while testing nothing.
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
	if s.oauth2Provider == nil {
		t.Fatal("precondition: no OAuth2 provider, so neither path is registered")
	}

	return s
}

// The advertised path follows what this server actually serves: the
// /mcp/ spelling only where MCP is all there is.
//
// Every combination, through the choice itself. Test builds do not embed
// the frontend, so anything keyed off the build exercises one branch and
// passes against a function that ignores the flag entirely.
func TestAdvertisedDeviceVerifyPathFollowsTheSurface(t *testing.T) {
	for _, tc := range []struct {
		webUI, mcp bool
		want       string
	}{
		{webUI: false, mcp: true, want: "/mcp/oauth2/device/verify"},
		{webUI: true, mcp: true, want: "/oauth2/device/verify"},
		{webUI: true, mcp: false, want: "/oauth2/device/verify"},
		{webUI: false, mcp: false, want: "/oauth2/device/verify"},
	} {
		h := &Handler{webUIEnabled: tc.webUI, mcpEnabled: tc.mcp}
		if got := h.deviceVerifyPath(); got != tc.want {
			t.Errorf("web UI %v, MCP %v: %q, want %q", tc.webUI, tc.mcp, got, tc.want)
		}
		// It tracks the callback's choice rather than diverging from
		// it: both are user-visible OAuth2 URLs on the same server.
		if strings.HasPrefix(h.deviceVerifyPath(), "/mcp/") != strings.HasPrefix(h.oauth2CallbackPath(), "/mcp/") {
			t.Errorf("web UI %v, MCP %v: device verify is at %q while the callback is at %q; they should agree",
				tc.webUI, tc.mcp, h.deviceVerifyPath(), h.oauth2CallbackPath())
		}
	}
}

// The issued verification_uri is built from the path this server
// advertises, not from a copy of it.
//
// Driven through the real endpoint on servers whose advertised paths
// differ, so a composition hardcoding either spelling fails one of them.
// A single test-build server could not tell: reverting the composition
// to a hardcoded "/mcp/oauth2/device/verify" once broke nothing.
func TestIssuedVerificationURIUsesTheAdvertisedPath(t *testing.T) {
	for _, tc := range []struct {
		name       string
		webUI, mcp bool
		want       string
	}{
		{"mcp only", false, true, "/mcp/oauth2/device/verify"},
		{"web UI and mcp", true, true, "/oauth2/device/verify"},
		{"web UI only", true, false, "/oauth2/device/verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startDeviceVerifyServerWith(t, tc.webUI, tc.mcp)

			form := url.Values{}
			form.Set("client_id", registerDeviceVerifyClient(t, srv))
			form.Set("scope", "openid")
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				srv.oauth2EndpointPath("device/authorize"), strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("device authorization failed: %d %s", w.Code, w.Body.String())
			}
			var got struct {
				VerificationURI         string `json:"verification_uri"`
				VerificationURIComplete string `json:"verification_uri_complete"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("decoding: %v (%s)", err, w.Body.String())
			}
			// Both halves matter: verification_uri is what a client
			// prints when it has nothing better, and
			// verification_uri_complete is the one-click link the SSH
			// gateway shows.
			if !strings.HasSuffix(got.VerificationURI, tc.want) {
				t.Errorf("verification_uri = %q, want it to end in %q", got.VerificationURI, tc.want)
			}
			if !strings.Contains(got.VerificationURIComplete, tc.want+"?") {
				t.Errorf("verification_uri_complete = %q, want it to use %q",
					got.VerificationURIComplete, tc.want)
			}
		})
	}
}

// registerDeviceVerifyClient registers a public client through RFC 7591
// dynamic registration and returns its id.
func registerDeviceVerifyClient(t *testing.T, srv *Server) string {
	t.Helper()
	body := `{"client_name":"device-verify-test","redirect_uris":["http://127.0.0.1/callback"],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"token_endpoint_auth_method":"none"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.oauth2EndpointPath("register"), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("registering a client: %d %s", w.Code, w.Body.String())
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil || reg.ClientID == "" {
		t.Fatalf("registration gave no client_id: %v (%s)", err, w.Body.String())
	}
	return reg.ClientID
}
