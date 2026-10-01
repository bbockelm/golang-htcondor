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
	cfg := newTestConfig(t)
	cfg.Logger = testLogger(t)
	cfg.EnableMCP = true
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

// The advertised path follows what this server actually serves.
//
// Asserted against deviceVerifyPathFor rather than the exported wrapper,
// because test builds do not embed the frontend: calling the wrapper
// exercises one branch and passes against a function that ignores the
// flag entirely.
func TestAdvertisedDeviceVerifyPathFollowsTheUI(t *testing.T) {
	if got, want := deviceVerifyPathFor(true), "/oauth2/device/verify"; got != want {
		t.Errorf("with the UI embedded: %q, want %q", got, want)
	}
	if got, want := deviceVerifyPathFor(false), "/mcp/oauth2/device/verify"; got != want {
		t.Errorf("without the UI: %q, want %q", got, want)
	}
	// Both are routed whichever this build advertises, so the exported
	// wrapper must return one of them and not something invented.
	switch OAuth2DeviceVerifyPath() {
	case mcpDeviceVerifyPath, webUIDeviceVerifyPath:
	default:
		t.Errorf("OAuth2DeviceVerifyPath() = %q, which is not a routed path", OAuth2DeviceVerifyPath())
	}
	// And it tracks the callback's choice rather than diverging from it:
	// both are user-visible OAuth2 URLs on the same server.
	if strings.HasPrefix(OAuth2DeviceVerifyPath(), "/mcp/") != strings.HasPrefix(OAuth2CallbackPath(), "/mcp/") {
		t.Errorf("device verify is at %q while the callback is at %q; they should agree",
			OAuth2DeviceVerifyPath(), OAuth2CallbackPath())
	}
}

// The issued verification_uri is built from the path this server
// advertises, not from a copy of it.
//
// Driven through the real endpoint, with deviceVerifyPath swapped to a
// sentinel. Without the swap this test could not fail: test builds do not
// embed the frontend, so the exported function, the MCP constant and a
// hardcoded string all evaluate the same, and reverting the composition
// to a hardcoded path broke nothing.
func TestIssuedVerificationURIUsesTheAdvertisedPath(t *testing.T) {
	const sentinel = "/somewhere/else/verify"
	saved := deviceVerifyPath
	deviceVerifyPath = func() string { return sentinel }
	t.Cleanup(func() { deviceVerifyPath = saved })

	srv := startDeviceVerifyServer(t)

	form := url.Values{}
	form.Set("client_id", registerDeviceVerifyClient(t, srv))
	form.Set("scope", "openid")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/mcp/oauth2/device/authorize", strings.NewReader(form.Encode()))
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
	// Both halves matter: verification_uri is what a client prints when
	// it has nothing better, and verification_uri_complete is the
	// one-click link the SSH gateway shows.
	if !strings.HasSuffix(got.VerificationURI, sentinel) {
		t.Errorf("verification_uri = %q, which does not use the advertised path", got.VerificationURI)
	}
	if !strings.Contains(got.VerificationURIComplete, sentinel) {
		t.Errorf("verification_uri_complete = %q, which does not use the advertised path",
			got.VerificationURIComplete)
	}
}

// registerDeviceVerifyClient registers a public client through RFC 7591
// dynamic registration and returns its id.
func registerDeviceVerifyClient(t *testing.T, srv *Server) string {
	t.Helper()
	body := `{"client_name":"device-verify-test","redirect_uris":["http://127.0.0.1/callback"],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"token_endpoint_auth_method":"none"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/mcp/oauth2/register", strings.NewReader(body))
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
