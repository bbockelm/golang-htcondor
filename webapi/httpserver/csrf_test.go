package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// csrfServer is a started server, because the check lives in ServeHTTP
// and a handler called directly never reaches it.
func csrfServer(t *testing.T) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.Logger = testLogger(t)
	cfg.HTTPBaseURL = "https://ap.example.edu"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()
	return s
}

func csrfPost(t *testing.T, s *Server, path, origin, authz string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path,
		strings.NewReader("{}"))
	req.Host = "ap.example.edu"
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w.Code
}

// A page on another site must not be able to change anything here.
//
// This is the server's CSRF defence and it did not have one. Session
// cookies are SameSite=Lax, which is why cookie deployments were never
// exposed -- but SameSite governs cookies, and HTTP_API_USER_HEADER
// authenticates with a header a trusted proxy attaches to every request
// the browser makes through it, cross-site included.
func TestCrossSiteStateChangeIsRefused(t *testing.T) {
	s := csrfServer(t)
	for _, path := range []string{
		"/api/v1/jobs",
		"/mcp/oauth2/device/verify",
		"/api/v1/interactive/terminal",
	} {
		t.Run(path, func(t *testing.T) {
			if got := csrfPost(t, s, path, "https://evil.example.com", ""); got != http.StatusForbidden {
				t.Fatalf("a cross-site POST to %s was answered %d, want 403", path, got)
			}
		})
	}
}

// The site's own pages keep working, by Host and by the configured base
// URL -- a deployment behind a proxy may see either.
func TestSameSiteStateChangeIsAllowed(t *testing.T) {
	s := csrfServer(t)
	for _, origin := range []string{"https://ap.example.edu", ""} {
		name := origin
		if name == "" {
			name = "no Origin (curl, scripts, the MCP stdio client)"
		}
		t.Run(name, func(t *testing.T) {
			// Any status but 403 means it got past the check; what the
			// handler then does about an unauthenticated request is its
			// own business and not what this test is about.
			if got := csrfPost(t, s, "/api/v1/jobs", origin, ""); got == http.StatusForbidden {
				t.Fatalf("a legitimate POST with origin %q was refused as cross-site", origin)
			}
		})
	}
}

// A Bearer token exempts the request: a browser does not attach one by
// itself, so a request carrying it was built by code that already held
// the credential -- which is not the situation CSRF describes.
func TestBearerCredentialIsExemptFromTheOriginCheck(t *testing.T) {
	s := csrfServer(t)
	if got := csrfPost(t, s, "/api/v1/jobs", "https://evil.example.com", "Bearer some.token"); got == http.StatusForbidden {
		t.Fatal("a Bearer-carrying request was refused as cross-site")
	}
}

// Reads are not state changes, and a CORS preflight is by definition a
// cross-origin OPTIONS -- refusing it would refuse the request it
// precedes before the real check ever ran.
func TestSafeMethodsAreNotRefused(t *testing.T) {
	s := csrfServer(t)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), method, "/api/v1/jobs", nil)
			req.Host = "ap.example.edu"
			req.Header.Set("Origin", "https://evil.example.com")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)
			if w.Code == http.StatusForbidden {
				t.Fatalf("%s with a foreign Origin was refused as cross-site", method)
			}
		})
	}
}

// The refusal says what happened without describing the route, which an
// attacker's page cannot read anyway but a log reader can.
func TestTheRefusalDoesNotDescribeTheRoute(t *testing.T) {
	s := csrfServer(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete,
		"/api/v1/jobs/12345.0", nil)
	req.Host = "ap.example.edu"
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("a cross-site DELETE was answered %d, want 403", w.Code)
	}
	if strings.Contains(w.Body.String(), "12345") {
		t.Errorf("the refusal echoes the target back: %s", w.Body.String())
	}
}
