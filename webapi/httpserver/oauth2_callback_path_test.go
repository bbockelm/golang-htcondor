package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/webui"
)

// TestAdvertisedCallbackMatchesTheSurface: an MCP-only server keeps the
// MCP-scoped callback, and a server that also serves the web UI uses the plain
// one, so a person logging in to the UI is not bounced through a URL naming a
// protocol they are not using.
//
// Which branch runs depends on the embed_frontend build tag, so this asserts
// against IsEmbedded rather than picking one: the untagged build covers the
// MCP-only case and `-tags embed_frontend` covers the other.
func TestAdvertisedCallbackMatchesTheSurface(t *testing.T) {
	got := OAuth2CallbackPath()
	want := mcpCallbackPath
	if webui.IsEmbedded() {
		want = webUICallbackPath
	}
	if got != want {
		t.Errorf("OAuth2CallbackPath() = %q, want %q (web UI embedded: %v)", got, want, webui.IsEmbedded())
	}
	t.Logf("web UI embedded: %v; advertised callback: %s", webui.IsEmbedded(), got)
}

// TestBothCallbackPathsAreServed is the invariant that keeps an upgrade from
// stranding a login: whichever path this build advertises, an authorization
// started against the other one still lands somewhere. A redirect URI lives in
// the identity provider's registration and in in-flight state, neither of which
// changes when the binary does.
func TestBothCallbackPathsAreServed(t *testing.T) {
	s := newMCPPathServer(t)

	for _, path := range []string{mcpCallbackPath, webUICallbackPath} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)

			// The callback rejects a request with no state/code, which is
			// what these send. What matters is that it was ROUTED: an
			// unregistered path falls through to the SPA or the welcome
			// page, which answer 200 with HTML.
			if rec.Code == http.StatusOK {
				t.Errorf("%s was not routed to the callback handler (got 200; likely the catch-all)", path)
			}
			if rec.Code == http.StatusNotFound {
				t.Errorf("%s is not served at all", path)
			}
			t.Logf("%s -> %d", path, rec.Code)
		})
	}
}

// TestAdvertisedCallbackIsServed ties the two together: whatever is advertised
// must be one of the paths actually routed.
func TestAdvertisedCallbackIsServed(t *testing.T) {
	advertised := OAuth2CallbackPath()
	if advertised != mcpCallbackPath && advertised != webUICallbackPath {
		t.Fatalf("advertised callback %q is neither of the served paths", advertised)
	}
}

// Every OAuth2 endpoint has to answer on both prefixes.
//
// The /mcp/ one is what every client registered before this change
// discovered, and a dynamically registered client may hold it for as
// long as its registration lasts. The plain one is what is advertised
// now. Withdrawing either strands somebody.
func TestEveryOAuth2EndpointIsServedOnBothPaths(t *testing.T) {
	s := newMCPPathServer(t)

	for _, name := range oauth2EndpointNames {
		for _, path := range []string{
			oauth2EndpointPathFor(false, name),
			oauth2EndpointPathFor(true, name),
		} {
			t.Run(path, func(t *testing.T) {
				req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
				rec := httptest.NewRecorder()
				s.ServeHTTP(rec, req)

				// These reject a bare GET in various ways. What matters
				// is that it was ROUTED: an unregistered path falls
				// through to the SPA or the welcome page, which answer
				// 200 with HTML -- which is how /oauth2/authorize
				// looked like it worked while being served by the
				// front end.
				if rec.Code == http.StatusOK {
					t.Errorf("%s was not routed to an OAuth2 handler (got 200; likely the catch-all)", path)
				}
				if rec.Code == http.StatusNotFound {
					t.Errorf("%s is not served at all", path)
				}
			})
		}
	}
}

// The choice itself, both branches. A test calling the exported wrapper
// exercises only the one this build happens to be, and passes against a
// function that ignores the flag entirely -- which is how the device
// verify path was caught by mutation.
func TestOAuth2EndpointPathFollowsTheSurface(t *testing.T) {
	if got, want := oauth2EndpointPathFor(true, "authorize"), "/oauth2/authorize"; got != want {
		t.Errorf("with the web UI embedded: %q, want %q", got, want)
	}
	if got, want := oauth2EndpointPathFor(false, "authorize"), "/mcp/oauth2/authorize"; got != want {
		t.Errorf("without it: %q, want %q", got, want)
	}
	// A nested name keeps its shape under both.
	if got, want := oauth2EndpointPathFor(true, "device/authorize"), "/oauth2/device/authorize"; got != want {
		t.Errorf("nested name: %q, want %q", got, want)
	}
}

// Whatever is advertised has to be one of the paths actually routed.
func TestAdvertisedOAuth2EndpointsAreServed(t *testing.T) {
	for _, name := range oauth2EndpointNames {
		advertised := OAuth2EndpointPath(name)
		if advertised != oauth2EndpointPathFor(true, name) && advertised != oauth2EndpointPathFor(false, name) {
			t.Errorf("advertised %q for %q is neither served path", advertised, name)
		}
	}
}
