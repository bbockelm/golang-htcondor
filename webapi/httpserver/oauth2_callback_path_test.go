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
