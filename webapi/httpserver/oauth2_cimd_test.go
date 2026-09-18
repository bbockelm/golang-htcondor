package httpserver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ory/fosite"
)

func TestIsDisallowedIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", false},              // public
		{"1.1.1.1", false},              // public
		{"2606:4700:4700::1111", false}, // public v6
		{"127.0.0.1", true},             // loopback
		{"::1", true},                   // loopback v6
		{"10.0.0.5", true},              // private
		{"172.16.3.4", true},            // private
		{"192.168.1.1", true},           // private
		{"169.254.169.254", true},       // link-local (cloud metadata)
		{"100.64.0.1", true},            // CGNAT (RFC 6598)
		{"100.127.255.255", true},       // CGNAT upper
		{"100.128.0.1", false},          // just past CGNAT -> public
		{"0.0.0.0", true},               // unspecified
		{"224.0.0.1", true},             // multicast
		{"fc00::1", true},               // v6 ULA (private)
		{"fe80::1", true},               // v6 link-local
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tc.ip)
		}
		if got := isDisallowedIP(ip); got != tc.want {
			t.Errorf("isDisallowedIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIsCIMDClientID(t *testing.T) {
	if !isCIMDClientID("https://example.org/mcp") {
		t.Error("https URL should be a CIMD id")
	}
	for _, id := range []string{"http://example.org/mcp", "client_123", "swagger-client", ""} {
		if isCIMDClientID(id) {
			t.Errorf("%q should NOT be a CIMD id", id)
		}
	}
}

func TestHostAllowed(t *testing.T) {
	r := &cimdResolver{allowedHosts: []string{"mcp.example.org", ".trusted.dev"}}
	yes := []string{"mcp.example.org", "a.trusted.dev", "trusted.dev"}
	no := []string{"evil.org", "mcp.example.org.evil.com", "nottrusted.dev"}
	for _, h := range yes {
		if !r.hostAllowed(h) {
			t.Errorf("hostAllowed(%q) = false, want true", h)
		}
	}
	for _, h := range no {
		if r.hostAllowed(h) {
			t.Errorf("hostAllowed(%q) = true, want false", h)
		}
	}
	// Empty allowlist => any host.
	open := &cimdResolver{}
	if !open.hostAllowed("anything.example") {
		t.Error("empty allowlist should permit any host")
	}
}

// cimdTestServer serves a document at /client and counts fetches.
func cimdTestServer(t *testing.T, doc func(clientURL string) any) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(nil)
	clientURL := srv.URL + "/client"
	mux.HandleFunc("/client", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc(clientURL))
	})
	srv.Config.Handler = mux
	return srv, &hits
}

func newTestResolver(srv *httptest.Server) *cimdResolver {
	// Inject the httptest client (trusts the test cert; loopback). The SSRF
	// dialer guard is exercised separately by TestIsDisallowedIP.
	return newCIMDResolver(nil, srv.Client())
}

func TestCIMDResolveHappyPath(t *testing.T) {
	srv, hits := cimdTestServer(t, func(u string) any {
		return map[string]any{
			"client_id":     u,
			"redirect_uris": []string{"https://app.example.org/cb"},
			"scope":         "openid offline_access mcp:read condor:/READ",
			"client_name":   "Test MCP Client",
		}
	})
	defer srv.Close()
	r := newTestResolver(srv)
	clientURL := srv.URL + "/client"

	c, err := r.resolve(context.Background(), clientURL)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	dc, ok := c.(*fosite.DefaultClient)
	if !ok {
		t.Fatalf("want *fosite.DefaultClient, got %T", c)
	}
	if !dc.Public {
		t.Error("CIMD client must be public")
	}
	if len(dc.Secret) != 0 {
		t.Error("CIMD client must have no secret")
	}
	if got := dc.GrantTypes; len(got) != 2 || got[0] != "authorization_code" || got[1] != "refresh_token" {
		t.Errorf("grant types = %v, want [authorization_code refresh_token]", got)
	}
	if len(dc.ResponseTypes) != 1 || dc.ResponseTypes[0] != "code" {
		t.Errorf("response types = %v, want [code]", dc.ResponseTypes)
	}
	if len(dc.RedirectURIs) != 1 || dc.RedirectURIs[0] != "https://app.example.org/cb" {
		t.Errorf("redirect uris = %v", dc.RedirectURIs)
	}
	// Declared scopes are narrowed to the advertised set (the unknown one, if any, dropped).
	want := map[string]bool{"openid": true, "offline_access": true, "mcp:read": true, "condor:/READ": true}
	for _, s := range dc.Scopes {
		if !want[s] {
			t.Errorf("unexpected scope %q", s)
		}
	}

	// A second resolve within the TTL is served from cache (no refetch).
	if _, err := r.resolve(context.Background(), clientURL); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Errorf("expected 1 fetch (cached), got %d", n)
	}
}

func TestCIMDResolveRejections(t *testing.T) {
	// client_id in the doc does not match the URL it was fetched from.
	mismatch, _ := cimdTestServer(t, func(_ string) any {
		return map[string]any{"client_id": "https://someone-else.example/", "redirect_uris": []string{"https://x/cb"}}
	})
	defer mismatch.Close()
	if _, err := newTestResolver(mismatch).resolve(context.Background(), mismatch.URL+"/client"); err == nil {
		t.Error("client_id/URL mismatch must be rejected")
	}

	// No redirect_uris.
	noredir, _ := cimdTestServer(t, func(u string) any {
		return map[string]any{"client_id": u}
	})
	defer noredir.Close()
	if _, err := newTestResolver(noredir).resolve(context.Background(), noredir.URL+"/client"); err == nil {
		t.Error("missing redirect_uris must be rejected")
	}

	// Confidential auth method (we can only be a public client for CIMD).
	conf, _ := cimdTestServer(t, func(u string) any {
		return map[string]any{"client_id": u, "redirect_uris": []string{"https://x/cb"}, "token_endpoint_auth_method": "client_secret_basic"}
	})
	defer conf.Close()
	if _, err := newTestResolver(conf).resolve(context.Background(), conf.URL+"/client"); err == nil {
		t.Error("confidential token_endpoint_auth_method must be rejected")
	}

	// Non-https client_id.
	if _, err := newCIMDResolver(nil, http.DefaultClient).resolve(context.Background(), "http://example.org/c"); err == nil {
		t.Error("non-https client_id must be rejected")
	}

	// Disallowed host (allowlist set, host not on it).
	ok, _ := cimdTestServer(t, func(u string) any {
		return map[string]any{"client_id": u, "redirect_uris": []string{"https://x/cb"}}
	})
	defer ok.Close()
	restricted := newCIMDResolver([]string{"only.example.org"}, ok.Client())
	if _, err := restricted.resolve(context.Background(), ok.URL+"/client"); err == nil {
		t.Error("host off the allowlist must be rejected")
	}
}

// claudeCodeMetadata is the document Claude Code publishes, verbatim as
// fetched on 2026-09-18. It declares loopback redirects with NO port, then
// requests one with an ephemeral port -- which is the whole of RFC 8252's
// loopback allowance, and what this exercises.
func claudeCodeMetadata(u string) any {
	return map[string]any{
		"client_id":                  u,
		"client_name":                "Claude Code",
		"client_uri":                 "https://claude.ai",
		"redirect_uris":              []string{"http://localhost/callback", "http://127.0.0.1/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
}

// The reported failure: an authorize request from Claude Code was refused
// with "The 'redirect_uri' parameter does not match any of the OAuth 2.0
// Client's pre-registered redirect urls."
//
// This asserts through fosite's OWN matcher rather than the helper, because
// fosite is what actually rejected the request: its port-independent rule
// tests net.ParseIP(host).IsLoopback(), which is false for the NAME
// "localhost", so neither declared URI could ever match.
func TestCIMDAcceptsEphemeralLoopbackPort(t *testing.T) {
	srv, _ := cimdTestServer(t, claudeCodeMetadata)
	defer srv.Close()
	r := newTestResolver(srv)
	clientURL := srv.URL + "/client"

	for _, requested := range []string{
		"http://localhost:60253/callback",
		"http://127.0.0.1:54321/callback",
	} {
		ctx := WithRequestedRedirectURI(context.Background(), requested)
		c, err := r.resolve(ctx, clientURL)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if _, err := fosite.MatchRedirectURIWithClientRedirectURIs(requested, c); err != nil {
			t.Errorf("fosite refused %s: %v", requested, err)
		}
	}
}

// The allowance must not widen anything else. The client may vary only the
// PORT of a loopback URI it already published.
func TestCIMDLoopbackAllowanceIsNarrow(t *testing.T) {
	srv, _ := cimdTestServer(t, claudeCodeMetadata)
	defer srv.Close()
	r := newTestResolver(srv)
	clientURL := srv.URL + "/client"

	for _, requested := range []string{
		"http://localhost:60253/evil",         // different path
		"http://evil.example:60253/callback",  // different host
		"https://localhost:60253/callback",    // different scheme
		"http://localhost:60253/callback?x=1", // extra query
		"http://10.0.0.5:60253/callback",      // not loopback
	} {
		ctx := WithRequestedRedirectURI(context.Background(), requested)
		c, err := r.resolve(ctx, clientURL)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if _, err := fosite.MatchRedirectURIWithClientRedirectURIs(requested, c); err == nil {
			t.Errorf("fosite ACCEPTED %s; the allowance is meant to vary the port only", requested)
		}
	}
}

// The cached client is shared by every request for this client_id. Baking
// one app's ephemeral port into it would hand that port to the next user.
func TestCIMDLoopbackAllowanceDoesNotPoisonTheCache(t *testing.T) {
	srv, _ := cimdTestServer(t, claudeCodeMetadata)
	defer srv.Close()
	r := newTestResolver(srv)
	clientURL := srv.URL + "/client"

	first := "http://localhost:1111/callback"
	if _, err := r.resolve(WithRequestedRedirectURI(context.Background(), first), clientURL); err != nil {
		t.Fatal(err)
	}

	// A later request with no redirect_uri at all must see only what the
	// document declared.
	c, err := r.resolve(context.Background(), clientURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range c.GetRedirectURIs() {
		if got == first {
			t.Fatalf("the cached client kept another request's port: %v", c.GetRedirectURIs())
		}
	}

	// And a different port must still be accepted on its own request.
	second := "http://localhost:2222/callback"
	c2, err := r.resolve(WithRequestedRedirectURI(context.Background(), second), clientURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fosite.MatchRedirectURIWithClientRedirectURIs(second, c2); err != nil {
		t.Errorf("second port refused: %v", err)
	}
}

// A client that declares a non-loopback redirect gets no allowance at all.
func TestCIMDNoAllowanceForNonLoopbackClients(t *testing.T) {
	srv, _ := cimdTestServer(t, func(u string) any {
		return map[string]any{
			"client_id":     u,
			"redirect_uris": []string{"https://app.example.org/cb"},
		}
	})
	defer srv.Close()
	r := newTestResolver(srv)

	requested := "https://app.example.org:8443/cb"
	ctx := WithRequestedRedirectURI(context.Background(), requested)
	c, err := r.resolve(ctx, srv.URL+"/client")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fosite.MatchRedirectURIWithClientRedirectURIs(requested, c); err == nil {
		t.Error("a non-loopback redirect was allowed to vary its port")
	}
}
