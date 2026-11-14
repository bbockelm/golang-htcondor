package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// setupPageHandler is a Handler that can render the page and nothing
// else. The page reads only the public base URL and the site name.
func setupPageHandler(t *testing.T, baseURL string) *Handler {
	t.Helper()
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return &Handler{logger: lg, httpBaseURL: baseURL}
}

// browserHelpOver wraps a protocol handler that records whether it was
// reached, which is what distinguishes "the page was served" from "the
// request went through to MCP".
func browserHelpOver(t *testing.T, h *Handler, reached *bool) http.Handler {
	t.Helper()
	return h.withMCPBrowserHelp(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
	}))
}

// browserRequest is a GET of /mcp with the headers a browser sends when
// someone follows a link to it.
func browserRequest(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, mcpPath, nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	return r
}

// TestABrowserGetsInstructionsInsteadOfTheJSONError is the report: a link
// to /mcp was sent to a new user, who opened it and got
// {"error":"invalid_token","message":"Invalid or missing token"}.
func TestABrowserGetsInstructionsInsteadOfTheJSONError(t *testing.T) {
	reached := false
	rec := httptest.NewRecorder()
	browserHelpOver(t, setupPageHandler(t, "https://ap.example.org"), &reached).
		ServeHTTP(rec, browserRequest(t))

	if reached {
		t.Fatal("the browser navigation reached the MCP protocol endpoint")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://ap.example.org/mcp") {
		t.Error("the page does not name the endpoint to connect to")
	}
	if strings.Contains(body, "invalid_token") {
		t.Error("the page still carries the JSON error")
	}
}

// TestTheStreamGETIsNotIntercepted is the thing this must not break. In
// streamable HTTP the server's side of the stream is opened by a GET of
// the same path, so the page cannot simply answer every GET.
func TestTheStreamGETIsNotIntercepted(t *testing.T) {
	reached := false
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, mcpPath, nil)
	r.Header.Set("Accept", "text/event-stream")

	rec := httptest.NewRecorder()
	browserHelpOver(t, setupPageHandler(t, ""), &reached).ServeHTTP(rec, r)

	if !reached {
		t.Fatal("an MCP stream GET was answered with the setup page")
	}
}

// TestAnMCPClientIsNotIntercepted covers the rest of the ways a request
// says it came from a client rather than a person. Each of these is a
// header a browser navigation cannot carry, and each is checked with an
// Accept header that would otherwise have served the page.
func TestAnMCPClientIsNotIntercepted(t *testing.T) {
	for _, tc := range []struct{ name, header, value string }{
		{"a bearer token", "Authorization", "Bearer abc123"},
		{"an established session", "Mcp-Session-Id", "01HZ0000000000000000000000"},
		{"a negotiated protocol version", "MCP-Protocol-Version", "2025-06-18"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := browserRequest(t)
			r.Header.Set(tc.header, tc.value)

			reached := false
			rec := httptest.NewRecorder()
			browserHelpOver(t, setupPageHandler(t, ""), &reached).ServeHTTP(rec, r)

			if !reached {
				t.Fatalf("a request carrying %s was answered with the setup page", tc.header)
			}
		})
	}
}

// TestAPostIsNotIntercepted keeps the protocol's own method clear of this
// whatever headers it arrives with.
func TestAPostIsNotIntercepted(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, mcpPath,
		strings.NewReader(`{"jsonrpc":"2.0","method":"initialize","id":1}`))
	r.Header.Set("Accept", "text/html")

	reached := false
	rec := httptest.NewRecorder()
	browserHelpOver(t, setupPageHandler(t, ""), &reached).ServeHTTP(rec, r)

	if !reached {
		t.Fatal("a POST was answered with the setup page")
	}
}

// TestAScriptStillGetsTheJSONError keeps curl and anything else that
// sends Accept: */* on the answer it gets today. Someone probing this
// endpoint from a shell wants the error, not a page about Cursor, and
// something parsing the response would break on HTML.
func TestAScriptStillGetsTheJSONError(t *testing.T) {
	for _, accept := range []string{"*/*", "", "application/json"} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, mcpPath, nil)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}

		reached := false
		rec := httptest.NewRecorder()
		browserHelpOver(t, setupPageHandler(t, ""), &reached).ServeHTTP(rec, r)

		if !reached {
			t.Errorf("Accept: %q was answered with the setup page", accept)
		}
	}
}

// TestSecFetchDestAloneIsEnough: a browser that sent an Accept header
// this does not recognise still said what the request was for.
func TestSecFetchDestAloneIsEnough(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, mcpPath, nil)
	r.Header.Set("Accept", "application/signed-exchange;v=b3")
	r.Header.Set("Sec-Fetch-Dest", "document")

	reached := false
	rec := httptest.NewRecorder()
	browserHelpOver(t, setupPageHandler(t, ""), &reached).ServeHTTP(rec, r)

	if reached {
		t.Fatal("a top-level navigation reached the MCP protocol endpoint")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestTheSetupPathNeedsNoBrowserHeaders: the page has a URL of its own so
// it can be sent to someone directly, and that URL answers whoever asks.
func TestTheSetupPathNeedsNoBrowserHeaders(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, mcpSetupPath, nil)

	rec := httptest.NewRecorder()
	setupPageHandler(t, "https://ap.example.org").handleMCPSetupPage(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "https://ap.example.org/mcp") {
		t.Error("the page does not name the endpoint to connect to")
	}
}

// TestThePageNamesEveryHarnessItSetsOutToCover. The page exists to be
// read by someone who has to configure one specific client, so a section
// quietly dropped from the markup makes it useless to exactly the person
// who needed it.
func TestThePageNamesEveryHarnessItSetsOutToCover(t *testing.T) {
	rec := httptest.NewRecorder()
	setupPageHandler(t, "https://ap.example.org").writeMCPSetupPage(rec, browserRequest(t))
	body := rec.Body.String()

	for _, want := range []string{
		"claude mcp add --transport http htcondor https://ap.example.org/mcp",
		"Add custom connector",
		"MCP: Add Server",
		"~/.cursor/mcp.json",
		"codex mcp add htcondor --url https://ap.example.org/mcp",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not contain %q", want)
		}
	}
}

// TestThePagePrefersTheConfiguredURLOverTheRequestHost. A reverse proxy
// in front of this server means the Host a request arrives at can be an
// internal name; HTTP_API_BASE_URL is what the operator published, and an
// instruction page naming anything else sends people to an address that
// does not resolve.
func TestThePagePrefersTheConfiguredURLOverTheRequestHost(t *testing.T) {
	r := browserRequest(t)
	r.Host = "htcondor-api-6f9c86677f-sg8cj:8080"

	rec := httptest.NewRecorder()
	setupPageHandler(t, "https://ap2001-api.example.org").writeMCPSetupPage(rec, r)

	body := rec.Body.String()
	if !strings.Contains(body, "https://ap2001-api.example.org/mcp") {
		t.Error("the page does not name the configured public URL")
	}
	if strings.Contains(body, "htcondor-api-6f9c86677f-sg8cj") {
		t.Error("the page names the internal host the request arrived at")
	}
}

// TestThePageEscapesTheHostItWasReachedAt. With no configured base URL
// the endpoint shown is built from the request's own Host and forwarding
// headers, which the caller controls. The page is same-origin with the
// whole web UI, so markup reaching it unescaped would run there.
func TestThePageEscapesTheHostItWasReachedAt(t *testing.T) {
	r := browserRequest(t)
	r.Header.Set("X-Forwarded-Host", `evil.example"><script>alert(1)</script>`)

	rec := httptest.NewRecorder()
	setupPageHandler(t, "").writeMCPSetupPage(rec, r)

	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("the page reflected the forwarded host as live markup")
	}
}

// TestTheMCPListenerAdmitsTheEndpointItself. mcpSurfaceOnly fronts the
// listener an operator gives MCP with HTTP_API_MCP_LISTEN_ADDR, and it
// admitted /mcp/ and everything under it -- but not /mcp, which has no
// trailing slash and is the address every client is configured with. On
// such a server the endpoint answered only at the older /mcp/message.
func TestTheMCPListenerAdmitsTheEndpointItself(t *testing.T) {
	for _, path := range []string{mcpPath, mcpMessagePath, mcpSetupPath} {
		if !isMCPSurfacePath(path) {
			t.Errorf("isMCPSurfacePath(%q) = false, want true", path)
		}
	}
	if isMCPSurfacePath("/api/v1/jobs") {
		t.Error("isMCPSurfacePath admitted the REST API")
	}
}

// TestTheRealRoutesServeThePage goes through setupRoutes and ServeHTTP
// rather than calling the wrapper directly, because everything above
// would keep passing if /mcp were registered without it. This is the
// path the reported request actually took.
func TestTheRealRoutesServeThePage(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.EnableMCP = true
	cfg.HTTPBaseURL = "https://ap.example.org"
	cfg.OAuth2ClientID = "test-client"
	cfg.OAuth2ClientSecret = "test-secret" //nolint:gosec // G101: test credentials
	cfg.OAuth2AuthURL = "https://idp.example.com/authorize"
	cfg.OAuth2TokenURL = "https://idp.example.com/token"
	cfg.OAuth2RedirectURL = "https://ap.example.org/mcp/oauth2/callback"

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()

	for _, path := range []string{mcpPath, mcpSetupPath} {
		r := browserRequest(t)
		r.URL.Path = path
		r.RequestURI = path

		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, r)

		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status = %d, want %d", path, rec.Code, http.StatusOK)
			continue
		}
		if !strings.Contains(rec.Body.String(), "https://ap.example.org/mcp") {
			t.Errorf("GET %s: the page does not name the endpoint to connect to", path)
		}
	}
}

// TestAStreamRequestWinsOverAnHTMLAccept pins the text/event-stream
// check, which this is the only request shape to exercise: a client
// asking for both the stream and HTML. Nothing was observed sending
// that, and every client seen in practice is already turned away by
// not asking for HTML at all -- which is why TestTheStreamGETIsNotIntercepted
// passes with the check removed. The check is here so a client with a
// broad Accept header gets a protocol response rather than a page, and
// without this test nothing would notice it going away.
func TestAStreamRequestWinsOverAnHTMLAccept(t *testing.T) {
	r := browserRequest(t)
	r.Header.Set("Accept", "text/html,text/event-stream")

	reached := false
	rec := httptest.NewRecorder()
	browserHelpOver(t, setupPageHandler(t, ""), &reached).ServeHTTP(rec, r)

	if !reached {
		t.Fatal("a request asking for the stream was answered with the setup page")
	}
}

// TestATrailingSlashReachesTheEndpoint. /mcp/ is not /mcp, and only /mcp
// is registered, so a trailing slash fell through to a JSON 404 -- for a
// person who typed the address that way, and for a client configured with
// it, which then did not work at all. The redirect has to keep the method
// so that the protocol's own POST survives it, and it has to leave a
// wrong path under /mcp/ reported wrong.
func TestATrailingSlashReachesTheEndpoint(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.EnableMCP = true
	cfg.OAuth2ClientID = "test-client"
	cfg.OAuth2ClientSecret = "test-secret" //nolint:gosec // G101: test credentials
	cfg.OAuth2AuthURL = "https://idp.example.com/authorize"
	cfg.OAuth2TokenURL = "https://idp.example.com/token"
	cfg.OAuth2RedirectURL = "https://ap.example.org/mcp/oauth2/callback"

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()

	get := func(method, path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, r)
		return rec
	}

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec := get(method, mcpPath+"/")
		if rec.Code != http.StatusPermanentRedirect {
			t.Errorf("%s /mcp/: status = %d, want %d", method, rec.Code, http.StatusPermanentRedirect)
		}
		if loc := rec.Header().Get("Location"); loc != mcpPath {
			t.Errorf("%s /mcp/: Location = %q, want %q", method, loc, mcpPath)
		}
	}

	// A path under /mcp/ that no endpoint claims is still wrong, and the
	// redirect must not have swallowed the whole prefix.
	if rec := get(http.MethodGet, mcpPath+"/not-an-endpoint"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /mcp/not-an-endpoint: status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	// And the endpoints that were already there still answer. 401 rather
	// than 404 is the point: the route resolved.
	if rec := get(http.MethodGet, "/mcp/oauth2/authorize"); rec.Code == http.StatusNotFound {
		t.Error("GET /mcp/oauth2/authorize: the trailing-slash pattern shadowed the OAuth2 endpoints")
	}
}
