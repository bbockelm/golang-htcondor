package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ory/fosite"

	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
)

// newMCPScopeServer is newMCPTransportServer with a signing key, so an
// OAuth2 caller that gets past the scope check can have a credential minted
// and reach the tools.
func newMCPScopeServer(t *testing.T, useSDK bool) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.EnableMCP = true
	cfg.OAuth2Issuer = "https://api.example.org"
	cfg.HTTPBaseURL = "https://api.example.org"
	cfg.TrustDomain = testTrustDomain
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.UIDDomain = "example.org"
	cfg.MCPUseSDKTransport = useSDK
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()
	return s
}

// mintMCPAccessToken issues a real access token whose stored grant is
// exactly scopes -- nil included, which is stored as JSON null and read back
// as nil, the shape a grant whose groups refused every scope used to have.
func mintMCPAccessToken(t *testing.T, s *Server, scopes []string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := s.oauth2Provider.GetStorage().GetDB().ExecContext(ctx,
		`INSERT OR IGNORE INTO oauth2_clients (id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
		 VALUES ('mcp-scope-client', '', '[]', '["authorization_code"]', '["code"]', '[]', 1)`); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	session := DefaultOpenIDConnectSession("alice")
	ar := fosite.NewAccessRequest(session)
	ar.Client = &fosite.DefaultClient{ID: "mcp-scope-client"}
	ar.GrantedScope = fosite.Arguments(scopes)
	setStandardTokenExpiries(ctx, s.oauth2Provider.config, session)
	strategy := s.oauth2Provider.GetStrategy()
	tok, _, err := strategy.GenerateAccessToken(ctx, ar)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if err := s.oauth2Provider.GetStorage().CreateAccessTokenSession(ctx,
		strategy.AccessTokenSignature(ctx, tok), ar); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}
	return tok
}

// mcpRPC posts one JSON-RPC message to /mcp with the given bearer.
func mcpRPC(t *testing.T, s *Server, bearer, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w.Result().StatusCode, w.Body.String()
}

const (
	rpcToolsList     = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	rpcCallSubmitJob = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"submit_job","arguments":{"submit_file":"executable = /bin/true\nqueue"}}}`
	rpcCallQueryJobs = `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query_jobs","arguments":{}}}`
)

func transportName(useSDK bool) string {
	if useSDK {
		return "sdk"
	}
	return "builtin"
}

// An OAuth2 token granted no MCP scope -- nil or empty -- is refused at
// authentication on both transports, for listing and for calling. A nil
// grant used to read as "no scope model" on the SDK transport and was served
// the whole catalogue.
func TestMCPTokenWithNoMCPScopeIsRefused(t *testing.T) {
	for _, useSDK := range []bool{false, true} {
		for _, grant := range []struct {
			name   string
			scopes []string
		}{
			{"nil", nil},
			{"empty", []string{}},
			{"openid only", []string{"openid"}},
		} {
			t.Run(transportName(useSDK)+"/"+grant.name, func(t *testing.T) {
				s := newMCPScopeServer(t, useSDK)
				tok := mintMCPAccessToken(t, s, grant.scopes)
				for _, body := range []string{rpcToolsList, rpcCallSubmitJob, rpcCallQueryJobs} {
					code, resp := mcpRPC(t, s, tok, body)
					if code != http.StatusForbidden || !strings.Contains(resp, "insufficient_scope") {
						t.Errorf("%s: got %d, want 403 insufficient_scope:\n%s", body, code, resp)
					}
					if strings.Contains(resp, `"submit_job"`) || strings.Contains(resp, `"query_jobs"`) {
						t.Errorf("%s: a token with no MCP scope was shown tools:\n%s", body, resp)
					}
				}
			})
		}
	}
}

// A read-only token sees the read tools and cannot call a write tool on the
// SDK transport.
func TestSDKReadOnlyTokenCannotCallAWriteTool(t *testing.T) {
	s := newMCPScopeServer(t, true)
	tok := mintMCPAccessToken(t, s, []string{"mcp:read"})

	code, listed := mcpRPC(t, s, tok, rpcToolsList)
	if code != http.StatusOK {
		t.Fatalf("tools/list: got %d:\n%s", code, listed)
	}
	if !strings.Contains(listed, `"query_jobs"`) {
		t.Errorf("a read tool is missing from a read-only catalogue:\n%s", listed)
	}
	if strings.Contains(listed, `"submit_job"`) {
		t.Errorf("a read-only catalogue lists submit_job:\n%s", listed)
	}

	_, called := mcpRPC(t, s, tok, rpcCallSubmitJob)
	var resp struct {
		Error  *struct{ Message string } `json:"error"`
		Result *struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(called), &resp); err != nil {
		t.Fatalf("decoding %q: %v", called, err)
	}
	if resp.Error == nil || !strings.Contains(strings.ToLower(resp.Error.Message), "unknown tool") {
		t.Errorf("a read-only token's submit_job was not refused as unknown:\n%s", called)
	}
}

// A forwarded HTCondor token is unscoped and sees the whole catalogue; a
// token granted nothing sees nothing. Whichever arrives first must not decide
// what the other gets -- both orders, on one server.
func TestSDKForwardedAndEmptyGrantDoNotShareACatalogue(t *testing.T) {
	for _, emptyFirst := range []bool{true, false} {
		name := "forwarded first"
		if emptyFirst {
			name = "empty grant first"
		}
		t.Run(name, func(t *testing.T) {
			s := newMCPScopeServer(t, true)
			forwarded := forwardedHTCondorToken(t)
			empty := mintMCPAccessToken(t, s, []string{})

			checkEmpty := func() {
				code, resp := mcpRPC(t, s, empty, rpcToolsList)
				if code == http.StatusOK && strings.Contains(resp, `"query_jobs"`) {
					t.Errorf("a token granted nothing was shown the catalogue:\n%s", resp)
				}
			}
			checkForwarded := func() {
				code, resp := mcpRPC(t, s, forwarded, rpcToolsList)
				if code != http.StatusOK {
					t.Fatalf("forwarded token: got %d:\n%s", code, resp)
				}
				if !strings.Contains(resp, `"query_jobs"`) || !strings.Contains(resp, `"submit_job"`) {
					t.Errorf("a forwarded token was not shown the whole catalogue:\n%s", resp)
				}
			}
			if emptyFirst {
				checkEmpty()
				checkForwarded()
			} else {
				checkForwarded()
				checkEmpty()
			}
		})
	}
}

// The SDK filters a caller's catalogue by what it is told, so losing the
// scopes here silently hands a read-only token the write tools. Neither case
// is visible from outside -- both callers reach the same tools when the
// scopes are dropped -- so the decision is read directly.
func TestSDKIsToldWhatTheCallerWasGranted(t *testing.T) {
	req := fosite.NewAccessRequest(&fosite.DefaultSession{})
	req.GrantScope("mcp:read")

	info := sdkTokenInfoFor(req)
	if len(info.Scopes) != 1 || info.Scopes[0] != "mcp:read" {
		t.Errorf("granted scopes = %v, want [mcp:read]; a read-only token would see the write tools", info.Scopes)
	}
	if len(info.Extra) != 0 {
		t.Errorf("an OAuth2 token was marked %v; it is scoped", info.Extra)
	}

	// Granted nothing is still scoped: no mark, and no nil to mistake for
	// the unscoped case.
	none := fosite.NewAccessRequest(&fosite.DefaultSession{})
	none.GrantedScope = nil
	if info := sdkTokenInfoFor(none); len(info.Extra) != 0 || info.Scopes == nil {
		t.Errorf("a token granted nothing was told %+v; it must be scoped and empty", info)
	}

	// A forwarded HTCondor token is unscoped, which the catalogue filter
	// reads as "no constraint" -- HTCondor gates that caller.
	if got := sdkTokenInfoFor(nil); !reflect.DeepEqual(got, mcpserver.UnscopedTokenInfo()) {
		t.Errorf("a forwarded token was told %+v, want the unscoped mark", got)
	}
}
