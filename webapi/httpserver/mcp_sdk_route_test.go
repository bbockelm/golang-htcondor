package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ory/fosite"
)

// forwardedHTCondorToken mints something validateOAuth2Token classifies as a
// pool IDTOKEN to be forwarded: a JWT whose `iss` is the trust domain. The
// signature is never checked here -- the schedd is what verifies a forwarded
// token -- so an unsigned one exercises the path without a pool.
func forwardedHTCondorToken(t *testing.T, trustDomain string) string {
	t.Helper()
	part := func(v interface{}) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := part(map[string]string{"alg": "HS256", "typ": "JWT", "kid": "POOL"})
	claims := part(map[string]string{"iss": trustDomain, "sub": "alice@" + trustDomain})
	return header + "." + claims + ".c2ln"
}

func newMCPTransportServer(t *testing.T, useSDK bool) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.EnableMCP = true
	cfg.OAuth2Issuer = "https://api.example.org"
	cfg.HTTPBaseURL = "https://api.example.org"
	cfg.TrustDomain = testTrustDomain
	cfg.MCPUseSDKTransport = useSDK
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()
	return s
}

func postMCP(t *testing.T, s *Server, path, accept string) *http.Response {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w.Result()
}

// Both transports serve both paths, and neither falls through to the SPA.
// Which one is serving is an operator's choice; that it is reachable is not.
func TestMCPRoutedOnEitherTransport(t *testing.T) {
	for _, useSDK := range []bool{false, true} {
		name := "builtin"
		if useSDK {
			name = "sdk"
		}
		t.Run(name, func(t *testing.T) {
			s := newMCPTransportServer(t, useSDK)
			for _, path := range []string{"/mcp", "/mcp/message"} {
				resp := postMCP(t, s, path, "application/json, text/event-stream")
				if resp.StatusCode == http.StatusNotFound {
					t.Errorf("%s is not routed on the %s transport", path, name)
				}
				if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
					t.Errorf("%s fell through to the SPA on the %s transport", path, name)
				}
			}
		})
	}
}

// An unauthenticated caller is refused before reaching any tool, on either
// transport. The SDK path authenticates in its own middleware rather than
// inheriting the built-in handler's check, so this is the assertion that the
// wiring did not lose it.
func TestMCPUnauthenticatedRefusedOnEitherTransport(t *testing.T) {
	for _, useSDK := range []bool{false, true} {
		name := "builtin"
		if useSDK {
			name = "sdk"
		}
		t.Run(name, func(t *testing.T) {
			s := newMCPTransportServer(t, useSDK)
			resp := postMCP(t, s, "/mcp", "application/json, text/event-stream")
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("an unauthenticated caller got %d on the %s transport, want 401",
					resp.StatusCode, name)
			}
		})
	}
}

// The SDK transport requires an Accept naming both media types and answers
// 400 without it, where the built-in one does not care.
//
// This is the compatibility break in the move, and the reason the transport
// is a knob rather than a swap: a spec-compliant client sends the header, a
// hand-written curl usually does not. Asserted rather than left to be found
// by a client, so the failure has a name.
func TestSDKTransportRequiresTheSpecAcceptHeader(t *testing.T) {
	sdk := newMCPTransportServer(t, true)
	builtin := newMCPTransportServer(t, false)

	// Authentication comes first on both, so use a header that gets past
	// neither -- what differs is WHICH refusal arrives.
	if got := postMCP(t, builtin, "/mcp", "application/json").StatusCode; got == http.StatusBadRequest {
		t.Errorf("the built-in transport rejected a plain Accept with 400; it should not care")
	}
	resp := postMCP(t, sdk, "/mcp", "application/json")
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
		t.Errorf("SDK transport answered %d for a plain Accept; expected a refusal", resp.StatusCode)
	}
}

// postMCPAuthed sends an authenticated tools/list, which is the only way to
// see past the identical 401 both transports give an anonymous caller.
func postMCPAuthed(t *testing.T, s *Server, accept string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+forwardedHTCondorToken(t, testTrustDomain))
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w.Result().StatusCode, w.Body.String()
}

// TestAuthenticatedCallerIsServedOnEitherTransport: a forwarded HTCondor
// token has no expiry this server knows, and the SDK's bearer middleware
// rejects a token whose expiration is missing unless told not to. So this
// caller -- a CLI user with condor_token_fetch output -- is exactly who a
// careless port stops serving, while every OAuth2 client keeps working.
func TestAuthenticatedCallerIsServedOnEitherTransport(t *testing.T) {
	const spec = "application/json, text/event-stream"
	for _, useSDK := range []bool{false, true} {
		name := "builtin"
		if useSDK {
			name = "sdk"
		}
		t.Run(name, func(t *testing.T) {
			code, body := postMCPAuthed(t, newMCPTransportServer(t, useSDK), spec)
			if code != http.StatusOK {
				t.Fatalf("a forwarded HTCondor token got %d on the %s transport:\n%s", code, name, body)
			}
			if !strings.Contains(body, "query_jobs") {
				t.Errorf("the %s transport did not list the tools:\n%s", name, body)
			}
		})
	}
}

// TestSDKTransportIsTheOneServing: with a valid token, the two transports
// disagree about a request missing the spec Accept header -- the SDK refuses
// it, the built-in one does not care. That disagreement is the only thing
// that proves which one the knob selected, and it is also the compatibility
// break worth pinning: a hand-written client that posts a bare body works
// today and stops working under the SDK.
func TestSDKTransportIsTheOneServing(t *testing.T) {
	builtinCode, _ := postMCPAuthed(t, newMCPTransportServer(t, false), "application/json")
	if builtinCode != http.StatusOK {
		t.Errorf("the built-in transport refused a plain Accept with %d; it should not care", builtinCode)
	}

	sdkCode, body := postMCPAuthed(t, newMCPTransportServer(t, true), "application/json")
	if sdkCode != http.StatusBadRequest {
		t.Errorf("the SDK transport answered %d for a plain Accept, want 400; "+
			"either the knob did not select it or it stopped being strict:\n%s", sdkCode, body)
	}
}

// The SDK filters a caller's catalogue by the scopes it is handed, so losing
// them here silently hands a read-only token the write tools. Neither case is
// visible from outside -- both callers reach the same tools when the scopes
// are dropped -- so the decision is read directly.
func TestSDKIsToldWhatTheCallerWasGranted(t *testing.T) {
	req := fosite.NewAccessRequest(&fosite.DefaultSession{})
	req.GrantScope("mcp:read")

	info := sdkTokenInfoFor(req)
	if len(info.Scopes) != 1 || info.Scopes[0] != "mcp:read" {
		t.Errorf("granted scopes = %v, want [mcp:read]; a read-only token would see the write tools", info.Scopes)
	}

	// A forwarded HTCondor token carries no scopes, which the catalogue
	// filter reads as "no constraint" -- HTCondor gates that caller.
	if info := sdkTokenInfoFor(nil); len(info.Scopes) != 0 {
		t.Errorf("a forwarded token was given scopes %v", info.Scopes)
	}
}
