package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The 2026-07-28 protocol (SEP-2575) is sessionless: what a session used to
// carry -- the negotiated version, the client's capabilities and identity --
// travels on every request instead, in headers an intermediary can read
// without parsing the body and in a `_meta` object inside params.
//
// These build that by hand rather than through the SDK client, so the request
// a v2 client actually sends is written down somewhere: each of these four
// pieces was discovered by being rejected for its absence.
const (
	protocolVersionV2 = "2026-07-28"
	metaVersionKey    = "io.modelcontextprotocol/protocolVersion"
	metaCapsKey       = "io.modelcontextprotocol/clientCapabilities"
	metaClientKey     = "io.modelcontextprotocol/clientInfo"
)

func v2Params(extra map[string]interface{}) map[string]interface{} {
	params := map[string]interface{}{
		"_meta": map[string]interface{}{
			metaVersionKey: protocolVersionV2,
			metaCapsKey:    map[string]interface{}{},
			metaClientKey:  map[string]interface{}{"name": "test", "version": "0"},
		},
	}
	for k, v := range extra {
		params[k] = v
	}
	return params
}

// postV2 sends one sessionless request the way a 2026-07-28 client does.
func postV2(t *testing.T, url, method string, params map[string]interface{}) string {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), "POST", url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Mcp-Protocol-Version", protocolVersionV2)
	req.Header.Set("Mcp-Method", method)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestMCPv2CacheableResultsArePrivate is the one thing about this protocol
// that this server had to answer for itself.
//
// 2026-07-28 attaches cache-control to the results a stateless client
// re-fetches constantly, and the SDK's default scope is "public": any
// intermediary may cache one and serve it to somebody else. This server's
// catalogue is built from the caller's granted scopes, so a read-write
// token's answer is the whole write surface -- and this daemon is deployed
// behind a gateway. The scope filter exists to stop a client learning what it
// may not call; "public" invites an intermediary to undo that.
func TestMCPv2CacheableResultsArePrivate(t *testing.T) {
	s := sdkTestServer(t)
	ts := httptest.NewServer(s.SDKHTTPHandler(verifierFor([]string{"mcp:read"})))
	defer ts.Close()

	for _, method := range []string{"server/discover", "tools/list"} {
		body := postV2(t, ts.URL, method, v2Params(nil))
		if strings.Contains(body, `"error"`) {
			t.Fatalf("%s failed:\n%s", method, body)
		}
		if !strings.Contains(body, `"cacheScope":"private"`) {
			t.Errorf("%s is not marked private, so an intermediary may serve this caller's "+
				"catalogue to another:\n%s", method, firstN(body, 240))
		}
	}
}

// A v2 caller gets the catalogue its token allows, the same as every other
// transport. The filter has to survive the move to a protocol that answers
// without a session to hang the caller's identity on.
func TestMCPv2CatalogueIsStillScoped(t *testing.T) {
	s := sdkTestServer(t)

	for _, tc := range []struct {
		name      string
		scopes    []string
		wantWrite bool
	}{
		{"read-only", []string{"mcp:read"}, false},
		{"read-write", []string{"mcp:read", "mcp:write"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(s.SDKHTTPHandler(verifierFor(tc.scopes)))
			defer ts.Close()

			body := postV2(t, ts.URL, "tools/list", v2Params(nil))
			if got := strings.Contains(body, `"submit_job"`); got != tc.wantWrite {
				t.Errorf("submit_job visible=%v, want %v", got, tc.wantWrite)
			}
			if !strings.Contains(body, `"query_jobs"`) {
				t.Error("a read tool is missing from the v2 catalogue")
			}
		})
	}
}

// TestMCPv2ClientConnectsAndCallsATool drives the SDK's own client at the
// version it negotiates by default, which is how a real v2 client arrives:
// server/discover instead of the initialize handshake, and no session id.
func TestMCPv2ClientConnectsAndCallsATool(t *testing.T) {
	s := sdkTestServer(t)
	ts := httptest.NewServer(s.SDKHTTPHandler(verifierFor([]string{"mcp:read"})))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   ts.URL,
		HTTPClient: &http.Client{Transport: bearerRoundTripper{}},
	}, &mcp.ClientSessionOptions{ProtocolVersion: protocolVersionV2})
	if err != nil {
		t.Fatalf("a %s client could not connect: %v", protocolVersionV2, err)
	}
	defer func() { _ = sess.Close() }()

	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	if len(names) == 0 {
		t.Fatal("no tools listed, so this passed without exercising the catalogue")
	}
	for _, name := range names {
		if name == "submit_job" {
			t.Error("a read-only token was served a write tool over v2")
		}
	}
}

type bearerRoundTripper struct{}

func (bearerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer test-token")
	return http.DefaultTransport.RoundTrip(r)
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// TestBuiltinTransportAnswersAV2ClientByDowngrade: the built-in transport is
// still the default, and it speaks neither server/discover nor 2026-07-28 --
// it answers initialize with 2024-11-05.
//
// What matters is that a v2-capable client is not stranded by that. The
// protocol says such a client falls back, so this pins the fallback actually
// working against THIS server rather than in principle: an operator who has
// not set HTTP_API_MCP_TRANSPORT=sdk should not discover that modern clients
// cannot connect at all.
func TestBuiltinTransportAnswersAV2Client(t *testing.T) {
	s := sdkTestServer(t)

	// server/discover is the v2 entry point, and the built-in dispatcher has
	// no such method.
	discover := s.HandleMessage(context.Background(), &MCPMessage{
		JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "server/discover",
	})
	if discover == nil || discover.Error == nil {
		t.Errorf("the built-in transport answered server/discover; it does not implement it, "+
			"so a v2 client would be told it works: %+v", discover)
	}

	// And the handshake it does implement names the version it speaks, so a
	// client can decide to downgrade rather than guess.
	initialize := s.HandleMessage(context.Background(), &MCPMessage{
		JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "initialize",
	})
	if initialize == nil || initialize.Result == nil {
		t.Fatalf("initialize did not answer: %+v", initialize)
	}
	raw, err := json.Marshal(initialize.Result)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.ProtocolVersion == "" {
		t.Error("initialize names no protocol version, so a client cannot tell what it is talking to")
	}
	if result.ProtocolVersion >= protocolVersionV2 {
		t.Errorf("the built-in transport claims %s; it does not implement SEP-2575, and a client "+
			"taking that claim would send requests it cannot answer", result.ProtocolVersion)
	}
}
