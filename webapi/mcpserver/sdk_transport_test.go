package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func sdkTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(Config{ScheddName: "test", ScheddAddr: "127.0.0.1:9618"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// verifierFor makes every request present the given scopes.
func verifierFor(scopes []string) auth.TokenVerifier {
	return func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		return &auth.TokenInfo{Scopes: scopes, Expiration: time.Now().Add(time.Hour)}, nil
	}
}

func sdkPost(t *testing.T, ts *httptest.Server, payload map[string]interface{}) (int, string) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", ts.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

// TestSDKCatalogueIsTheCallGate: the catalogue a caller sees and the calls it
// may make have been two allowlists whose own comment warns they can drift.
// Registering only the permitted tools on that caller's server makes them one
// fact: a tool this caller may not see does not exist to answer.
func TestSDKCatalogueIsTheCallGate(t *testing.T) {
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

			_, listed := sdkPost(t, ts, map[string]interface{}{
				"jsonrpc": "2.0", "id": 1, "method": "tools/list",
			})
			if strings.Contains(listed, `"submit_job"`) != tc.wantWrite {
				t.Errorf("submit_job listed=%v, want %v", !tc.wantWrite, tc.wantWrite)
			}
			if !strings.Contains(listed, `"query_jobs"`) {
				t.Error("a read tool is missing from the catalogue")
			}

			// The call gate must agree with the catalogue.
			_, called := sdkPost(t, ts, map[string]interface{}{
				"jsonrpc": "2.0", "id": 2, "method": "tools/call",
				"params": map[string]interface{}{
					"name":      "submit_job",
					"arguments": map[string]interface{}{"submit_file": "executable = /bin/true\nqueue"},
				},
			})
			refused := strings.Contains(called, "Unknown tool") || strings.Contains(called, "unknown tool")
			if refused == tc.wantWrite {
				t.Errorf("submit_job refused=%v but listed=%v; the catalogue and the gate disagree:\n%s",
					refused, tc.wantWrite, called)
			}
		})
	}
}

// TestSDKToolFailureIsAResultNotAProtocolError: a tool that ran and failed
// must come back as a result carrying isError. A client renders a JSON-RPC
// error as an opaque failure, so returning one hides the diagnosis from the
// model exactly when it needs it -- and returning err for everything is the
// obvious way to write this adapter.
func TestSDKToolFailureIsAResultNotAProtocolError(t *testing.T) {
	s := sdkTestServer(t)
	ts := httptest.NewServer(s.SDKHTTPHandler(verifierFor([]string{"mcp:read", "mcp:write"})))
	defer ts.Close()

	// A real tool, reaching a schedd that is not there.
	_, body := sdkPost(t, ts, map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{"name": "query_jobs", "arguments": map[string]interface{}{}},
	})

	var envelope struct {
		Error  *struct{} `json:"error"`
		Result *struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("unmarshal %q: %v", body, err)
	}
	if envelope.Error != nil {
		t.Fatalf("a failing tool came back as a protocol error; the model never sees why:\n%s", body)
	}
	if envelope.Result == nil || !envelope.Result.IsError {
		t.Fatalf("a failing tool did not come back as an error result:\n%s", body)
	}
	if len(envelope.Result.Content) == 0 || envelope.Result.Content[0].Text == "" {
		t.Errorf("the error result carries no diagnosis:\n%s", body)
	}
}

// TestSDKCancelsWhenTheClientGoesAway: the SDK detaches a tool's context from
// the request's, so a client that crashes or loses its network stops being
// able to stop the work it started. The built-in transport cancels in about
// 0.1s. Left alone an abandoned exec_in_job holds an interactive slot for its
// whole timeout.
func TestSDKCancelsWhenTheClientGoesAway(t *testing.T) {
	var cancelled atomic.Bool
	ran := make(chan time.Duration, 1)

	srv := mcp.NewServer(sdkImplementation, nil)
	srv.AddTool(&mcp.Tool{Name: "slow", Description: "s", InputSchema: map[string]interface{}{"type": "object"}},
		func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ctx, stop := withClientGoneCancel(ctx)
			defer stop()
			start := time.Now()
			select {
			case <-ctx.Done():
				cancelled.Store(true)
			case <-time.After(4 * time.Second):
			}
			ran <- time.Since(start)
			return &mcp.CallToolResult{}, nil
		})

	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	ts := httptest.NewServer(sdkHTTPMiddleware(h))
	defer ts.Close()

	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{"name": "slow", "arguments": map[string]interface{}{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, abandon := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		abandon()
	}()
	req, err := http.NewRequestWithContext(ctx, "POST", ts.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	_, _ = http.DefaultClient.Do(req)

	select {
	case took := <-ran:
		if !cancelled.Load() {
			t.Errorf("the tool ran on for %s after its client vanished", took.Round(10*time.Millisecond))
		}
		if took > 2*time.Second {
			t.Errorf("cancellation took %s", took.Round(10*time.Millisecond))
		}
	case <-time.After(6 * time.Second):
		t.Fatal("the tool never returned")
	}
}

// A reconfigure changes the instructions every other surface serves. The SDK
// transport caches a server per scope set with that text baked in, so without
// invalidation this is the one surface that keeps serving the old text.
func TestSDKServersAreRebuiltAfterAReconfigure(t *testing.T) {
	s := sdkTestServer(t)
	cache := newScopedServers(s.sdkServerFor, s.catalogGen.Load)

	first := cache.get([]string{"mcp:read"})
	if again := cache.get([]string{"mcp:read"}); again != first {
		t.Error("an unchanged catalogue rebuilt its server; the cache is doing nothing")
	}

	s.SetInstructions("site policy: ask an administrator first")
	if after := cache.get([]string{"mcp:read"}); after == first {
		t.Fatal("the cached server survived a reconfigure, so it still serves the old instructions")
	}
}

// The instructions an initialize returns must be the operator's current text.
func TestSDKServesCurrentInstructions(t *testing.T) {
	s := sdkTestServer(t)
	s.SetInstructions("MARKER-ONE")
	ts := httptest.NewServer(s.SDKHTTPHandler(verifierFor([]string{"mcp:read"})))
	defer ts.Close()

	initialize := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "t", "version": "0"},
		},
	}
	if _, body := sdkPost(t, ts, initialize); !strings.Contains(body, "MARKER-ONE") {
		t.Fatalf("initialize did not carry the operator's instructions:\n%s", body)
	}

	s.SetInstructions("MARKER-TWO")
	_, body := sdkPost(t, ts, initialize)
	if strings.Contains(body, "MARKER-ONE") || !strings.Contains(body, "MARKER-TWO") {
		t.Errorf("initialize served stale instructions after a reconfigure:\n%s", body)
	}
}
