package httpserver

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// Over real sockets: the two ports must expose different things.
//
// The filters are unit-tested above, but a split that is wired up wrongly
// -- the filter on the wrong server, or the MCP listener never served --
// passes those and fails here.
func TestSplitPortsExposeDifferentSurfaces(t *testing.T) {
	logger := testLogger(t)

	mainLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mcpLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s, err := NewServer(Config{
		Logger:        logger,
		ScheddName:    "test-schedd",
		ScheddAddr:    "127.0.0.1:9618",
		OAuth2DBPath:  t.TempDir() + "/oauth2.db",
		EnableMCP:     true,
		MCPListenAddr: mcpLn.Addr().String(),
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})

	go func() { _ = s.ServeListenerWithCert(mainLn, "", "") }()
	// The handler is started by the primary listener; the MCP one only
	// adds a socket, so it follows.
	time.Sleep(500 * time.Millisecond)
	go func() { _ = s.ServeMCPListener(mcpLn, "", "") }()

	mainURL := "http://" + mainLn.Addr().String()
	mcpURL := "http://" + mcpLn.Addr().String()
	client := &http.Client{Timeout: 10 * time.Second}

	get := func(t *testing.T, base, path string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s%s: %v", base, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// Both ports have to be up before the comparison means anything.
	if got := get(t, mainURL, "/healthz"); got != http.StatusOK {
		t.Fatalf("the main listener is not serving: /healthz = %d", got)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if get(t, mcpURL, "/healthz") == http.StatusOK {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if got := get(t, mcpURL, "/healthz"); got != http.StatusOK {
		t.Fatalf("the MCP listener is not serving: /healthz = %d", got)
	}

	// The REST API is on the main port and not on the MCP one.
	if got := get(t, mainURL, "/api/v1/version"); got == http.StatusNotFound {
		t.Error("/api/v1/version is missing from the main listener")
	}
	if got := get(t, mcpURL, "/api/v1/version"); got != http.StatusNotFound {
		t.Errorf("/api/v1/version = %d on the MCP port, want 404; "+
			"a separate port that also serves the REST API is not a split", got)
	}

	// The protocol endpoint moved: it answers on the MCP port and not on
	// the main one. This is the property the whole feature exists for, so
	// it is asserted over the sockets and not only against the filter.
	if got := get(t, mainURL, "/mcp/message"); got != http.StatusNotFound {
		t.Errorf("/mcp/message = %d on the main port, want 404; "+
			"MCP still answering there leaves the surface as wide as before the split", got)
	}
	if got := get(t, mcpURL, "/mcp/message"); got == http.StatusNotFound {
		t.Error("/mcp/message is missing from the MCP port, so the split moved it nowhere")
	}

	// The OAuth2 endpoints are on both, so a client reaching either can
	// finish authenticating.
	for _, base := range []string{mainURL, mcpURL} {
		if got := get(t, base, "/.well-known/oauth-authorization-server"); got != http.StatusOK {
			t.Errorf("%s: authorization server metadata = %d, want 200", base, got)
		}
	}
}
