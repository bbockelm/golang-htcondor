package mcpserver

import (
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// TestEveryMCPRequestIsLogged: without this the only record of an MCP call is
// the HTTP line, which says "POST /mcp status=200" and nothing about what was
// asked. The built-in transport logged the method before dispatch; that line
// lives in the HTTP handler the SDK transport does not call.
//
// Found by needing it: a 34-second call on a live deployment could not be
// identified from its logs, and whether any tool had run at all could not be
// answered.
func TestEveryMCPRequestIsLogged(t *testing.T) {
	buf := logging.NewBuffer(200, slog.LevelDebug)
	logger, err := logging.New(&logging.Config{
		OutputPath:        "stderr",
		DestinationLevels: map[logging.Destination]logging.Verbosity{logging.DestinationMCP: logging.VerbosityDebug},
	})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	logging.AttachBuffer(logger, buf)
	s, err := NewServer(Config{ScheddName: "test", ScheddAddr: "127.0.0.1:9618", Logger: logger})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(s.SDKHTTPHandler(verifierFor([]string{"mcp:read"})))
	defer ts.Close()

	// Two different methods, so the log has to distinguish them rather than
	// record that something happened.
	sdkPost(t, ts, map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	sdkPost(t, ts, map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{"name": "query_jobs", "arguments": map[string]interface{}{}},
	})

	var logged []string
	for _, entry := range buf.Entries(200) {
		if entry.Message != "MCP request" {
			continue
		}
		parts := []string{entry.Destination}
		for k, v := range entry.Fields {
			parts = append(parts, k+"="+v)
		}
		logged = append(logged, strings.Join(parts, " "))
	}
	if len(logged) < 2 {
		t.Fatalf("expected a line per request, got %d:\n%s", len(logged), strings.Join(logged, "\n"))
	}
	all := strings.Join(logged, "\n")
	for _, want := range []string{"tools/list", "tools/call", "duration_ms"} {
		if !strings.Contains(all, want) {
			t.Errorf("the log does not record %q, so a request cannot be told apart from another:\n%s", want, all)
		}
	}
}
