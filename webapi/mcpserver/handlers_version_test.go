package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestGetVersionToolListed asserts the tool is advertised, takes no
// required arguments, and is classified read-only. The whole point of
// the tool is to be callable by an operator holding only a read scope
// ("is my redeploy live?"), so a regression that drops it from the
// read-only allowlist would silently make it write-only.
func TestGetVersionToolListed(t *testing.T) {
	s := &Server{}
	payload, err := json.Marshal(s.handleListTools(context.Background(), nil))
	if err != nil {
		t.Fatalf("marshal tools/list: %v", err)
	}
	var listing struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Required []string `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(payload, &listing); err != nil {
		t.Fatalf("tools/list is not the documented shape: %v", err)
	}

	var found bool
	for _, tool := range listing.Tools {
		if tool.Name == "get_version" {
			found = true
			if len(tool.InputSchema.Required) != 0 {
				t.Errorf("get_version should require no arguments, got %v", tool.InputSchema.Required)
			}
		}
	}
	if !found {
		t.Fatal("get_version is not advertised in tools/list")
	}
	if !IsReadOnlyTool("get_version") {
		t.Error("get_version is not in the read-only allowlist; a read-scope client cannot call it")
	}
}

// TestGetVersionResult checks the handler returns a readable summary and
// the exact build info as JSON. It does not assert a specific version --
// a test binary's build info is deliberately unstamped -- only that the
// structured payload is present and parseable, which is what a client
// comparing "deployed" against "expected" relies on.
func TestGetVersionResult(t *testing.T) {
	s := &Server{}
	res, err := s.toolGetVersion(context.Background(), nil)
	if err != nil {
		t.Fatalf("toolGetVersion: %v", err)
	}

	text := textOf(t, res)
	if !strings.Contains(text, "htcondor-api") {
		t.Errorf("summary missing the daemon name: %q", text)
	}

	// The JSON block is appended after the summary, which contains no
	// braces, so the first '{' begins it. It must parse and carry a
	// version field (empty is fine).
	i := strings.Index(text, "{")
	if i < 0 {
		t.Fatalf("no JSON build block in result: %q", text)
	}
	var build struct {
		Version string `json:"version"`
		Stack   struct {
			Go string `json:"go"`
		} `json:"stack"`
	}
	if err := json.Unmarshal([]byte(text[i:]), &build); err != nil {
		t.Fatalf("build JSON does not parse: %v\n%s", err, text[i:])
	}
	if build.Stack.Go == "" {
		t.Error("build info omits the Go toolchain version; it is always known at runtime")
	}
}

// textOf extracts the text of a single-text-content tool result.
func textOf(t *testing.T, res interface{}) string {
	t.Helper()
	payload, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal tool result: %v", err)
	}
	var r struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(payload, &r); err != nil {
		t.Fatalf("tool result is not the content shape: %v", err)
	}
	if len(r.Content) == 0 {
		t.Fatal("tool result has no content")
	}
	return r.Content[0].Text
}
