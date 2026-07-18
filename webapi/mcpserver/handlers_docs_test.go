package mcpserver

import (
	"context"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/condordocs"
)

func newDocTestServer(t *testing.T) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	return &Server{
		schedd:          htcondor.NewSchedd("test_schedd", "localhost:9618"),
		logger:          logger,
		validatedTokens: make(map[string]TokenInfo),
	}
}

// TestToolCondorDocSearch_NotEmbedded verifies the tool reports a clear
// error when the binary was built without -tags embed_condor_docs. We
// rely on the IsEmbedded sentinel so the test is meaningful in either
// build configuration: it skips when docs are present.
func TestToolCondorDocSearch_NotEmbedded(t *testing.T) {
	if condordocs.IsEmbedded() {
		t.Skip("docs are embedded; this path only fires when they aren't")
	}
	s := newDocTestServer(t)
	_, err := s.toolCondorDocSearch(context.Background(), "condor_doc_job_attributes", map[string]interface{}{
		"query": "ClusterId",
	})
	if err == nil {
		t.Fatal("expected error when docs are not embedded")
	}
	if !strings.Contains(err.Error(), "not embedded") {
		t.Errorf("expected error to mention 'not embedded', got: %v", err)
	}
}

func TestToolCondorDocSearch_RequiresQuery(t *testing.T) {
	s := newDocTestServer(t)
	_, err := s.toolCondorDocSearch(context.Background(), "condor_doc_search", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing query")
	}
}

// TestCondorDocTools_Listed verifies condorDocTools() emits exactly the
// five tool names referenced from the read-only allowlist in
// httpserver/mcp_handlers.go. If you add or rename a tool here, update
// that allowlist or every read-scope OAuth client will be silently
// blocked from calling it.
func TestCondorDocTools_Listed(t *testing.T) {
	got := map[string]bool{}
	for _, tool := range condorDocTools() {
		got[tool.Name] = true
	}
	want := []string{
		"condor_doc_job_attributes",
		"condor_doc_machine_attributes",
		"condor_doc_submit_syntax",
		"condor_doc_config_variables",
		"condor_doc_search",
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("missing tool %q in condorDocTools()", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("expected %d tools, got %d (%v)", len(want), len(got), got)
	}
}

func TestIntArg(t *testing.T) {
	if v := intArg(map[string]interface{}{"k": 5.0}, "k", 99); v != 5 {
		t.Errorf("float64: got %d", v)
	}
	if v := intArg(map[string]interface{}{"k": 7}, "k", 99); v != 7 {
		t.Errorf("int: got %d", v)
	}
	if v := intArg(map[string]interface{}{}, "k", 42); v != 42 {
		t.Errorf("missing: got %d", v)
	}
	if v := intArg(map[string]interface{}{"k": "nope"}, "k", 42); v != 42 {
		t.Errorf("non-numeric: got %d", v)
	}
}

func TestRenderDocHits_Header(t *testing.T) {
	hits := []condordocs.Snippet{{
		Page:        condordocs.PageJobAttributes,
		Source:      "job-attributes.rst",
		Line:        10,
		Snippet:     "JobStatus\n  Integer state.",
		MatchedLine: "JobStatus",
	}}
	out := renderDocHits("JobStatus", hits)
	if !strings.Contains(out, "page=job_attributes") {
		t.Errorf("expected page tag in header, got: %q", out)
	}
	if !strings.Contains(out, "line=10") {
		t.Errorf("expected line number in header, got: %q", out)
	}
}
