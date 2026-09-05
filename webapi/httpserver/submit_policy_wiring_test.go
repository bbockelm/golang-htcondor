package httpserver

import (
	"os"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/submitpolicy"
)

// The policy is worth nothing if a submit surface bypasses it. This
// walks the SubmitRemote call sites and asserts each one runs its submit
// file through the policy first.
//
// A source-level check rather than a behavioural one because the
// alternative is standing up a schedd per surface; what actually goes
// wrong here is someone adding a fourth submit path and not knowing the
// policy exists, which is precisely what this catches.
func TestEverySubmitSiteAppliesThePolicy(t *testing.T) {
	files := map[string]string{
		"handlers.go":             mustRead(t, "handlers.go"),
		"handlers_interactive.go": mustRead(t, "handlers_interactive.go"),
		"handlers_jupyter.go":     mustRead(t, "handlers_jupyter.go"),
	}
	for name, src := range files {
		for _, line := range strings.Split(src, "\n") {
			if !strings.Contains(line, "SubmitRemote(") {
				continue
			}
			if strings.Contains(line, "//") {
				continue // a mention in a comment
			}
			if !strings.Contains(line, "submitPolicy.Apply(") {
				t.Errorf("%s submits without applying the site policy:\n\t%s\n"+
					"every submit path must go through submitPolicy.Apply, or a site's "+
					"requirements silently do not apply to it", name, strings.TrimSpace(line))
			}
		}
	}
}

// The handler must carry the configured policy through to the embedded
// MCP server, or agent submissions would skip site policy that every
// other surface honours.
func TestMCPServerInheritsTheSubmitPolicy(t *testing.T) {
	src := mustRead(t, "handler.go")
	if !strings.Contains(src, "SubmitPolicy:   h.submitPolicy,") {
		t.Error("the MCP server is built without the submit policy; agent submissions would bypass it")
	}
}

// An unconfigured deployment must be entirely unaffected.
func TestHandlerWithNoPolicyLeavesSubmitFilesAlone(t *testing.T) {
	h := &Handler{}
	const file = "executable = /bin/true\nlog = job.log\nqueue\n"
	if got := h.submitPolicy.Apply(file); got != file {
		t.Errorf("a handler with no configured policy changed the submit file:\n%s", got)
	}
}

// And a configured one reaches the submit file with both halves in
// character: the default yields to the user, the override does not.
func TestHandlerPolicyAppliesBothHalves(t *testing.T) {
	h := &Handler{submitPolicy: submitpolicy.Policy{
		Defaults:  "request_memory = 512",
		Overrides: "log = /home/alice/forced.log",
	}}
	got := h.submitPolicy.Apply("executable = /bin/true\nrequest_memory = 2048\nlog = /tmp/nope.log\nqueue\n")

	if !strings.Contains(got, "request_memory = 2048") {
		t.Error("the user's request_memory was lost")
	}
	if strings.Index(got, "/home/alice/forced.log") < strings.Index(got, "queue") &&
		strings.Index(got, "/home/alice/forced.log") < strings.LastIndex(got, "/tmp/nope.log") {
		t.Error("the override does not come after the user's log line, so it would not win")
	}
	if !strings.Contains(got, "/home/alice/forced.log") {
		t.Error("the override is missing")
	}
}

// mustRead loads a source file from this package's directory.
func mustRead(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // G304: a fixed source filename from this test, not user input
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}
