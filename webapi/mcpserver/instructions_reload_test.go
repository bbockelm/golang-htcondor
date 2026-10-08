package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// initializeInstructions runs one initialize exchange against the server and
// returns the instructions it handed back.
func initializeInstructions(t *testing.T, s *Server) string {
	t.Helper()
	s.stdin = bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}` + "\n")
	out := &bytes.Buffer{}
	s.stdout = out

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("server error: %v", err)
		}
	case <-ctx.Done():
	}

	var resp struct {
		Result struct {
			Instructions string `json:"instructions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v\nresponse: %s", err, out.String())
	}
	return resp.Result.Instructions
}

// TestSetInstructionsChangesInitializeResponse is the end of the MCP_INSTRUCTIONS
// reconfigure path: a running server, told new instructions the way a SIGHUP
// tells it, hands the new text to the next agent that connects. Without this,
// the daemon-side wiring could be exercised entirely by its own test double and
// still not change anything a client sees.
func TestSetInstructionsChangesInitializeResponse(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	s := &Server{schedd: htcondor.NewSchedd("test_schedd", "localhost:9618"), logger: logger}

	s.SetInstructions("submit to the physics accounting group")
	before := initializeInstructions(t, s)
	if !strings.Contains(before, "submit to the physics accounting group") {
		t.Fatalf("initial instructions missing the configured text: %q", before)
	}

	// The reconfigure.
	s.SetInstructions("submit to the astronomy accounting group")
	after := initializeInstructions(t, s)
	if !strings.Contains(after, "submit to the astronomy accounting group") {
		t.Errorf("instructions did not pick up the new text: %q", after)
	}
	if strings.Contains(after, "physics") {
		t.Errorf("instructions still carry the replaced text: %q", after)
	}
	// The generic guidance is rebuilt around the new text, not dropped.
	if !strings.Contains(after, "## Submitting") {
		t.Errorf("instructions lost the generic HTCondor guidance: %q", after)
	}
}

// TestSiteInstructionsPrecedeGenericGuidance pins the order of the initialize
// text. Clients may pass only its beginning to the model (Claude Code keeps
// about 2 KB), so the operator's notes and the site skills have to come before
// the generic guidance, which follows them.
func TestSiteInstructionsPrecedeGenericGuidance(t *testing.T) {
	const note = "Store a scitokens credential before submitting."
	text := buildInstructions("ap.example.org", note, "## Site skills\n\n- `gpus` -- GPUs\n")

	generic := strings.Index(text, "## Submitting")
	if generic < 0 {
		t.Fatalf("generic guidance missing: %q", text)
	}
	for _, want := range []string{note, "## Site skills"} {
		i := strings.Index(text, want)
		switch {
		case i < 0:
			t.Errorf("%q missing from the instructions", want)
		case i > generic:
			t.Errorf("%q is at byte %d, after the generic guidance at byte %d", want, i, generic)
		}
	}
	if i := strings.Index(text, note); i > 2048 {
		t.Errorf("deployment notes start at byte %d, past what a truncating client keeps", i)
	}
}
