package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

func newTailTestServer(t *testing.T) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	// An address that goes nowhere: every case below is decided before
	// any schedd round trip, so a connection error means the check under
	// test did not happen.
	return &Server{schedd: htcondor.NewSchedd("nowhere", "127.0.0.1:1"), logger: logger}
}

func TestTailToolIsListedAndDispatchable(t *testing.T) {
	s := newTailTestServer(t)
	ctx := context.Background()

	body, err := json.Marshal(s.handleListTools(ctx, nil))
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, tool := range parsed.Tools {
		if tool.Name != "tail_job_output" {
			continue
		}
		found = true
		// The distinction from get_job_stdout is the whole point; a
		// model that does not know it will reach for the wrong one.
		if !strings.Contains(tool.Description, "get_job_stdout") {
			t.Error("the description does not say what to use for a finished job")
		}
		if !strings.Contains(strings.ToLower(tool.Description), "running") {
			t.Error("the description does not say the job has to be running")
		}
	}
	if !found {
		t.Fatal("tail_job_output is not in tools/list")
	}

	params, err := json.Marshal(map[string]interface{}{
		"name":      "tail_job_output",
		"arguments": map[string]interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.handleCallTool(ctx, params); err == nil {
		t.Error("a call with no job_id succeeded")
	} else if strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("listed but not dispatched: %v", err)
	}
}

// Reading output is a read: a read-scoped token should have it.
func TestTailIsClassifiedReadOnly(t *testing.T) {
	if !IsReadOnlyTool("tail_job_output") {
		t.Error("tail_job_output is not classified read-only")
	}
}

func TestTailArgumentValidation(t *testing.T) {
	s := newTailTestServer(t)
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@example.com")

	tests := map[string]struct {
		args map[string]interface{}
		want string
	}{
		"missing job id": {map[string]interface{}{}, "job_id is required"},
		"bad job id":     {map[string]interface{}{"job_id": "not-a-job"}, "invalid job_id"},
		"bad stream":     {map[string]interface{}{"job_id": "1.0", "stream": "sideways"}, "stream must be"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := s.toolTailJobOutput(ctx, tt.args)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// Who a caller is depends on the transport: behind HTTP the server acts
// for somebody else, over stdio it acts as the user running it.
func TestTailRequiresAuthentication(t *testing.T) {
	// Behind HTTP every call is on somebody's behalf, so a caller the
	// transport could not identify has to be refused.
	s := newTailTestServer(t)
	s.delegated = true
	_, err := s.toolTailJobOutput(context.Background(), map[string]interface{}{"job_id": "1.0"})
	if err == nil {
		t.Fatal("an unidentifiable caller was served")
	}
	if !strings.Contains(err.Error(), "authentication required") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// Over stdio the server IS the user, and this test previously
	// asserted the opposite: that the same empty context is refused.
	// That made the tool unusable from a shell while still advertising
	// it, which is the bug the session tools had already fixed.
	s = newTailTestServer(t)
	_, err = s.toolTailJobOutput(context.Background(), map[string]interface{}{"job_id": "1.0"})
	if err != nil && strings.Contains(err.Error(), "authentication required") {
		t.Errorf("a stdio caller was refused instead of acting as the local user: %v", err)
	}
}
