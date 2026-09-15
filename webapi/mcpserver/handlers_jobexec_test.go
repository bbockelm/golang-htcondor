package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
)

func newExecTestServer(t *testing.T) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	s := &Server{
		// Goes nowhere on purpose: every case here is decided before any
		// schedd round trip.
		schedd:    htcondor.NewSchedd("nowhere", "127.0.0.1:1"),
		logger:    logger,
		delegated: true,
	}
	mgr, err := interactive.NewManager(interactive.Options{
		Schedd: func() interactive.ScheddClient { return s.schedd },
		Logger: logger,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(mgr.Close)
	s.interactive = mgr
	return s
}

func TestExecInJobIsListedAndDispatchable(t *testing.T) {
	s := newExecTestServer(t)
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
	var desc string
	for _, tool := range parsed.Tools {
		if tool.Name == "exec_in_job" {
			desc = tool.Description
		}
	}
	if desc == "" {
		t.Fatal("exec_in_job is not in tools/list")
	}
	// The cost model is the thing a model has to know: one connection
	// per call, so repeated work belongs in a session.
	if !strings.Contains(desc, "interactive_session_start") {
		t.Error("the description does not point at sessions for repeated commands")
	}
	if !strings.Contains(strings.ToLower(desc), "running") {
		t.Error("the description does not say the job has to be running")
	}

	params, err := json.Marshal(map[string]interface{}{
		"name":      "exec_in_job",
		"arguments": map[string]interface{}{"job_id": "1.0", "command": "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.handleCallTool(ctx, params); err == nil {
		t.Error("an unauthenticated call succeeded")
	} else if strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("listed but not dispatched: %v", err)
	}
}

// Running arbitrary commands inside a job is not a read.
func TestExecInJobIsNotReadOnly(t *testing.T) {
	if IsReadOnlyTool("exec_in_job") {
		t.Error("exec_in_job is classified read-only; a read-scoped token could run commands on an execute node")
	}
}

func TestExecInJobValidation(t *testing.T) {
	s := newExecTestServer(t)
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@example.com")

	tests := map[string]struct {
		args map[string]interface{}
		want string
	}{
		"missing command": {map[string]interface{}{"job_id": "1.0"}, "command is required"},
		"empty command":   {map[string]interface{}{"job_id": "1.0", "command": "   "}, "command is required"},
		"missing job id":  {map[string]interface{}{"command": "true"}, "job_id is required"},
		"bad job id":      {map[string]interface{}{"job_id": "nope", "command": "true"}, "invalid job_id"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := s.toolExecInJob(ctx, tt.args)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestExecInJobRequiresAuthentication(t *testing.T) {
	s := newExecTestServer(t)
	_, err := s.toolExecInJob(context.Background(), map[string]interface{}{
		"job_id": "1.0", "command": "true",
	})
	if err == nil {
		t.Fatal("an unauthenticated caller was served")
	}
	if !strings.Contains(err.Error(), "authentication required") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestDescribeJobStatus(t *testing.T) {
	for status, want := range map[int]string{
		1: "idle", 2: "running", 3: "removed", 4: "completed",
		5: "held", 6: "transferring output", 7: "suspended",
	} {
		if got := describeJobStatus(status); got != want {
			t.Errorf("describeJobStatus(%d) = %q, want %q", status, got, want)
		}
	}
}
