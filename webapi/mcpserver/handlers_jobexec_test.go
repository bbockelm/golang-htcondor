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

// TestLiveJobToolsFollowScheddRediscovery: this server replaces its
// schedd when the collector reports a new address, which is why the
// Config takes a provider. A tool holding the snapshot from NewServer
// keeps dialling a socket that no longer exists after the schedd
// restarts -- the failure that comment in httpserver records having
// already fixed once.
func TestLiveJobToolsFollowScheddRediscovery(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	first := htcondor.NewSchedd("first", "127.0.0.1:1")
	current := first
	s, err := NewServer(Config{
		ScheddProvider: func() *htcondor.Schedd { return current },
		Logger:         logger,
		Delegated:      true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.Close)

	// Rediscovery: the collector reported a new address.
	second := htcondor.NewSchedd("second", "127.0.0.1:2")
	current = second

	if got := s.getSchedd(); got != second {
		t.Fatalf("getSchedd returned the stale handle")
	}
	// The session manager was handed an accessor, not a snapshot, so it
	// sees the new one too.
	if got := s.interactive.ScheddForTest(); got != interactive.ScheddClient(second) {
		t.Errorf("the interactive manager is pinned to the schedd it was built with")
	}
}

// TestLiveJobToolsRefuseAdminExemption: reaching into a running job is
// a shell in somebody's process. The session tools decided an admin does
// not get one by being an admin; routing tail and exec through the
// query-tool scoping (which does exempt admins, correctly, for reading
// job ads) quietly handed them that exemption -- unaudited, unlike the
// REST superuser path.
//
// Reads the constraint rather than watching a call fail, because an
// exempted admin and a confined one fail a dead address identically --
// which is how the first version of this test passed against the very
// behaviour it was meant to reject.
func TestLiveJobToolsRefuseAdminExemption(t *testing.T) {
	s := newExecTestServer(t)
	s.adminUsers = map[string]struct{}{"root@example.com": {}}
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "root@example.com")

	constraint, opts, err := s.liveJobQuery(ctx, 1, 0)
	if err != nil {
		t.Fatalf("liveJobQuery: %v", err)
	}
	if !strings.Contains(constraint, `Owner == "root"`) {
		t.Errorf("an admin's lookup is not owner-confined: %q", constraint)
	}
	if opts.Owner != "root" {
		t.Errorf("opts.Owner = %q, want root", opts.Owner)
	}
	if opts.FetchOpts&htcondor.FetchMyJobs == 0 {
		t.Error("the authenticated-query filter was dropped for an admin")
	}
}

// Over stdio there is no actor on the context because the server IS the
// user. Refusing there lists these tools and then fails every call --
// the bug the session tools already fixed once. Goes through
// requireOwnRunningJob, not just the caller helper: the helper existed
// before this fix too, and the bug was that this path did not use it.
func TestLiveJobToolsWorkOverStdio(t *testing.T) {
	s := newExecTestServer(t)
	s.delegated = false

	_, _, err := s.requireOwnRunningJob(context.Background(), "1.0", "because")
	if err == nil {
		t.Fatal("expected the dead schedd to fail the query")
	}
	if strings.Contains(err.Error(), "authentication required") {
		t.Errorf("a stdio caller was refused instead of acting as the local user: %v", err)
	}

	// Behind HTTP the same empty context must still be refused.
	s.delegated = true
	_, _, err = s.requireOwnRunningJob(context.Background(), "1.0", "because")
	if err == nil || !strings.Contains(err.Error(), "authentication required") {
		t.Errorf("a delegated server served an unidentifiable caller: %v", err)
	}
}
