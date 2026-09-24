package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
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
	// "Running" is not enough: a DAGMan manager is running and still
	// has no starter to reach into.
	if !strings.Contains(desc, "scheduler- or grid-universe") {
		t.Error("the description does not rule out the universes with no starter")
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

	_, _, err := s.requireOwnRunningJob(context.Background(), "1.0", execJobNeeds)
	if err == nil {
		t.Fatal("expected the dead schedd to fail the query")
	}
	if strings.Contains(err.Error(), "authentication required") {
		t.Errorf("a stdio caller was refused instead of acting as the local user: %v", err)
	}

	// Behind HTTP the same empty context must still be refused.
	s.delegated = true
	_, _, err = s.requireOwnRunningJob(context.Background(), "1.0", execJobNeeds)
	if err == nil || !strings.Contains(err.Error(), "authentication required") {
		t.Errorf("a delegated server served an unidentifiable caller: %v", err)
	}
}

// liveJobAd builds the ad the schedd would return for one job, with the
// two attributes the live-job tools decide on.
func liveJobAd(t *testing.T, universe, status int) *classad.ClassAd {
	t.Helper()
	ad := classad.New()
	ad.InsertAttr("ClusterId", 12)
	ad.InsertAttr("ProcId", 0)
	// A negative universe stands for an ad that carries none at all.
	if universe >= 0 {
		ad.InsertAttr("JobUniverse", int64(universe))
	}
	ad.InsertAttr("JobStatus", int64(status))
	return ad
}

// A running DAGMan manager passed the running check and then failed in
// the schedd with a bare "does not support remote access": the schedd's
// GET_JOB_CONNECT_INFO switch refuses scheduler universe outright. The
// refusal has to arrive here instead, naming what does work.
func TestLiveJobToolsRefuseSchedulerUniverse(t *testing.T) {
	ad := liveJobAd(t, htcondor.UniverseScheduler, runningJobStatus)

	err := checkLiveJobAd(ad, "12.0", tailJobNeeds)
	if err == nil {
		t.Fatal("tail accepted a scheduler-universe job; the schedd will refuse it with no explanation")
	}
	msg := err.Error()
	for _, want := range []string{"12.0", "JobUniverse=7", "no live stream to tail", "get_job_output", "do not poll"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the tail refusal does not mention %q: %s", want, msg)
		}
	}

	err = checkLiveJobAd(ad, "12.0", execJobNeeds)
	if err == nil {
		t.Fatal("exec accepted a scheduler-universe job")
	}
	msg = err.Error()
	for _, want := range []string{"12.0", "JobUniverse=7", "no way to run a command"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the exec refusal does not mention %q: %s", want, msg)
		}
	}
	// Nothing can exec into one, so the message must not send the caller
	// back for another try with a different tool that also cannot.
	if strings.Contains(msg, "tail_job_output") {
		t.Errorf("the exec refusal suggests a tool that is equally refused: %s", msg)
	}
}

// Grid universe is the schedd's other refusal in the same switch, and
// neither tool has a fallback to offer: the job runs on somebody else's
// batch system.
func TestLiveJobToolsRefuseGridUniverse(t *testing.T) {
	ad := liveJobAd(t, htcondor.UniverseGrid, runningJobStatus)
	for name, needs := range map[string]liveJobNeeds{"tail": tailJobNeeds, "exec": execJobNeeds} {
		t.Run(name, func(t *testing.T) {
			err := checkLiveJobAd(ad, "12.0", needs)
			if err == nil {
				t.Fatal("a grid-universe job was accepted")
			}
			want := "job 12.0 is a grid-universe job (JobUniverse=9): it runs on a remote batch " +
				"system and HTCondor has no starter to reach into."
			if err.Error() != want {
				t.Errorf("error = %q, want %q", err.Error(), want)
			}
		})
	}
}

// Local universe runs on the access point, but under a starter, and the
// schedd's switch serves it. Refusing it here would take away the one
// case that looks like scheduler universe and is not.
func TestLiveJobToolsAllowLocalAndVanillaUniverse(t *testing.T) {
	for name, universe := range map[string]int{
		"local":   htcondor.UniverseLocal,
		"vanilla": htcondor.UniverseVanilla,
		"absent":  -1,
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkLiveJobAd(liveJobAd(t, universe, runningJobStatus), "12.0", tailJobNeeds); err != nil {
				t.Errorf("a running %s job was refused: %v", name, err)
			}
			if err := checkLiveJobAd(liveJobAd(t, universe, runningJobStatus), "12.0", execJobNeeds); err != nil {
				t.Errorf("a running %s job was refused for exec: %v", name, err)
			}
			// Unchanged behaviour for the state that was always
			// refused, with the per-tool reason still attached.
			err := checkLiveJobAd(liveJobAd(t, universe, 5), "12.0", tailJobNeeds)
			if err == nil || !strings.Contains(err.Error(), "is held, not running") {
				t.Errorf("a held %s job: err = %v, want the not-running refusal", name, err)
			}
			if err != nil && !strings.Contains(err.Error(), "get_job_stdout") {
				t.Errorf("the not-running refusal lost its per-tool advice: %v", err)
			}
		})
	}
}

// The universe check has to come before the running check: a scheduler
// job that is idle is still a scheduler job, and "not running" would
// invite a caller to wait for a starter that will never exist.
func TestSchedulerUniverseRefusedBeforeRunningCheck(t *testing.T) {
	err := checkLiveJobAd(liveJobAd(t, htcondor.UniverseScheduler, 1), "12.0", tailJobNeeds)
	if err == nil {
		t.Fatal("an idle scheduler-universe job was accepted")
	}
	if strings.Contains(err.Error(), "not running") {
		t.Errorf("refused as not-running rather than as unreachable: %v", err)
	}
}

// The universe cannot be checked if it was never asked for: the
// projection is what the schedd sends back, and dropping the attribute
// would silently restore the old behaviour.
func TestLiveJobQueryProjectsJobUniverse(t *testing.T) {
	s := newExecTestServer(t)
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@example.com")
	_, opts, err := s.liveJobQuery(ctx, 1, 0)
	if err != nil {
		t.Fatalf("liveJobQuery: %v", err)
	}
	var found bool
	for _, attr := range opts.Projection {
		if attr == "JobUniverse" {
			found = true
		}
	}
	if !found {
		t.Errorf("JobUniverse is not projected, so the universe check reads 0 for every job: %v", opts.Projection)
	}
}
