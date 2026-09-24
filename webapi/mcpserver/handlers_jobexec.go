// Running a command inside a job that is already running.
//
// The interactive-session tools own their job: they submit it, lease it,
// heartbeat it and stop it. This one owns nothing. It reaches into a job
// somebody already submitted -- the caller's own batch job, mid-run --
// which is what condor_ssh_to_job is for, and what the REST surface
// exposes as a terminal over /api/v1/jobs/{id}/ssh.

package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
)

// runningJobStatus is the only state either live-job tool can work in:
// both reach the job through its starter, and the starter exists only
// while the job runs.
const runningJobStatus = 2

// describeJobStatus renders a JobStatus for an error a caller acts on.
func describeJobStatus(status int) string {
	switch status {
	case 1:
		return "idle"
	case 2:
		return "running"
	case 3:
		return "removed"
	case 4:
		return "completed"
	case 5:
		return "held"
	case 6:
		return "transferring output"
	case 7:
		return "suspended"
	default:
		return fmt.Sprintf("in state %d", status)
	}
}

func execInJobTool() Tool {
	return Tool{
		Name: "exec_in_job",
		Description: "Run one shell command inside a RUNNING job, on the execute machine, and return its exit code, " +
			"stdout and stderr. This is condor_ssh_to_job: use it to look at a job that is already running -- what its " +
			"working directory holds, whether the input it expected arrived, why it is using no CPU.\n" +
			"Each call opens and closes its own connection to the execute node, which takes about a second. For several " +
			"commands on the same machine, start an interactive session instead (interactive_session_start): a session " +
			"keeps one connection open and its sandbox persists between calls.\n" +
			"Each call is a FRESH shell: the working directory is the job's own, and environment changes do not carry " +
			"over. Chain dependent steps in one command with '&&'. The command runs as the job's user, and anything it " +
			"writes lands in the job's sandbox, which is deleted when the job ends.\n" +
			"Not for scheduler- or grid-universe jobs, which have no starter.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"job_id": map[string]interface{}{
					"type":        "string",
					"description": "Job ID in format 'cluster.proc' (e.g. '123.0'). The job must be running.",
				},
				"command": map[string]interface{}{
					"type":        "string",
					"description": "Shell command to run, interpreted by /bin/sh inside the job's sandbox.",
				},
				"timeout_seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Kill the command after this long (default 300, max 1800). On timeout you still get the output produced so far.",
				},
			},
			"required": []string{"job_id", "command"},
		},
	}
}

func (s *Server) toolExecInJob(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	mgr, err := s.interactiveManager()
	if err != nil {
		return nil, err
	}
	jobID, _ := args["job_id"].(string)
	command, _ := args["command"].(string)
	if strings.TrimSpace(command) == "" {
		return nil, fmt.Errorf("command is required")
	}

	cluster, proc, err := s.requireOwnRunningJob(ctx, jobID, execJobNeeds)
	if err != nil {
		return nil, err
	}

	result, err := mgr.RunInJob(ctx, cluster, proc, interactive.ExecRequest{
		Command: command,
		Timeout: time.Duration(intArg(args, "timeout_seconds", 0)) * time.Second,
	})
	if err != nil {
		return nil, err
	}

	structured := map[string]interface{}{
		"job_id":           result.JobID,
		"stdout":           result.Stdout,
		"stderr":           result.Stderr,
		"exit_code":        result.ExitCode,
		"duration_ms":      result.Duration.Milliseconds(),
		"timed_out":        result.TimedOut,
		"stdout_truncated": result.StdoutTruncated,
		"stderr_truncated": result.StderrTruncated,
	}
	return withStructured(map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": formatExecResult(result)},
		},
		"metadata": structured,
	}, structured), nil
}

// liveJobQuery builds the owner-confined lookup for one job.
//
// It derives the caller the way the session tools do, not the way the
// query tools do, and that difference is the point:
//
// scopeToOwner and selfScopedQueryOptions exempt MCP admins, which is
// right for reading job ads and wrong here. Reaching into a running job
// is a shell in somebody's process, and the session tools already
// decided an admin does not get one by being an admin ("troubleshooting"
// is not a reason). Routing the live-job tools through the query-tool
// scoping quietly handed them the exemption the session tools had
// refused -- and unlike the REST superuser path, nothing here audits it.
//
// It also answers the transport question: over stdio there is no actor
// on the context because the server IS the user, and refusing there
// would list these tools and then fail every call.
func (s *Server) liveJobQuery(ctx context.Context, cluster, proc int) (string, *htcondor.QueryOptions, error) {
	caller, err := s.liveJobCaller(ctx)
	if err != nil {
		return "", nil, err
	}
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d && Owner == %s",
		cluster, proc, classadStringLit(caller.Owner))
	return constraint, &htcondor.QueryOptions{
		Projection: []string{"ClusterId", "ProcId", "JobStatus", "JobUniverse"},
		Limit:      1,
		FetchOpts:  htcondor.FetchMyJobs,
		Owner:      caller.Owner,
	}, nil
}

// requireOwnRunningJob resolves a job id to (cluster, proc) after
// checking that it is the caller's and that it is running.
//
// Both of the tools that reach into a live job need this, and both need
// it for the same two reasons. The schedd enforces ownership on its own
// -- it refuses GET_JOB_CONNECT_INFO for somebody else's job -- but
// asking here first means another user's job id comes back "not found"
// instead of a refusal that has already confirmed the job exists. And
// the running check turns "the starter could not be reached" into a
// sentence that says what to do instead.
//
// needs carries the per-tool wording, because the reason a job is out
// of reach differs per tool and a caller acts on the difference.
func (s *Server) requireOwnRunningJob(ctx context.Context, jobID string, needs liveJobNeeds) (int, int, error) {
	if strings.TrimSpace(jobID) == "" {
		return 0, 0, fmt.Errorf("job_id is required")
	}
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid job_id: %w", err)
	}

	constraint, opts, err := s.liveJobQuery(ctx, cluster, proc)
	if err != nil {
		return 0, 0, err
	}
	ads, _, err := s.getSchedd().QueryWithOptions(ctx, constraint, opts)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to query job: %w", err)
	}
	if len(ads) == 0 {
		return 0, 0, fmt.Errorf("job not found: %s", jobID)
	}
	if err := checkLiveJobAd(ads[0], jobID, needs); err != nil {
		return 0, 0, err
	}
	return cluster, proc, nil
}

// liveJobNeeds is what one live-job tool needs of the job it was
// pointed at, in words the caller can act on. Both fields are per-tool:
// tail and exec are out of luck for the same reasons but have different
// things to suggest instead.
type liveJobNeeds struct {
	// whyRunning is appended to the not-running error.
	whyRunning string
	// schedulerUniverse is the whole refusal for a scheduler-universe
	// job: a format string with one %s for the job id.
	schedulerUniverse string
}

// execJobNeeds is exec_in_job's wording. There is no fallback to
// suggest for a scheduler-universe job -- nothing can run a command
// inside one -- so the message says that rather than implying a retry.
var execJobNeeds = liveJobNeeds{
	whyRunning: "exec_in_job reaches into the job through its starter, which exists only while the job runs",
	schedulerUniverse: "job %s is a scheduler-universe job (JobUniverse=7); condor_ssh_to_job needs a starter " +
		"and there is none. There is no way to run a command inside it. Its files are readable with " +
		"get_job_output while it runs.",
}

// gridUniverseRefusal is shared by both tools: a grid job runs on
// somebody else's batch system, so neither has anything to offer.
const gridUniverseRefusal = "job %s is a grid-universe job (JobUniverse=9): it runs on a remote batch " +
	"system and HTCondor has no starter to reach into."

// jobUniverseHasStarter reports whether a job of this universe runs
// under a starter the schedd will broker a connection to.
//
// Both live-job tools go through GET_JOB_CONNECT_INFO, and its universe
// switch (src/condor_schedd.V6/schedd.cpp,
// Scheduler::get_job_connect_info) decides this: scheduler universe (7)
// and grid universe (9) are refused with a bare "does not support
// remote access", while local universe (12), vanilla/docker/java/vm and
// parallel/mpi are served. Local universe runs on the access point but
// still under a starter, so it must NOT be refused here. An ad with no
// JobUniverse reads as 0 and is left alone: the schedd is the authority
// and will say so itself.
func jobUniverseHasStarter(universe int) bool {
	switch universe {
	case htcondor.UniverseScheduler, htcondor.UniverseGrid:
		return false
	default:
		return true
	}
}

// checkLiveJobAd decides whether the job the schedd just described can
// be reached through its starter at all.
//
// The universe check comes first, and that ordering is the fix: a
// running DAGMan manager passes the running check and then fails inside
// the schedd with "does not support remote access", which tells a
// caller neither why nor what to do instead.
func checkLiveJobAd(ad *classad.ClassAd, jobID string, needs liveJobNeeds) error {
	universe, _ := ad.EvaluateAttrInt("JobUniverse")
	if !jobUniverseHasStarter(int(universe)) {
		if int(universe) == htcondor.UniverseGrid {
			// ST1005 wants an error fragment; these are whole
			// sentences on purpose, because a model reads them.
			return fmt.Errorf(gridUniverseRefusal, jobID) //nolint:staticcheck
		}
		return fmt.Errorf(needs.schedulerUniverse, jobID)
	}
	status, _ := ad.EvaluateAttrInt("JobStatus")
	if int(status) != runningJobStatus {
		return fmt.Errorf("job %s is %s, not running; %s",
			jobID, describeJobStatus(int(status)), needs.whyRunning)
	}
	return nil
}
