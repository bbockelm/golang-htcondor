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
			"writes lands in the job's sandbox, which is deleted when the job ends.",
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

	cluster, proc, err := s.requireOwnRunningJob(ctx, jobID,
		"exec_in_job reaches into the job through its starter, which exists only while the job runs")
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

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": formatExecResult(result)},
		},
		"metadata": map[string]interface{}{
			"job_id":           result.JobID,
			"exit_code":        result.ExitCode,
			"duration_ms":      result.Duration.Milliseconds(),
			"timed_out":        result.TimedOut,
			"stdout_truncated": result.StdoutTruncated,
			"stderr_truncated": result.StderrTruncated,
		},
	}, nil
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
		Projection: []string{"ClusterId", "ProcId", "JobStatus"},
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
// whyRunning is appended to the not-running error, because the reason
// differs per tool and a caller acts on it.
func (s *Server) requireOwnRunningJob(ctx context.Context, jobID, whyRunning string) (int, int, error) {
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
	status, _ := ads[0].EvaluateAttrInt("JobStatus")
	if int(status) != runningJobStatus {
		return 0, 0, fmt.Errorf("job %s is %s, not running; %s",
			jobID, describeJobStatus(int(status)), whyRunning)
	}
	return cluster, proc, nil
}
