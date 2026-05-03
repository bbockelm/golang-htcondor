// Interactive batch jobs: vanilla-universe shells the user attaches to via
// the existing /api/v1/jobs/{id}/ssh WebSocket. The lifetime of the job is
// gated by a heartbeat file in its scratch dir; the SSH bridge multiplexes
// a side-channel session over the user's already-connected ssh.Client to
// `touch .heartbeat` whenever the user has typed recently. If the file
// goes stale the watchdog inside the job exits and the slot is released.
//
// Why this design:
//   - HTCondor's `condor_submit -i` produces a similar shape (sleep job +
//     condor_ssh_to_job). Using a WATCHDOG instead of `sleep $LARGE` means
//     a user closing the browser tab and forgetting about the job doesn't
//     squat a slot for hours. The webapp's heartbeat injection is the
//     liveness signal.
//   - We deliberately avoid spawning fresh `condor_ssh_to_job` processes
//     for the heartbeat — establishing a Cedar session is expensive.
//     Instead the SSH bridge piggybacks on the user's existing ssh.Client
//     (handlers_ssh.go) and opens a new ssh.Session per heartbeat tick;
//     SSH sessions are cheap once the transport is up.

package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing/fstest"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"golang.org/x/crypto/ssh"
)

// Prefix on JobBatchName that marks a job as an interactive terminal
// the SSH bridge should heartbeat. Public so the SPA could (later)
// filter the global jobs list by it.
const interactiveTerminalBatchPrefix = "htcondor-api-interactive-terminal-"

// Watchdog timing.
//
// The script polls every InteractiveWatchdogPollSec; if .heartbeat is
// older than InteractiveWatchdogFreshnessSec it exits. The webapp side
// sends heartbeats every interactiveHeartbeatIntervalSec (handlers_ssh.go)
// when the user has typed within interactiveHeartbeatIdleWindowSec.
//
// Defaults give a ~120s eviction window once the user goes idle, with
// 30s polling on each end. Tuned for "tab forgotten" not "user thinking".
const (
	InteractiveWatchdogPollSec        = 30
	InteractiveWatchdogFreshnessSec   = 120
	interactiveHeartbeatIntervalSec   = 20
	interactiveHeartbeatIdleWindowSec = 60
)

// InteractiveCreateTerminalRequest is the optional JSON body of
// POST /api/v1/interactive/terminal. All fields are optional; the
// server fills sensible defaults.
type InteractiveCreateTerminalRequest struct {
	Cpus     int `json:"cpus,omitempty"`
	MemoryMB int `json:"memory_mb,omitempty"`
	DiskMB   int `json:"disk_mb,omitempty"`
}

func (req *InteractiveCreateTerminalRequest) applyDefaults() {
	if req.Cpus == 0 {
		req.Cpus = 1
	}
	if req.MemoryMB == 0 {
		req.MemoryMB = 1024
	}
	if req.DiskMB == 0 {
		req.DiskMB = 1024
	}
}

func (req *InteractiveCreateTerminalRequest) validate() error {
	if req.Cpus < 1 || req.Cpus > 64 {
		return fmt.Errorf("cpus must be between 1 and 64, got %d", req.Cpus)
	}
	if req.MemoryMB < 256 || req.MemoryMB > 256*1024 {
		return fmt.Errorf("memory_mb must be between 256 and %d, got %d", 256*1024, req.MemoryMB)
	}
	if req.DiskMB < 256 || req.DiskMB > 1024*1024 {
		return fmt.Errorf("disk_mb must be between 256 and %d, got %d", 1024*1024, req.DiskMB)
	}
	return nil
}

// InteractiveCreateTerminalResponse is the JSON returned on success.
type InteractiveCreateTerminalResponse struct {
	InstanceID string `json:"instance_id"`
	ClusterID  int    `json:"cluster_id"`
	ProcID     int    `json:"proc_id"`
	JobID      string `json:"job_id"` // "cluster.proc" — convenience for the SPA
	BatchName  string `json:"batch_name"`
}

// InteractiveTerminalSummary is the SPA-facing shape of one terminal
// session. Returned by GET /api/v1/interactive/terminal.
//
// JobCurrentStartExecutingDate is the schedd's "executable actually
// started running" timestamp; combined with JobStatus the SPA's
// shared status module distinguishes "queued" from "transferring
// input" from "executing".
type InteractiveTerminalSummary struct {
	InstanceID                   string `json:"instance_id"`
	JobID                        string `json:"job_id"`
	ClusterID                    int    `json:"cluster_id"`
	ProcID                       int    `json:"proc_id"`
	BatchName                    string `json:"batch_name"`
	JobStatus                    int    `json:"job_status"`
	JobCurrentStartExecutingDate int64  `json:"job_current_start_executing_date,omitempty"`
	HoldReasonCode               int    `json:"hold_reason_code,omitempty"`
	HoldReason                   string `json:"hold_reason,omitempty"`
	SubmittedAt                  string `json:"submitted_at,omitempty"` // RFC3339 from QDate
}

// handleInteractiveTerminal dispatches /api/v1/interactive/terminal by
// HTTP method: POST creates a session, GET lists the caller's
// sessions. Switching from "one route per handler" to a small
// dispatcher avoids registering two distinct paths and keeps the
// REST shape conventional.
func (s *Handler) handleInteractiveTerminal(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleInteractiveCreateTerminal(w, r)
	case http.MethodGet:
		s.handleInteractiveListTerminals(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleInteractiveCreateTerminal handles POST /api/v1/interactive/terminal.
// Submits a vanilla-universe job whose executable is a small shell
// watchdog. The user attaches via /api/v1/jobs/{id}/ssh.
func (s *Handler) handleInteractiveCreateTerminal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	username := htcondor.GetAuthenticatedUserFromContext(ctx)
	if username == "" {
		s.writeError(w, http.StatusUnauthorized, "no authenticated user")
		return
	}

	var req InteractiveCreateTerminalRequest
	if r.Body != nil && r.ContentLength != 0 {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
			return
		}
	}
	req.applyDefaults()
	if err := req.validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	instanceID, err := generateInteractiveInstanceID()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("gen id: %v", err))
		return
	}
	batchName := interactiveTerminalBatchPrefix + instanceID

	submitFile := buildInteractiveTerminalSubmitFile(interactiveTerminalSubmitArgs{
		InstanceID: instanceID,
		BatchName:  batchName,
		Cpus:       req.Cpus,
		MemoryMB:   req.MemoryMB,
		DiskMB:     req.DiskMB,
	})

	clusterID, procAds, err := s.getSchedd().SubmitRemote(ctx, submitFile)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "interactive submit failed",
			"owner", username, "error", err)
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("schedd submit failed: %v", err))
		return
	}

	stage := fstest.MapFS{
		"interactive-watchdog.sh": &fstest.MapFile{
			Data: []byte(buildInteractiveWatchdogScript()),
			Mode: 0o755,
		},
	}
	if err := s.getSchedd().SpoolJobFilesFromFS(ctx, procAds, stage); err != nil {
		s.logger.Error(logging.DestinationHTTP, "interactive spool failed",
			"owner", username, "cluster", clusterID, "error", err)
		s.writeError(w, http.StatusBadGateway,
			fmt.Sprintf("schedd accepted the submit but spooling watchdog failed: %v", err))
		return
	}

	procID := 0
	if len(procAds) > 0 {
		if v, ok := procAds[0].EvaluateAttrInt("ProcId"); ok {
			procID = int(v)
		}
	}
	jobID := fmt.Sprintf("%d.%d", clusterID, procID)

	s.logger.Info(logging.DestinationHTTP, "interactive terminal created",
		"instance", instanceID, "owner", username, "cluster", clusterID, "proc", procID,
		"batch_name", batchName)

	s.writeJSON(w, http.StatusCreated, InteractiveCreateTerminalResponse{
		InstanceID: instanceID,
		ClusterID:  clusterID,
		ProcID:     procID,
		JobID:      jobID,
		BatchName:  batchName,
	})
}

type interactiveTerminalSubmitArgs struct {
	InstanceID string
	BatchName  string
	Cpus       int
	MemoryMB   int
	DiskMB     int
}

func buildInteractiveTerminalSubmitFile(a interactiveTerminalSubmitArgs) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Auto-generated by htcondor-api for interactive terminal %s\n", a.InstanceID)
	fmt.Fprintf(&sb, "universe = vanilla\n\n")

	fmt.Fprintf(&sb, "executable = interactive-watchdog.sh\n")
	fmt.Fprintf(&sb, "transfer_executable = true\n\n")

	fmt.Fprintf(&sb, "should_transfer_files = YES\n")
	fmt.Fprintf(&sb, "when_to_transfer_output = ON_EXIT\n\n")

	fmt.Fprintf(&sb, "request_cpus = %d\n", a.Cpus)
	fmt.Fprintf(&sb, "request_memory = %d\n", a.MemoryMB)
	fmt.Fprintf(&sb, "request_disk = %d\n\n", a.DiskMB)

	// JobBatchName lets handleJobSSH identify this as an interactive job
	// at attach time (see ssh-bridge heartbeat plumbing). The prefix is
	// also used to enumerate active terminals for the SPA.
	fmt.Fprintf(&sb, "job_batch_name = %s\n\n", a.BatchName)

	fmt.Fprintf(&sb, "log    = interactive.log\n")
	fmt.Fprintf(&sb, "output = interactive.out\n")
	fmt.Fprintf(&sb, "error  = interactive.err\n")
	fmt.Fprintf(&sb, "queue\n")
	return sb.String()
}

// buildInteractiveWatchdogScript emits the POSIX-shell watchdog that
// runs as the interactive job's executable. It primes a heartbeat
// file, then loops checking the file's age. If it goes stale the
// script kills any sshd processes the user attached through and exits
// — that combination releases the HTCondor slot.
//
// The bridge also drops a `.shutdown` file in the scratch dir when the
// SSH session ends; the watchdog notices that on its next tick and
// exits immediately, so the slot frees within POLL_INTERVAL seconds
// instead of waiting out the full FRESHNESS_WINDOW. Either trigger
// reaches the same stale_exit path.
//
// Implementation notes:
//   - We use plain /bin/sh to avoid bash-isms.
//   - `stat -c %Y` is GNU stat (Linux); `stat -f %m` is BSD stat
//     (macOS). Try both so the same script runs on either pool.
//   - Bootstrap touch happens BEFORE the loop so the user has up to
//     one full freshness window to attach + start sending heartbeats.
//   - On stale-exit we `pkill sshd` first. condor_ssh_to_job spawns
//     an sshd inside the sandbox; if we just exit while the user
//     still has the WebSocket open, the starter waits for sshd's
//     descendants and the slot stays held. Killing sshd lets the
//     starter actually wind the job down.
//   - Startup log line goes to stderr (= the job's `error` file) so
//     the operator can confirm the watchdog is running.
func buildInteractiveWatchdogScript() string {
	return fmt.Sprintf(`#!/bin/sh
# Auto-generated by htcondor-api. Keeps an interactive terminal job
# alive only while the webapp is actively heartbeating it.
HEARTBEAT_FILE=".heartbeat"
SHUTDOWN_FILE=".shutdown"
POLL_INTERVAL=%d
FRESHNESS_WINDOW=%d

echo "[interactive-watchdog] starting pid=$$ scratch=${_CONDOR_SCRATCH_DIR:-(unset)} poll=${POLL_INTERVAL}s freshness=${FRESHNESS_WINDOW}s" >&2

touch "$HEARTBEAT_FILE"

stat_mtime() {
  stat -c %%Y "$1" 2>/dev/null || stat -f %%m "$1" 2>/dev/null
}

stale_exit() {
  echo "[interactive-watchdog] $1; killing sshd and exiting" >&2
  # condor_ssh_to_job spawns an sshd inside the sandbox; killing it
  # lets the starter actually finish the job once the heartbeat goes
  # stale. Without this, an attached-but-idle browser holds the slot.
  pkill -TERM sshd 2>/dev/null || true
  sleep 1
  pkill -KILL sshd 2>/dev/null || true
  exit 0
}

while true; do
  sleep "$POLL_INTERVAL"
  if [ -f "$SHUTDOWN_FILE" ]; then
    stale_exit "shutdown file present"
  fi
  now=$(date +%%s)
  mt=$(stat_mtime "$HEARTBEAT_FILE")
  if [ -z "$mt" ]; then
    stale_exit "heartbeat file gone or stat failed"
  fi
  age=$(( now - mt ))
  if [ "$age" -gt "$FRESHNESS_WINDOW" ]; then
    stale_exit "heartbeat ${age}s old (>${FRESHNESS_WINDOW}s)"
  fi
done
`, InteractiveWatchdogPollSec, InteractiveWatchdogFreshnessSec)
}

// generateInteractiveInstanceID returns a short hex token used both as
// the user-facing instance id and as the JobBatchName suffix. 8 bytes
// (16 hex chars) is plenty given that uniqueness is only needed across
// the API server's lifetime.
func generateInteractiveInstanceID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// jobIsInteractive returns true if the proc ad's JobBatchName marks it
// as an interactive terminal we should heartbeat. The SSH bridge calls
// this on attach to decide whether to run the heartbeat goroutine.
func jobIsInteractive(ad interface {
	EvaluateAttrString(name string) (string, bool)
}) bool {
	name, ok := ad.EvaluateAttrString("JobBatchName")
	if !ok {
		return false
	}
	return strings.HasPrefix(name, interactiveTerminalBatchPrefix)
}

// handleInteractiveListTerminals handles GET /api/v1/interactive/terminal.
// Returns the caller's interactive-terminal jobs (active, held, or
// queued) by enumerating their queue and filtering in Go on the
// JobBatchName prefix.
//
// This deliberately does the filtering in Go rather than via a
// schedd-side `regexp(...)` constraint string: the regexp form
// silently matched zero rows in some pool configurations (a bug we
// hit before adding this endpoint), and a Go-side filter makes the
// behavior portable across HTCondor versions and easy to log.
func (s *Handler) handleInteractiveListTerminals(w http.ResponseWriter, r *http.Request) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	owner := htcondor.GetAuthenticatedUserFromContext(ctx)
	if owner == "" {
		s.writeError(w, http.StatusUnauthorized, "no authenticated user")
		return
	}
	bareOwner := strings.SplitN(owner, "@", 2)[0]

	opts := &htcondor.QueryOptions{
		Limit: 500,
		Projection: []string{
			"ClusterId", "ProcId", "JobStatus", "JobBatchName",
			"HoldReason", "HoldReasonCode", "QDate",
			"JobCurrentStartExecutingDate",
		},
		FetchOpts: htcondor.FetchMyJobs,
		Owner:     bareOwner,
	}
	ads, _, err := s.getSchedd().QueryWithOptions(ctx, "true", opts)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "interactive list query failed",
			"owner", owner, "error", err)
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("schedd query failed: %v", err))
		return
	}

	out := make([]InteractiveTerminalSummary, 0, len(ads))
	for _, ad := range ads {
		batchName, ok := ad.EvaluateAttrString("JobBatchName")
		if !ok || !strings.HasPrefix(batchName, interactiveTerminalBatchPrefix) {
			continue
		}
		clusterID, _ := ad.EvaluateAttrInt("ClusterId")
		procID, _ := ad.EvaluateAttrInt("ProcId")
		jobStatus, _ := ad.EvaluateAttrInt("JobStatus")
		holdCode, _ := ad.EvaluateAttrInt("HoldReasonCode")
		holdReason, _ := ad.EvaluateAttrString("HoldReason")
		qdate, _ := ad.EvaluateAttrInt("QDate")
		startExec, _ := ad.EvaluateAttrInt("JobCurrentStartExecutingDate")

		summary := InteractiveTerminalSummary{
			InstanceID:                   strings.TrimPrefix(batchName, interactiveTerminalBatchPrefix),
			JobID:                        fmt.Sprintf("%d.%d", clusterID, procID),
			ClusterID:                    int(clusterID),
			ProcID:                       int(procID),
			BatchName:                    batchName,
			JobStatus:                    int(jobStatus),
			JobCurrentStartExecutingDate: startExec,
			HoldReasonCode:               int(holdCode),
			HoldReason:                   holdReason,
		}
		if qdate > 0 {
			summary.SubmittedAt = time.Unix(qdate, 0).UTC().Format(time.RFC3339)
		}
		out = append(out, summary)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"terminals": out})
}

// startInteractiveHeartbeat runs a goroutine that, while the SSH
// bridge is up, periodically opens a fresh ssh.Session on the existing
// client and runs `touch .heartbeat` — but only when the user has
// typed within the activity window. Returns a stop function the bridge
// must defer; the goroutine also exits if ctx is canceled.
//
// We deliberately reuse the user's already-authenticated ssh.Client
// instead of spawning another condor_ssh_to_job (which would require
// a fresh Cedar handshake — expensive). SSH sessions are cheap once
// the transport is up.
//
// Heartbeat sessions never read input or output; they just dispatch a
// short command and close. Errors are logged at debug level — the
// next tick will retry, and if every tick fails the watchdog inside
// the job will eventually evict it, which is the right behavior.
func (s *Handler) startInteractiveHeartbeat(
	ctx context.Context,
	sshClient *ssh.Client,
	jobID string,
	lastKeystroke *atomic.Int64,
) func() {
	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Duration(interactiveHeartbeatIntervalSec) * time.Second)
		defer ticker.Stop()

		// Send one bootstrap heartbeat right away so the watchdog's
		// freshness window starts ticking against a recent timestamp
		// — there's a brief gap between bootstrap-touch (in the
		// watchdog script) and our first scheduled tick that could
		// otherwise let a slow-typing user fall behind.
		s.sendInteractiveHeartbeat(sshClient, jobID)

		idleWindow := time.Duration(interactiveHeartbeatIdleWindowSec) * time.Second
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-ticker.C:
				lastNanos := lastKeystroke.Load()
				if lastNanos == 0 {
					continue
				}
				if time.Since(time.Unix(0, lastNanos)) > idleWindow {
					// User idle. Skip — let the watchdog reclaim the
					// slot if this stays true long enough.
					continue
				}
				s.sendInteractiveHeartbeat(sshClient, jobID)
			}
		}
	}()
	return func() { close(stopCh) }
}

// removeJobOnDisconnect issues a condor_rm for the given cluster.proc
// after the SSH bridge tears down. Used for interactive terminal
// sessions: when the user closes the browser tab (or clicks "End
// session"), the watchdog would eventually reap the job, but users
// expect immediate slot release. Best-effort: errors are logged and
// swallowed since the bridge is already gone.
//
// Uses a fresh background context with a short timeout — the bridge's
// own ctx is being canceled when this runs.
func (s *Handler) removeJobOnDisconnect(jobIDStr string) {
	cluster, proc, err := parseJobID(jobIDStr)
	if err != nil {
		s.logger.Warn(logging.DestinationHTTP, "interactive disconnect: bad job id",
			"job_id", jobIDStr, "error", err)
		return
	}

	// Use the server's own token (if available) so this works even
	// after the user's session has expired. The schedd verifies that
	// the requester owns the job; the API server token is daemon-level
	// so it can act on any job.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if s.token != "" {
		ctx = WithToken(ctx, s.token)
	}

	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	results, err := s.getSchedd().RemoveJobs(ctx, constraint, "Interactive session ended")
	if err != nil {
		s.logger.Warn(logging.DestinationHTTP, "interactive disconnect: condor_rm failed",
			"job_id", jobIDStr, "error", err)
		return
	}
	s.logger.Info(logging.DestinationHTTP, "interactive disconnect: removed job",
		"job_id", jobIDStr, "removed", results.Success, "not_found", results.NotFound)
}

// sendInteractiveHeartbeat opens a transient ssh.Session on the live
// client, runs `touch <scratch>/.heartbeat`, and closes. Failures are
// non-fatal: the next tick retries, and the watchdog inside the job
// is the ultimate arbiter of liveness.
//
// The heartbeat command must use an absolute path to the heartbeat
// file. SSH exec sessions don't necessarily inherit the per-job cwd
// the user's shell sees — the OpenSSH server in condor_ssh_to_job
// runs `$SHELL -c <cmd>` from the user's $HOME, not from the job
// scratch dir. The starter sets _CONDOR_SCRATCH_DIR in the job's env;
// we use that as the prefix and fall back to "." just in case.
const interactiveHeartbeatCmd = `touch "${_CONDOR_SCRATCH_DIR:-.}/.heartbeat"`

// interactiveShutdownCmd drops a sentinel the watchdog polls for. Used
// on bridge teardown so the watchdog exits within POLL_INTERVAL seconds
// instead of waiting out the heartbeat-stale window — and instead of
// relying on condor_rm having already taken effect on the schedd.
const interactiveShutdownCmd = `touch "${_CONDOR_SCRATCH_DIR:-.}/.shutdown"`

func (s *Handler) sendInteractiveHeartbeat(client *ssh.Client, jobID string) {
	sess, err := client.NewSession()
	if err != nil {
		s.logger.Debug(logging.DestinationHTTP, "interactive heartbeat: NewSession failed",
			"job_id", jobID, "error", err)
		return
	}
	defer func() { _ = sess.Close() }()
	if err := sess.Run(interactiveHeartbeatCmd); err != nil {
		s.logger.Debug(logging.DestinationHTTP, "interactive heartbeat: touch failed",
			"job_id", jobID, "error", err)
	}
}

// sendInteractiveShutdownSignal opens a transient session on the still-
// open ssh.Client and drops `.shutdown` in the scratch dir. The watchdog
// inside the sandbox checks for that file on every tick and exits
// immediately when it appears — that's how a closed WebSocket actually
// frees the HTCondor slot quickly. Best-effort: an error here is logged
// at debug; condor_rm (run from removeJobOnDisconnect) is the backstop.
func (s *Handler) sendInteractiveShutdownSignal(client *ssh.Client, jobID string) {
	sess, err := client.NewSession()
	if err != nil {
		s.logger.Debug(logging.DestinationHTTP, "interactive shutdown: NewSession failed",
			"job_id", jobID, "error", err)
		return
	}
	defer func() { _ = sess.Close() }()
	if err := sess.Run(interactiveShutdownCmd); err != nil {
		s.logger.Debug(logging.DestinationHTTP, "interactive shutdown: touch failed",
			"job_id", jobID, "error", err)
	}
}

// _ = strconv ensures the import survives unrelated edits that drop
// the only call site temporarily; remove once the SSH bridge edits
// land in this same package.
var _ = strconv.Itoa
