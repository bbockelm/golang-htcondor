// Interactive batch jobs: vanilla-universe shells the user attaches to
// via the existing /api/v1/jobs/{id}/ssh WebSocket. The job itself --
// submit file, watchdog script, heartbeat and shutdown commands -- is
// built by webapi/interactive, which the MCP session tools share; this
// file is the REST/SPA surface over it.
//
// The lifetime of the job is gated by a heartbeat file in its scratch
// dir; the SSH bridge multiplexes a side-channel session over the
// user's already-connected ssh.Client to `touch .heartbeat` while the
// browser is attached. If the file goes stale the watchdog inside the
// job exits and the slot is released.
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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing/fstest"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/submitpolicy"
	"golang.org/x/crypto/ssh"
)

// interactiveTerminalBatchPrefix is the JobBatchName prefix marking a
// job as an interactive terminal the SSH bridge should heartbeat.
const interactiveTerminalBatchPrefix = interactive.BatchPrefix

// Watchdog timing for browser terminals, and how often the bridge
// heartbeats them.
//
// The watchdog polls every InteractiveWatchdogPollSec; if .heartbeat is
// older than InteractiveWatchdogFreshnessSec it exits. The bridge sends
// a heartbeat every interactiveHeartbeatIntervalSec for as long as the
// WebSocket is open, and gives up after interactiveMaxIdleSec without
// a keystroke.
//
// That idle bound used to be 60s, which is where a bug lived: a user
// who read output or thought for two minutes with the tab open stopped
// being heartbeated and lost their shell to the watchdog. The socket
// being open is the real "someone is there" signal -- a closed tab
// closes it -- so the keystroke clock now only exists to reclaim a tab
// left open and forgotten, and is set at the scale that behaviour
// actually happens on.
const (
	InteractiveWatchdogPollSec      = interactive.DefaultTerminalWatchdogPollSec
	InteractiveWatchdogFreshnessSec = interactive.DefaultTerminalWatchdogFreshnessSec
	interactiveHeartbeatIntervalSec = 20
	interactiveMaxIdleSec           = 4 * 60 * 60
)

// InteractiveCreateTerminalRequest is the optional JSON body of
// POST /api/v1/interactive/terminal. All fields are optional; the
// server fills sensible defaults.
type InteractiveCreateTerminalRequest struct {
	Cpus     int `json:"cpus,omitempty"`
	MemoryMB int `json:"memory_mb,omitempty"`
	DiskMB   int `json:"disk_mb,omitempty"`

	// GPU fields. Mirrored verbatim into request_gpus and the
	// gpus_minimum_* / cuda_version / require_gpus submit lines.
	// Gpus == 0 disables the entire GPU section in the submit file.
	Gpus                  int    `json:"gpus,omitempty"`
	GpusMinimumCapability string `json:"gpus_minimum_capability,omitempty"`
	GpusMinimumMemory     int    `json:"gpus_minimum_memory,omitempty"`
	GpusMinimumRuntime    string `json:"gpus_minimum_runtime,omitempty"`
	CudaVersion           string `json:"cuda_version,omitempty"`
	RequireGpus           string `json:"require_gpus,omitempty"`
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
	if req.Gpus < 0 || req.Gpus > 16 {
		return fmt.Errorf("gpus must be between 0 and 16, got %d", req.Gpus)
	}
	// GPU strings get concatenated raw into the submit file via
	// resourceRequestLines's fmt.Fprintf. Without a whitelist a value
	// like "12.0\nuniverse = parallel\n+JobUser = root" would inject
	// arbitrary submit directives. Submit files are user-owned, so
	// the user could submit anything anyway — but the request body
	// validators are the right place to refuse out-of-band syntax
	// that the SPA never produces.
	if err := validateGPUSubmitFields(req.GpusMinimumCapability, req.GpusMinimumRuntime, req.CudaVersion, req.RequireGpus); err != nil {
		return err
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

	submitFile := buildInteractiveTerminalSubmitFile(interactive.SubmitArgs{
		InstanceID:            instanceID,
		BatchName:             batchName,
		Cpus:                  req.Cpus,
		MemoryMB:              req.MemoryMB,
		DiskMB:                req.DiskMB,
		Gpus:                  req.Gpus,
		GpusMinimumCapability: req.GpusMinimumCapability,
		GpusMinimumMemory:     req.GpusMinimumMemory,
		GpusMinimumRuntime:    req.GpusMinimumRuntime,
		CudaVersion:           req.CudaVersion,
		RequireGpus:           req.RequireGpus,
		Requirements:          s.interactiveRequirements,
		ExtraSubmitLines:      s.interactiveExtraSubmit,
	})

	// Some access points hold every job submitted without particular OAuth
	// service credentials on file. Create them first, so a person using the
	// web UI does not get a held job for a reason unrelated to what they
	// asked for. Best effort: see ensureRequiredCredentials.
	s.ensureRequiredCredentials(ctx)

	clusterID, procAds, err := s.getSchedd().SubmitRemote(ctx, s.submitPolicy.Apply(submitFile))
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "interactive submit failed",
			"owner", username, "error", err)
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("schedd submit failed: %v", err))
		return
	}

	stage := fstest.MapFS{
		"interactive-watchdog.sh": &fstest.MapFile{
			Data: []byte(interactive.BuildWatchdogScript(interactive.DefaultTerminalWatchdog)),
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

// buildInteractiveTerminalSubmitFile renders the terminal's submit
// file. The shape lives in webapi/interactive so the MCP session tools
// build the same job; this wrapper fixes the browser terminal's
// watchdog timing.
func buildInteractiveTerminalSubmitFile(a interactive.SubmitArgs) string {
	a.Watchdog = interactive.DefaultTerminalWatchdog
	return interactive.BuildSubmitFile(a)
}

// resourceRequestLines and appendExtraSubmitLines are shared with the
// Jupyter submit generator; both now come from webapi/interactive so
// the three surfaces cannot drift.
func resourceRequestLines(
	cpus, memoryMB, diskMB int,
	gpus int, gpusMinCapability string, gpusMinMemoryMB int,
	gpusMinRuntime, cudaVersion, requireGpus string,
) string {
	return interactive.ResourceRequestLines(cpus, memoryMB, diskMB, gpus,
		gpusMinCapability, gpusMinMemoryMB, gpusMinRuntime, cudaVersion, requireGpus)
}

func appendExtraSubmitLines(sb *strings.Builder, extras string) {
	interactive.AppendExtraSubmitLines(sb, extras)
}

// generateInteractiveInstanceID returns the short hex token used both
// as the user-facing instance id and as the JobBatchName suffix.
func generateInteractiveInstanceID() (string, error) {
	return interactive.GenerateInstanceID()
}

// jobIsInteractive reports whether a job ad is one of our interactive
// jobs, by JobBatchName prefix.
func jobIsInteractive(ad interface {
	EvaluateAttrString(name string) (string, bool)
}) bool {
	return interactive.IsInteractiveAd(ad)
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
	// FetchMyJobs feeds opts.Owner into the schedd's MyJobs constraint
	// as `Owner == Me`. The schedd stores the job's Owner attribute with
	// whatever string the negotiation surfaced (typically the full
	// `user@TRUST_DOMAIN` form on this codepath), so passing the raw,
	// unstripped identity is what produces a match. An earlier version
	// stripped `@TRUST_DOMAIN` here and silently matched zero rows;
	// keep this in sync with the dashboard handler, which is the
	// canonical example.
	opts := &htcondor.QueryOptions{
		Limit: 500,
		Projection: []string{
			"ClusterId", "ProcId", "JobStatus", "JobBatchName",
			"HoldReason", "HoldReasonCode", "QDate",
			"JobCurrentStartExecutingDate",
		},
		FetchOpts: htcondor.FetchMyJobs,
		Owner:     owner,
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
// client and runs `touch .heartbeat`. Returns a stop function the
// bridge must defer; the goroutine also exits if ctx is canceled.
//
// The open WebSocket is the liveness signal. An earlier version also
// required a keystroke within the last 60s before each beat, which
// evicted anyone who spent two minutes reading their terminal instead
// of typing into it — the watchdog's freshness window is 120s, so two
// skipped beats were enough to lose the session. The keystroke clock
// survives only as interactiveMaxIdleSec, a bound on a tab left open
// and forgotten, which is measured in hours because that is the
// timescale the behaviour it guards against happens on.
//
// We deliberately reuse the user's already-authenticated ssh.Client
// instead of spawning another condor_ssh_to_job (which would require
// a fresh Cedar handshake — expensive). SSH sessions are cheap once
// the transport is up.
//
// Heartbeat sessions never read input or output; they just dispatch a
// short command and close.
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

		maxIdle := time.Duration(interactiveMaxIdleSec) * time.Second
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
				if time.Since(time.Unix(0, lastNanos)) > maxIdle {
					// Attached but untouched for hours: stop beating
					// and let the watchdog reclaim the slot. Logged,
					// because from the user's side this looks exactly
					// like the session dying on its own.
					s.logger.Info(logging.DestinationHTTP, "interactive heartbeat: idle limit reached, releasing slot",
						"job_id", jobID, "idle_seconds", int(time.Since(time.Unix(0, lastNanos)).Seconds()))
					return
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

// The heartbeat and shutdown commands come from webapi/interactive:
// they must name the same files the watchdog script checks, and that
// script is generated there.
const (
	interactiveHeartbeatCmd = interactive.HeartbeatCmd
	interactiveShutdownCmd  = interactive.ShutdownCmd
)

// sendInteractiveHeartbeat opens a transient ssh.Session on the live
// client, runs the heartbeat touch, and closes.
//
// Failures are logged at Warn rather than Debug. A heartbeat that has
// stopped working is invisible from the outside: the session simply
// ends a couple of minutes later, with nothing at the default log
// level to distinguish it from the user having closed the tab.
func (s *Handler) sendInteractiveHeartbeat(client *ssh.Client, jobID string) {
	sess, err := client.NewSession()
	if err != nil {
		s.logger.Warn(logging.DestinationHTTP, "interactive heartbeat: NewSession failed",
			"job_id", jobID, "error", err)
		return
	}
	defer func() { _ = sess.Close() }()
	if err := sess.Run(interactiveHeartbeatCmd); err != nil {
		s.logger.Warn(logging.DestinationHTTP, "interactive heartbeat: touch failed",
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

// requirementsProbeAttr is an attribute name no real machine ad carries,
// used to check that an operator-supplied interactive requirement actually
// survives into the submitted job.
const requirementsProbeAttr = "HtcondorApiRequirementsProbe"

// verifyInteractiveRequirementsSurvive reports whether an interactive
// requirement still reaches the job ad once the operator's other submit
// knobs have had their say.
//
// A submit file cannot express "and also": `requirements` is a command like
// any other, so the last assignment wins outright. HTTP_API_INTERACTIVE_-
// EXTRA_SUBMIT is spliced after ours, and the site policy's overrides are
// inserted after that, so either can replace the constraint that decides
// whether a terminal can be attached to at all -- silently, because
// dropping it produces a job that runs perfectly and refuses every shell.
//
// Rather than scan the text for a `requirements` line, which means
// reimplementing submit-file lexing and being wrong about continuations and
// comments, this runs the real pipeline with a probe expression and asks
// whether the probe came out the other end.
func verifyInteractiveRequirementsSurvive(extraSubmit string, policy submitpolicy.Policy) error {
	probe := fmt.Sprintf("%s =!= undefined", requirementsProbeAttr)
	submitText := policy.Apply(buildInteractiveTerminalSubmitFile(interactive.SubmitArgs{
		InstanceID:       "probe",
		BatchName:        "probe",
		Cpus:             1,
		MemoryMB:         1024,
		DiskMB:           1024,
		Requirements:     probe,
		ExtraSubmitLines: extraSubmit,
	}))

	sf, err := htcondor.ParseSubmitFile(strings.NewReader(submitText))
	if err != nil {
		return fmt.Errorf("the generated interactive submit file does not parse: %w", err)
	}
	ad, err := sf.MakeJobAd(htcondor.JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		return fmt.Errorf("the generated interactive submit file does not produce a job ad: %w", err)
	}
	req, ok := ad.Lookup("Requirements")
	if !ok || !strings.Contains(req.String(), requirementsProbeAttr) {
		return fmt.Errorf(
			"HTTP_API_INTERACTIVE_REQUIREMENTS would be discarded: another knob sets `requirements` "+
				"later in the submit file (HTTP_API_INTERACTIVE_EXTRA_SUBMIT or HTTP_API_SUBMIT_FILE_OVERRIDES), "+
				"and the last assignment wins. Combine them into one expression. Resulting requirements: %s",
			requirementsSummary(req))
	}
	return nil
}

// requirementsSummary renders a Requirements expression for an error
// message, or says so when there is none.
func requirementsSummary(req interface{ String() string }) string {
	if req == nil {
		return "<none>"
	}
	return req.String()
}
