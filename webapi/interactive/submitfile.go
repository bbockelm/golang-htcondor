// Package interactive builds and supervises interactive HTCondor jobs:
// vanilla-universe sandboxes a caller keeps alive with a heartbeat and
// runs commands inside over condor_ssh_to_job.
//
// Two surfaces consume it. The REST/SPA terminal (webapi/httpserver)
// submits one of these jobs and attaches a browser to it over a
// WebSocket, heartbeating for as long as the socket is open. The MCP
// tools (webapi/mcpserver) have no socket to hang liveness on, so they
// name a session and lease it: see Manager.
//
// The job's lifetime is gated by a heartbeat file in its scratch dir.
// A watchdog shell script is the job's executable; if the file goes
// stale the watchdog exits and the slot is released. Using a watchdog
// rather than `sleep $LARGE` means a caller that walks away — a closed
// browser tab, an agent that never calls back, an API server that
// crashed — does not squat the slot indefinitely.
package interactive

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// BatchPrefix marks a job as an interactive session by JobBatchName.
// Both surfaces filter the caller's queue on it, and the SSH bridge
// uses it to decide whether a job wants heartbeating.
const BatchPrefix = "htcondor-api-interactive-terminal-"

// SessionBatchPrefix marks a job as an MCP interactive session and
// carries the caller's chosen name: the JobBatchName is this prefix
// plus the name, and that is what a lookup resolves.
//
// The name has to live on the JOB rather than only in the server's
// memory: an MCP client addresses a session by name on every call and
// holds no connection in between, so the queue -- not a process that
// may have restarted since -- is what remembers which session a name
// refers to.
//
// JobBatchName rather than a custom +InteractiveSessionName attribute.
// A custom attribute was the first choice and could not be used: the
// submit parser silently dropped every `+Attr = "value"` line, so a
// session named that way was created and then never found again. That
// bug is fixed now (see setCustomAttributes in submit.go), but this
// stayed put on its own merits -- JobBatchName is the attribute
// `condor_q -batch` already displays, so a user sees their session
// names in the queue without being told where to look.
const SessionBatchPrefix = "htcondor-api-interactive-session-"

// SessionLeaseAttr records a session's lease duration, in seconds, on
// the job ad.
//
// The queue is the session registry -- a name resolves after this
// process is gone -- but the lease itself lived only in memory, so a
// session re-adopted after a restart silently fell back to the
// default. A caller who asked for eight hours got thirty minutes and
// found out when the slot was reclaimed. Anything the lease depends on
// has to live where the session does.
const SessionLeaseAttr = "HTCondorAPISessionLeaseSeconds"

// BatchNameForSession is the JobBatchName carrying a session's name.
func BatchNameForSession(name string) string { return SessionBatchPrefix + name }

// SessionNameFromBatchName recovers the session name from a job's
// JobBatchName, reporting false for a job that is not a session.
func SessionNameFromBatchName(batchName string) (string, bool) {
	if !strings.HasPrefix(batchName, SessionBatchPrefix) {
		return "", false
	}
	name := strings.TrimPrefix(batchName, SessionBatchPrefix)
	if name == "" {
		return "", false
	}
	return name, true
}

// WatchdogTiming is how often the in-job watchdog checks its heartbeat
// file and how stale that file may get before it gives up.
//
// The script polls every PollSec; if .heartbeat is older than
// FreshnessSec it exits. Whoever holds the session must touch the file
// more often than FreshnessSec.
//
// FreshnessSec is really "how long a slot stays held after everything
// keeping it alive has died", so the two surfaces want different
// values. A browser terminal's heartbeat stops the moment the socket
// drops, and the socket dropping is itself a reliable signal, so it can
// afford a tight window. An MCP session's heartbeat stops when the API
// server stops, which a restart should be able to recover from — its
// window is what bounds that recovery.
type WatchdogTiming struct {
	PollSec      int
	FreshnessSec int
}

// Terminal and session watchdog timings, as constants so callers can
// use them where a constant is required.
const (
	// Browser terminal: a ~120s eviction window once the WebSocket
	// goes away, polled every 30s.
	DefaultTerminalWatchdogPollSec      = 30
	DefaultTerminalWatchdogFreshnessSec = 120

	// MCP session: the wider freshness window is the restart budget
	// described on DefaultSessionWatchdog.
	DefaultSessionWatchdogPollSec      = 30
	DefaultSessionWatchdogFreshnessSec = 900
)

// DefaultTerminalWatchdog is the browser-terminal timing.
var DefaultTerminalWatchdog = WatchdogTiming{
	PollSec:      DefaultTerminalWatchdogPollSec,
	FreshnessSec: DefaultTerminalWatchdogFreshnessSec,
}

// DefaultSessionWatchdog is the MCP-session timing. The wider
// freshness window is the restart budget: if the API server dies,
// nothing touches .heartbeat until a client names the session again
// and the manager re-adopts it, so the window has to be long enough for
// an operator restart to land inside it. The cost of getting it wrong
// in the other direction is a held slot doing nothing, which is why it
// is minutes and not hours.
var DefaultSessionWatchdog = WatchdogTiming{
	PollSec:      DefaultSessionWatchdogPollSec,
	FreshnessSec: DefaultSessionWatchdogFreshnessSec,
}

func (t WatchdogTiming) withDefaults() WatchdogTiming {
	if t.PollSec <= 0 {
		t.PollSec = DefaultTerminalWatchdog.PollSec
	}
	if t.FreshnessSec <= 0 {
		t.FreshnessSec = DefaultTerminalWatchdog.FreshnessSec
	}
	return t
}

// HeartbeatCmd and ShutdownCmd are run inside the job over SSH.
//
// Both must name the heartbeat file the same way the watchdog does.
// The watchdog runs with the scratch dir as its cwd; an SSH exec does
// not necessarily share that cwd, so these use an absolute path built
// from the environment the starter exports. The fallback to "." exists
// only so a malformed environment degrades to "touch something" rather
// than "touch /.heartbeat".
const (
	HeartbeatCmd = `touch "${_CONDOR_SCRATCH_DIR:-.}/.heartbeat"`
	ShutdownCmd  = `touch "${_CONDOR_SCRATCH_DIR:-.}/.shutdown"`
)

// HeartbeatFile and ShutdownFile are the names the watchdog checks,
// relative to its cwd (the scratch dir).
const (
	HeartbeatFile = ".heartbeat"
	ShutdownFile  = ".shutdown"
)

// SubmitArgs describes one interactive job to submit.
type SubmitArgs struct {
	InstanceID string
	BatchName  string

	Cpus     int
	MemoryMB int
	DiskMB   int

	// GPU fields. Mirrored verbatim into request_gpus and the
	// gpus_minimum_* / cuda_version / require_gpus submit lines.
	// Gpus == 0 disables the entire GPU section in the submit file.
	Gpus                  int
	GpusMinimumCapability string
	GpusMinimumMemory     int
	GpusMinimumRuntime    string
	CudaVersion           string
	RequireGpus           string

	// Requirements is an operator-supplied ClassAd expression ANDed into
	// the job's Requirements (httpserver's Handler.interactiveRequirements).
	Requirements string

	// LeaseSeconds, when positive, is recorded on the job ad so the
	// session's lease survives this process. See SessionLeaseAttr.
	LeaseSeconds int

	// Watchdog is the timing baked into the generated script. The zero
	// value means DefaultTerminalWatchdog.
	Watchdog WatchdogTiming

	// ExtraSubmitLines is operator-supplied submit-file content merged
	// in just before the `queue` directive.
	ExtraSubmitLines string

	// CallerSubmitLines are submit commands the SESSION's caller asked
	// for. Emitted before the operator's block so the operator still has
	// the last word, and validated by ValidateCallerSubmitLines first.
	CallerSubmitLines string
}

// AppendExtraSubmitLines writes operator-supplied extra submit-file
// directives to sb, surrounded by a marker comment so the resulting
// submit file makes the source obvious. No-op when extras is empty
// or whitespace-only. The contents are passed through verbatim:
// because the file is operator-only config (loaded at startup from
// a path the operator chose), we trust whatever it contains the
// same way HTCondor trusts its own site_local config.
//
// Always emits a leading newline so the marker line stands apart
// from whatever directive immediately preceded it, and a trailing
// newline so `queue` appears on its own line.
func AppendExtraSubmitLines(sb *strings.Builder, extras string) {
	if strings.TrimSpace(extras) == "" {
		return
	}
	sb.WriteString("\n# --- Operator-supplied extra submit directives ---\n")
	sb.WriteString(extras)
	if !strings.HasSuffix(extras, "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString("# --- End operator-supplied extras ---\n")
}

// ResourceRequestLines emits the request_cpus / request_memory /
// request_disk plus optional request_gpus + gpus_minimum_* / cuda_version
// / require_gpus lines. Shared between the terminal, session and Jupyter
// submit generators so they speak the same vocabulary.
//
// Unit note: HTCondor's bare-integer convention differs by attribute —
// `request_memory` is interpreted as MiB, `request_disk` as KiB. The
// API surface speaks MiB for both, so we multiply diskMB by 1024 on
// the way out. Without this, asking for 4096 MB of scratch produced
// jobs that died in transfer because the schedd actually allocated
// 4 MiB.
func ResourceRequestLines(
	cpus, memoryMB, diskMB int,
	gpus int, gpusMinCapability string, gpusMinMemoryMB int,
	gpusMinRuntime, cudaVersion, requireGpus string,
) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "request_cpus = %d\n", cpus)
	fmt.Fprintf(&sb, "request_memory = %d\n", memoryMB)
	fmt.Fprintf(&sb, "request_disk = %d\n", diskMB*1024)
	if gpus > 0 {
		fmt.Fprintf(&sb, "request_gpus = %d\n", gpus)
		if gpusMinCapability != "" {
			fmt.Fprintf(&sb, "gpus_minimum_capability = %s\n", gpusMinCapability)
		}
		if gpusMinMemoryMB > 0 {
			fmt.Fprintf(&sb, "gpus_minimum_memory = %d\n", gpusMinMemoryMB)
		}
		if gpusMinRuntime != "" {
			fmt.Fprintf(&sb, "gpus_minimum_runtime = %s\n", gpusMinRuntime)
		}
		if cudaVersion != "" {
			fmt.Fprintf(&sb, "cuda_version = %s\n", cudaVersion)
		}
		if requireGpus != "" {
			fmt.Fprintf(&sb, "require_gpus = %s\n", requireGpus)
		}
	}
	sb.WriteString("\n")
	return sb.String()
}

// BuildSubmitFile renders the submit file for one interactive job.
func BuildSubmitFile(a SubmitArgs) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Auto-generated by htcondor-api for interactive terminal %s\n", a.InstanceID)
	fmt.Fprintf(&sb, "universe = vanilla\n\n")

	fmt.Fprintf(&sb, "executable = interactive-watchdog.sh\n")
	fmt.Fprintf(&sb, "transfer_executable = true\n\n")

	fmt.Fprintf(&sb, "should_transfer_files = YES\n")
	fmt.Fprintf(&sb, "when_to_transfer_output = ON_EXIT\n\n")

	sb.WriteString(ResourceRequestLines(
		a.Cpus, a.MemoryMB, a.DiskMB,
		a.Gpus, a.GpusMinimumCapability, a.GpusMinimumMemory,
		a.GpusMinimumRuntime, a.CudaVersion, a.RequireGpus,
	))

	// JobBatchName lets the SSH bridge identify this as an interactive
	// job at attach time. The prefix is also used to enumerate active
	// sessions for a caller.
	//
	// The submit-file key is `batch_name` (no `job_` prefix). The
	// in-process submit parser at submit.go's setExtendedJobExprs only
	// recognises that exact spelling and maps it to the JobBatchName
	// ad attribute; emitting `job_batch_name` here was silently
	// no-oping, leaving JobBatchName unset and making the prefix filter
	// skip every job the user submitted ("No active terminal sessions"
	// in the SPA).
	// For an MCP session this is also where the caller's session name
	// lives (SessionBatchPrefix + name), which is what makes a name
	// resolvable after this process is gone.
	fmt.Fprintf(&sb, "batch_name = %s\n\n", a.BatchName)

	// The lease belongs on the job because the job outlives this
	// process. A session adopted after a restart otherwise fell back to
	// the default lease: a caller who asked for eight hours got thirty
	// minutes, and only found out when the session was reclaimed.
	//
	// This is also the line that could not have been written before
	// the submit parser stopped dropping `+Attr` entirely.
	if a.LeaseSeconds > 0 {
		fmt.Fprintf(&sb, "+%s = %d\n\n", SessionLeaseAttr, a.LeaseSeconds)
	}

	fmt.Fprintf(&sb, "log    = interactive.log\n")
	fmt.Fprintf(&sb, "output = interactive.out\n")
	fmt.Fprintf(&sb, "error  = interactive.err\n")

	// Emitted before the operator's extra block, not after: setRequirements
	// ANDs a `requirements` command with the clauses submit derives for
	// itself, so this narrows the match rather than replacing it. An
	// operator who sets `requirements` in the extra block is spliced later
	// and therefore still wins, which is the precedence they would expect
	// from a verbatim escape hatch.
	if req := strings.TrimSpace(a.Requirements); req != "" {
		fmt.Fprintf(&sb, "requirements = (%s)\n\n", req)
	}

	// The caller's own submit commands come before the operator's block,
	// so an operator override still wins -- same precedence the rest of
	// this file follows, and the reason the operator block is last.
	if lines := strings.TrimSpace(a.CallerSubmitLines); lines != "" {
		sb.WriteString("\n# --- Caller-supplied submit commands ---\n")
		sb.WriteString(lines)
		if !strings.HasSuffix(lines, "\n") {
			sb.WriteString("\n")
		}
		sb.WriteString("# --- End caller-supplied commands ---\n")
	}

	// Operator-supplied extras get spliced in just before `queue`
	// so they can override anything the builder emitted above. The
	// banner comment makes it obvious in the schedd's spool which
	// directives came from us vs the operator's site policy.
	AppendExtraSubmitLines(&sb, a.ExtraSubmitLines)

	fmt.Fprintf(&sb, "queue\n")
	return sb.String()
}

// BuildWatchdogScript emits the POSIX-shell watchdog that runs as the
// interactive job's executable. It primes a heartbeat file, then loops
// checking the file's age. If it goes stale the script kills any sshd
// processes the caller attached through and exits — that combination
// releases the HTCondor slot.
//
// Whoever holds the session also drops a `.shutdown` file in the
// scratch dir when it is done; the watchdog notices that on its next
// tick and exits immediately, so the slot frees within PollSec seconds
// instead of waiting out the full freshness window. Either trigger
// reaches the same stale_exit path.
//
// Implementation notes:
//
//   - We use plain /bin/sh to avoid bash-isms.
//
//   - `stat -c %Y` is GNU stat (Linux); `stat -f %m` is BSD stat
//     (macOS). Try both so the same script runs on either pool.
//
//   - Bootstrap touch happens BEFORE the loop so the caller has up to
//     one full freshness window to attach + start sending heartbeats.
//
//   - On stale-exit we kill this job's sshd first. condor_ssh_to_job
//     spawns an sshd inside the sandbox; if we just exit while the
//     caller still has a session open, the starter waits for sshd's
//     descendants and the slot stays held. Killing it lets the starter
//     actually wind the job down.
//
//     The match is on the sandbox path, not the process name. A bare
//     `pkill sshd` matches every sshd the job's UID may signal, and
//     only a pool that runs jobs as dedicated slot users is saved by
//     that: where jobs run as the submitting user, the set includes
//     that user's login sshd on the same node and the sshd of their
//     other interactive jobs. condor_ssh_to_job puts its config under
//     _CONDOR_SCRATCH_DIR and passes it with -f, so the sandbox path
//     is on the command line and tells this job's sshd from the rest.
//
//   - Startup log line goes to stderr (= the job's `error` file) so
//     the operator can confirm the watchdog is running.
func BuildWatchdogScript(t WatchdogTiming) string {
	t = t.withDefaults()
	return fmt.Sprintf(`#!/bin/sh
# Auto-generated by htcondor-api. Keeps an interactive job alive only
# while something is actively heartbeating it.
HEARTBEAT_FILE="%s"
SHUTDOWN_FILE="%s"
POLL_INTERVAL=%d
FRESHNESS_WINDOW=%d

echo "[interactive-watchdog] starting pid=$$ scratch=${_CONDOR_SCRATCH_DIR:-(unset)} poll=${POLL_INTERVAL}s freshness=${FRESHNESS_WINDOW}s" >&2

touch "$HEARTBEAT_FILE"

stat_mtime() {
  stat -c %%Y "$1" 2>/dev/null || stat -f %%m "$1" 2>/dev/null
}

stale_exit() {
  echo "[interactive-watchdog] $1; killing this job's sshd and exiting" >&2
  # Only the sshd condor_ssh_to_job started for THIS job: its config
  # path is under our scratch directory and appears on its command
  # line. Matching on the name alone would reach the user's login sshd
  # and their other jobs' sessions wherever jobs run as the submitting
  # user rather than a slot user.
  scratch="${_CONDOR_SCRATCH_DIR:-$PWD}"
  pkill -TERM -f "sshd.*${scratch}" 2>/dev/null || true
  sleep 1
  pkill -KILL -f "sshd.*${scratch}" 2>/dev/null || true
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
`, HeartbeatFile, ShutdownFile, t.PollSec, t.FreshnessSec)
}

// GenerateInstanceID returns a short hex token used both as the
// user-facing instance id and as the JobBatchName suffix. 8 bytes
// (16 hex chars) is plenty given that uniqueness is only needed across
// the API server's lifetime.
func GenerateInstanceID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// IsInteractiveAd reports whether a job ad is one of our interactive
// jobs, by JobBatchName prefix.
func IsInteractiveAd(ad interface {
	EvaluateAttrString(name string) (string, bool)
}) bool {
	name, ok := ad.EvaluateAttrString("JobBatchName")
	if !ok {
		return false
	}
	return strings.HasPrefix(name, BatchPrefix)
}

// sessionNamePattern is deliberately narrow. The name is spliced into
// a ClassAd string literal in the submit file and into a constraint
// expression on every lookup, so the safest thing it can be is a token
// with no syntax in it at all. It is also what a person types into an
// agent prompt, so it stays readable.
var sessionNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// sessionOwnedCommands are the submit commands that make the job a
// session rather than an ordinary job. A caller who redefines one gets a
// job that submits cleanly and then cannot be attached to -- the wrong
// executable runs, or the batch name no longer carries the session's
// identity, so nothing can find it by name again.
var sessionOwnedCommands = map[string]string{
	"executable":              "the session's executable is the watchdog that keeps the job alive",
	"transfer_executable":     "the watchdog has to be transferred for the job to run at all",
	"batch_name":              "the batch name carries the session's name; a session is found by it",
	"queue":                   "the builder emits the queue statement",
	"universe":                "a session is a vanilla-universe job",
	"should_transfer_files":   "file transfer delivers the watchdog",
	"when_to_transfer_output": "file transfer delivers the watchdog",
}

// ValidateCallerSubmitLines checks caller-supplied submit commands,
// rejecting the ones the session itself depends on.
//
// This is not a privilege check -- the same caller can submit anything
// through an ordinary submit -- it keeps a SESSION from being redefined
// into something the session tools cannot use.
func ValidateCallerSubmitLines(lines string) error {
	for i, raw := range strings.Split(lines, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			// `queue` and friends have no '=' and are equally unwelcome.
			if why, owned := sessionOwnedCommands[strings.ToLower(line)]; owned {
				return fmt.Errorf("line %d: %q is set by the session builder: %s", i+1, line, why)
			}
			return fmt.Errorf("line %d: %q is not a submit command (expected name = value)", i+1, line)
		}
		name := strings.ToLower(strings.TrimSpace(line[:eq]))
		if why, owned := sessionOwnedCommands[name]; owned {
			return fmt.Errorf("line %d: %q is set by the session builder: %s", i+1, name, why)
		}
	}
	return nil
}

// ValidateSessionName checks a caller-supplied session name.
func ValidateSessionName(name string) error {
	if name == "" {
		return fmt.Errorf("session name is required")
	}
	if !sessionNamePattern.MatchString(name) {
		return fmt.Errorf("invalid session name %q: use 1-64 characters of letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	return nil
}
