package interactive

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing/fstest"
	"time"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/submitpolicy"
)

// Manager owns named interactive sessions: it submits their jobs,
// keeps them alive, runs commands in them, and tears them down.
//
// # Why a lease and not a connection
//
// The browser terminal hangs a job's liveness on a WebSocket: the
// socket is open, therefore someone is there. An MCP client has no
// such socket. It calls a tool, gets an answer, and may say nothing
// for minutes while a model thinks — and in MCP's sessionless
// direction it may not even be talking to the same server process it
// talked to last time. So liveness here is a LEASE: every call that
// names a session pushes its expiry out, a heartbeat runs meanwhile,
// and silence past the lease reclaims the slot.
//
// # Why the name lives in the job ad
//
// A session is addressed by a name the caller passes as an argument on
// every call, never by connection state. That name is stored on the
// job (SessionNameAttr), so the queue is the session registry and this
// map is only a cache of it. A restarted API server re-adopts a
// session the first time a client names it; the watchdog's freshness
// window (DefaultSessionWatchdog) is what bounds how long that restart
// may take before the slot is reclaimed anyway.
type Manager struct {
	opts Options

	mu       sync.Mutex
	sessions map[string]*session
	closed   bool
	wg       sync.WaitGroup
}

// Options configures a Manager. The zero value of every field has a
// working default except Schedd, which is required.
type Options struct {
	// Schedd returns the schedd to submit to and query. A function
	// rather than a value because the host may reconnect or rediscover
	// it over the process's lifetime, and an interface rather than
	// *htcondor.Schedd so the lease and lifecycle logic can be tested
	// without a pool behind it.
	Schedd func() ScheddClient

	Logger  *logging.Logger
	LogDest logging.Destination

	// SubmitPolicy is the operator's site-wide submit-file policy, and
	// ExtraSubmit the operator's interactive-specific additions. Both
	// apply here for the same reason they apply to every other submit
	// surface: a site requirement the caller cannot know about.
	SubmitPolicy submitpolicy.Policy
	ExtraSubmit  string

	// Watchdog is the timing baked into the job. Defaults to
	// DefaultSessionWatchdog.
	Watchdog WatchdogTiming

	// HeartbeatInterval is how often an attached session's heartbeat
	// fires. Clamped to at most a third of the watchdog's freshness
	// window so a couple of lost beats cannot evict a live session.
	HeartbeatInterval time.Duration

	// DefaultLease is applied when a caller does not ask for one;
	// MaxLease is the ceiling on what they may ask for.
	DefaultLease time.Duration
	MaxLease     time.Duration

	// MaxPerOwner bounds how many sessions one owner may hold at once.
	// Interactive sessions hold a slot while idle, so this is the knob
	// that keeps an agent in a retry loop from draining the pool.
	MaxPerOwner int

	// MaxOutputBytes caps each of stdout and stderr per exec.
	MaxOutputBytes int

	// Dial opens a Shell into a running job. Defaults to
	// condor_ssh_to_job; tests substitute a fake.
	Dial Dialer

	// Now is the clock, for tests.
	Now func() time.Time
}

// Defaults for Options.
const (
	DefaultLease          = 30 * time.Minute
	DefaultMaxLease       = 8 * time.Hour
	DefaultHeartbeat      = 60 * time.Second
	DefaultMaxPerOwner    = 4
	DefaultMaxOutputBytes = 64 * 1024
	// DefaultExecTimeout bounds one command. Long enough for a build
	// or a test run, short enough that a wedged command gives the
	// caller its output back rather than hanging the tool call.
	DefaultExecTimeout = 5 * time.Minute
	// MaxExecTimeout is the ceiling on a caller-requested timeout.
	MaxExecTimeout = 30 * time.Minute
	// DefaultWaitForReady is how long exec waits for a just-submitted
	// session to start running before giving up.
	DefaultWaitForReady = 2 * time.Minute
	// MaxWaitForReady is the ceiling on that wait.
	MaxWaitForReady = 15 * time.Minute
)

// Caller identifies who is asking. Actor is the authenticated identity
// ("alice@uid.domain"); Owner is the value HTCondor puts in a job's
// Owner attribute ("alice"). Both are needed because the schedd's
// authenticated-query filter keys on the first and job ads carry the
// second; the host computes the mapping, since it already owns that
// rule.
type Caller struct {
	Actor string
	Owner string
}

func (c Caller) valid() bool { return c.Actor != "" && c.Owner != "" }

// session is one live session's in-process state. All fields are
// guarded by Manager.mu; commands and heartbeats run outside the lock
// on a shell pointer copied out under it.
type session struct {
	name       string
	owner      string
	instanceID string
	cluster    int
	proc       int

	shell         Shell
	leaseExpires  time.Time
	heartbeatOn   bool
	stopHeartbeat chan struct{}

	// secConfig is the credential the session was last reached with,
	// kept so the manager can redial the job or remove it from a
	// background goroutine that has no request context of its own.
	// This is the same trust the WebSocket bridge takes by holding an
	// authenticated ssh.Client open for the life of a terminal; the
	// lease is what bounds how long it is held.
	secConfig *security.SecurityConfig
}

// Info is the caller-facing view of a session.
type Info struct {
	Name           string    `json:"name"`
	JobID          string    `json:"job_id"`
	ClusterID      int       `json:"cluster_id"`
	ProcID         int       `json:"proc_id"`
	JobStatus      int       `json:"job_status"`
	Status         string    `json:"status"`
	HoldReason     string    `json:"hold_reason,omitempty"`
	HoldReasonCode int       `json:"hold_reason_code,omitempty"`
	SubmittedAt    time.Time `json:"submitted_at,omitempty"`
	LeaseExpires   time.Time `json:"lease_expires,omitempty"`
	Attached       bool      `json:"attached"`
}

// CreateSpec describes a session to start.
type CreateSpec struct {
	Name     string
	Cpus     int
	MemoryMB int
	DiskMB   int

	Gpus                  int
	GpusMinimumCapability string
	GpusMinimumMemory     int
	GpusMinimumRuntime    string
	CudaVersion           string
	RequireGpus           string

	Lease time.Duration
}

// ExecRequest is one command to run in a session.
type ExecRequest struct {
	Command      string
	Timeout      time.Duration
	WaitForReady time.Duration
}

// ExecResult is what the command did.
type ExecResult struct {
	JobID           string        `json:"job_id"`
	ExitCode        int           `json:"exit_code"`
	Stdout          string        `json:"stdout"`
	Stderr          string        `json:"stderr"`
	StdoutTruncated bool          `json:"stdout_truncated,omitempty"`
	StderrTruncated bool          `json:"stderr_truncated,omitempty"`
	Duration        time.Duration `json:"duration"`
	TimedOut        bool          `json:"timed_out,omitempty"`
	// MaxOutputBytes is the cap that was in force for this call, so a
	// truncation note names the limit that actually applied rather
	// than the package default.
	MaxOutputBytes int       `json:"max_output_bytes,omitempty"`
	LeaseExpires   time.Time `json:"lease_expires"`
}

// NewManager returns a Manager with defaults filled in.
func NewManager(opts Options) (*Manager, error) {
	if opts.Schedd == nil {
		return nil, fmt.Errorf("interactive: Options.Schedd is required")
	}
	if opts.Logger == nil {
		var err error
		opts.Logger, err = logging.New(&logging.Config{OutputPath: "stderr"})
		if err != nil {
			return nil, fmt.Errorf("interactive: create logger: %w", err)
		}
	}
	if opts.Watchdog.PollSec <= 0 {
		opts.Watchdog.PollSec = DefaultSessionWatchdog.PollSec
	}
	if opts.Watchdog.FreshnessSec <= 0 {
		opts.Watchdog.FreshnessSec = DefaultSessionWatchdog.FreshnessSec
	}
	if opts.HeartbeatInterval <= 0 {
		opts.HeartbeatInterval = DefaultHeartbeat
	}
	// A heartbeat that fires as rarely as the watchdog checks means one
	// slow round-trip evicts a live session. Insist on headroom.
	if maxInterval := time.Duration(opts.Watchdog.FreshnessSec) * time.Second / 3; opts.HeartbeatInterval > maxInterval {
		opts.HeartbeatInterval = maxInterval
	}
	if opts.DefaultLease <= 0 {
		opts.DefaultLease = DefaultLease
	}
	if opts.MaxLease <= 0 {
		opts.MaxLease = DefaultMaxLease
	}
	if opts.DefaultLease > opts.MaxLease {
		opts.DefaultLease = opts.MaxLease
	}
	if opts.MaxPerOwner <= 0 {
		opts.MaxPerOwner = DefaultMaxPerOwner
	}
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Dial == nil {
		opts.Dial = sshDialer(opts.Schedd)
	}
	return &Manager{opts: opts, sessions: map[string]*session{}}, nil
}

func sessionKey(owner, name string) string { return owner + "\x00" + name }

func (m *Manager) log() *logging.Logger { return m.opts.Logger }

// Create submits a new session job and registers a lease for it. The
// job is idle when this returns; Exec waits for it to start.
func (m *Manager) Create(ctx context.Context, caller Caller, spec CreateSpec) (*Info, error) {
	if !caller.valid() {
		return nil, fmt.Errorf("authentication required")
	}
	if err := ValidateSessionName(spec.Name); err != nil {
		return nil, err
	}
	applySpecDefaults(&spec)
	if err := validateSpec(spec); err != nil {
		return nil, err
	}

	// Two separate limits, both checked against the queue rather than
	// the in-process map: after a restart the map is empty but the
	// jobs are not, and "you already have a session by that name" has
	// to keep being true across that boundary.
	existing, err := m.listAds(ctx, caller, "")
	if err != nil {
		return nil, err
	}
	for _, info := range existing {
		if info.Name == spec.Name {
			return nil, fmt.Errorf("session %q already exists (job %s, %s); use it, or stop it first",
				spec.Name, info.JobID, info.Status)
		}
	}
	if len(existing) >= m.opts.MaxPerOwner {
		return nil, fmt.Errorf("you already have %d interactive sessions, the per-user limit; stop one before starting another",
			len(existing))
	}

	instanceID, err := GenerateInstanceID()
	if err != nil {
		return nil, fmt.Errorf("generate instance id: %w", err)
	}

	submitFile := BuildSubmitFile(SubmitArgs{
		InstanceID:            instanceID,
		BatchName:             BatchNameForSession(spec.Name),
		Cpus:                  spec.Cpus,
		MemoryMB:              spec.MemoryMB,
		DiskMB:                spec.DiskMB,
		Gpus:                  spec.Gpus,
		GpusMinimumCapability: spec.GpusMinimumCapability,
		GpusMinimumMemory:     spec.GpusMinimumMemory,
		GpusMinimumRuntime:    spec.GpusMinimumRuntime,
		CudaVersion:           spec.CudaVersion,
		RequireGpus:           spec.RequireGpus,
		Watchdog:              m.opts.Watchdog,
		ExtraSubmitLines:      m.opts.ExtraSubmit,
	})

	schedd := m.opts.Schedd()
	if schedd == nil {
		return nil, fmt.Errorf("no schedd configured")
	}
	clusterID, procAds, err := schedd.SubmitRemote(ctx, m.opts.SubmitPolicy.Apply(submitFile))
	if err != nil {
		return nil, fmt.Errorf("schedd submit failed: %w", err)
	}

	stage := fstest.MapFS{
		"interactive-watchdog.sh": &fstest.MapFile{
			Data: []byte(BuildWatchdogScript(m.opts.Watchdog)),
			Mode: 0o755,
		},
	}
	if err := schedd.SpoolJobFilesFromFS(ctx, procAds, stage); err != nil {
		// The job exists but can never run: remove it rather than
		// leave the caller a held job they did not ask for.
		m.removeJob(ctx, caller, clusterID, 0, "watchdog spooling failed")
		return nil, fmt.Errorf("schedd accepted the submit but spooling the watchdog failed: %w", err)
	}

	procID := 0
	if len(procAds) > 0 {
		if v, ok := procAds[0].EvaluateAttrInt("ProcId"); ok {
			procID = int(v)
		}
	}

	lease := m.clampLease(spec.Lease)
	sess := &session{
		name:         spec.Name,
		owner:        caller.Owner,
		instanceID:   instanceID,
		cluster:      clusterID,
		proc:         procID,
		leaseExpires: m.opts.Now().Add(lease),
		secConfig:    securityConfigFrom(ctx),
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, fmt.Errorf("interactive session manager is shutting down")
	}
	m.sessions[sessionKey(caller.Owner, spec.Name)] = sess
	m.mu.Unlock()

	m.log().Info(m.opts.LogDest, "interactive session created",
		"session", spec.Name, "owner", caller.Owner,
		"job_id", jobIDOf(clusterID, procID), "instance", instanceID,
		"lease_seconds", int(lease.Seconds()))

	info := &Info{
		Name:         spec.Name,
		JobID:        jobIDOf(clusterID, procID),
		ClusterID:    clusterID,
		ProcID:       procID,
		JobStatus:    jobStatusIdle,
		Status:       statusText(jobStatusIdle, 0),
		LeaseExpires: sess.leaseExpires,
	}
	return info, nil
}

// List returns the caller's sessions, from the queue.
func (m *Manager) List(ctx context.Context, caller Caller) ([]Info, error) {
	if !caller.valid() {
		return nil, fmt.Errorf("authentication required")
	}
	infos, err := m.listAds(ctx, caller, "")
	if err != nil {
		return nil, err
	}
	for i := range infos {
		m.mu.Lock()
		if sess, ok := m.sessions[sessionKey(caller.Owner, infos[i].Name)]; ok {
			infos[i].LeaseExpires = sess.leaseExpires
			infos[i].Attached = sess.shell != nil
		}
		m.mu.Unlock()
	}
	return infos, nil
}

// Exec runs one command in a named session and returns its output.
//
// It waits for the job to start if it has not yet, attaches if this
// process is not attached, extends the lease, and runs the command in
// a fresh shell. Nothing about it depends on a previous call having
// happened in this process: that is what makes it usable from a
// sessionless client.
func (m *Manager) Exec(ctx context.Context, caller Caller, name string, req ExecRequest) (*ExecResult, error) {
	if !caller.valid() {
		return nil, fmt.Errorf("authentication required")
	}
	if err := ValidateSessionName(name); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Command) == "" {
		return nil, fmt.Errorf("command is required")
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultExecTimeout
	}
	if timeout > MaxExecTimeout {
		timeout = MaxExecTimeout
	}
	wait := req.WaitForReady
	if wait <= 0 {
		wait = DefaultWaitForReady
	}
	if wait > MaxWaitForReady {
		wait = MaxWaitForReady
	}

	info, err := m.waitForRunning(ctx, caller, name, wait)
	if err != nil {
		return nil, err
	}

	shell, err := m.attach(ctx, caller, info)
	if err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout := newCappedBuffer(m.opts.MaxOutputBytes)
	stderr := newCappedBuffer(m.opts.MaxOutputBytes)
	started := m.opts.Now()
	code, runErr := shell.Run(runCtx, req.Command, stdout, stderr)
	elapsed := m.opts.Now().Sub(started)

	if runErr != nil && errors.Is(runErr, errNotDispatched) && runCtx.Err() == nil && ctx.Err() == nil {
		// The command never started: a session idle for a while may be
		// holding a connection the job has already dropped. Redial and
		// try once more before reporting failure.
		//
		// Only this case retries. A command that started and then lost
		// its transport may have already done part of its work, and
		// running it a second time would repeat it — the caller gets
		// the error and decides.
		m.detach(caller.Owner, name, "shell error: "+runErr.Error())
		shell, err = m.attach(ctx, caller, info)
		if err != nil {
			return nil, fmt.Errorf("command dispatch failed: %w; reconnecting to the session also failed: %w", runErr, err)
		}
		stdout.reset()
		stderr.reset()
		started = m.opts.Now()
		code, runErr = shell.Run(runCtx, req.Command, stdout, stderr)
		elapsed = m.opts.Now().Sub(started)
	}

	lease := m.extendLease(caller.Owner, name)

	result := &ExecResult{
		JobID:           info.JobID,
		ExitCode:        code,
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		StdoutTruncated: stdout.truncated(),
		StderrTruncated: stderr.truncated(),
		Duration:        elapsed,
		MaxOutputBytes:  m.opts.MaxOutputBytes,
		LeaseExpires:    lease,
	}
	if runErr != nil {
		if runCtx.Err() != nil && ctx.Err() == nil {
			// The command outlived its timeout. Its partial output is
			// the useful part of the answer, so this is a result, not
			// an error.
			result.TimedOut = true
			result.ExitCode = -1
			return result, nil
		}
		return nil, runErr
	}
	return result, nil
}

// Stop ends a session: shutdown sentinel (fast path), then condor_rm
// (the one that works whether or not we are attached).
func (m *Manager) Stop(ctx context.Context, caller Caller, name string) (*Info, error) {
	if !caller.valid() {
		return nil, fmt.Errorf("authentication required")
	}
	if err := ValidateSessionName(name); err != nil {
		return nil, err
	}
	info, err := m.lookup(ctx, caller, name)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	sess := m.sessions[sessionKey(caller.Owner, name)]
	var shell Shell
	if sess != nil {
		shell = sess.shell
	}
	m.mu.Unlock()

	if shell != nil {
		// Best effort: the watchdog sees the sentinel within one poll
		// interval, which beats waiting for the schedd to act.
		shutdownCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if _, err := shell.Run(shutdownCtx, ShutdownCmd, discard{}, discard{}); err != nil {
			m.log().Debug(m.opts.LogDest, "interactive session shutdown sentinel failed",
				"session", name, "owner", caller.Owner, "error", err)
		}
		cancel()
	}

	m.forget(caller.Owner, name, "stopped by caller")
	m.removeJob(ctx, caller, info.ClusterID, info.ProcID, "Interactive session stopped")

	info.Status = "stopping"
	return info, nil
}

// Close stops every heartbeat and drops every attached shell. It
// deliberately does NOT remove the jobs: a restarting API server should
// find its sessions still there and re-adopt them. The watchdog's
// freshness window is what reclaims them if the restart never happens.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	// Take what has to be torn down while holding the lock -- the
	// fields belong to it, and a heartbeat goroutine may be reading
	// them right now.
	type teardown struct {
		stop  chan struct{}
		shell Shell
	}
	pending := make([]teardown, 0, len(m.sessions))
	for _, sess := range m.sessions {
		pending = append(pending, teardown{stop: sess.stopHeartbeat, shell: sess.shell})
		sess.stopHeartbeat = nil
		sess.shell = nil
		sess.heartbeatOn = false
	}
	m.sessions = map[string]*session{}
	m.mu.Unlock()

	for _, p := range pending {
		if p.stop != nil {
			close(p.stop)
		}
		// Closing the connection is also what unblocks a heartbeat
		// mid-command, so shutdown does not wait out its timeout.
		if p.shell != nil {
			_ = p.shell.Close()
		}
	}
	m.wg.Wait()
}
