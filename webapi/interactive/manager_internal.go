package interactive

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// HTCondor JobStatus values, named where this package uses them.
const (
	jobStatusIdle      = 1
	jobStatusRunning   = 2
	jobStatusRemoved   = 3
	jobStatusCompleted = 4
	jobStatusHeld      = 5

	// holdReasonSpoolingInput is the hold a job sits in between
	// SubmitRemote and the end of spooling. It is not a failure: the
	// submit path puts every spooled job here and takes it out again a
	// moment later, so a session seen in this state is still starting.
	holdReasonSpoolingInput = 16
)

func statusText(status, holdCode int) string {
	switch status {
	case jobStatusIdle:
		return "starting"
	case jobStatusRunning:
		return "ready"
	case jobStatusRemoved:
		return "removed"
	case jobStatusCompleted:
		return "ended"
	case jobStatusHeld:
		if holdCode == holdReasonSpoolingInput {
			return "starting"
		}
		return "held"
	default:
		return fmt.Sprintf("unknown (JobStatus=%d)", status)
	}
}

func jobIDOf(cluster, proc int) string { return fmt.Sprintf("%d.%d", cluster, proc) }

// sessionAdAttrs is what a session lookup needs off the job ad.
var sessionAdAttrs = []string{
	"ClusterId", "ProcId", "JobStatus", "JobBatchName", "Owner",
	"QDate", "HoldReason", "HoldReasonCode", "JobCurrentStartExecutingDate",
}

// liveSessionClause restricts a lookup to jobs that could still be a
// usable session. Completed and removed jobs linger in the queue —
// long enough, on a busy pool, that a name would otherwise resolve to
// a session that ended an hour ago.
const liveSessionClause = `(JobStatus == 1 || JobStatus == 2 || JobStatus == 5)`

// listAds queries the caller's live interactive sessions. A non-empty
// name asks for that one session.
//
// The batch-name filter is applied by the SCHEDD, not here. Filtering
// client-side would mean fetching the caller's whole queue and keeping
// the few rows that are sessions -- which on an access point where
// someone has ten thousand jobs quietly stops finding their session at
// all once the row limit is reached.
//
// Confinement is this daemon's, not the schedd's. FetchMyJobs sounds
// like a server-side check and is not: it sets Me to the owner string
// the client supplied and asks the schedd to match Owner == Me, so
// both it and the constraint below confine the query to the same name
// this process chose. What makes that name trustworthy is upstream --
// the transport resolved the caller's identity before the owner was
// derived from it -- so the filters must be built from that identity
// and never from anything the caller can set directly.
func (m *Manager) listAds(ctx context.Context, caller Caller, name string) ([]Info, error) {
	schedd := m.opts.Schedd()
	if schedd == nil {
		return nil, fmt.Errorf("no schedd configured")
	}

	var batchClause string
	if name != "" {
		batchClause = fmt.Sprintf("JobBatchName == %q", BatchNameForSession(name))
	} else {
		// The prefix is a literal with no regexp metacharacters in it
		// (ValidateSessionName guarantees the same for the name), so
		// the pattern needs no escaping.
		batchClause = fmt.Sprintf("regexp(%q, JobBatchName)", "^"+SessionBatchPrefix)
	}
	constraint := fmt.Sprintf(`Owner == %q && %s && %s`, caller.Owner, liveSessionClause, batchClause)

	ads, _, err := schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: sessionAdAttrs,
		Limit:      500,
		FetchOpts:  htcondor.FetchMyJobs,
		Owner:      caller.Owner,
	})
	if err != nil {
		return nil, fmt.Errorf("schedd query failed: %w", err)
	}

	out := make([]Info, 0, len(ads))
	for _, ad := range ads {
		// The constraint already asked for these, but a schedd that
		// ignored part of it must not widen what we return: filter
		// again on the two things that define a session.
		batchName, _ := ad.EvaluateAttrString("JobBatchName")
		sessionName, ok := SessionNameFromBatchName(batchName)
		if !ok || (name != "" && sessionName != name) {
			continue
		}
		if owner, ok := ad.EvaluateAttrString("Owner"); ok && owner != caller.Owner {
			continue
		}
		cluster, _ := ad.EvaluateAttrInt("ClusterId")
		proc, _ := ad.EvaluateAttrInt("ProcId")
		status, _ := ad.EvaluateAttrInt("JobStatus")
		holdReason, _ := ad.EvaluateAttrString("HoldReason")
		holdCode, _ := ad.EvaluateAttrInt("HoldReasonCode")
		qdate, _ := ad.EvaluateAttrInt("QDate")

		info := Info{
			Name:           sessionName,
			JobID:          jobIDOf(int(cluster), int(proc)),
			ClusterID:      int(cluster),
			ProcID:         int(proc),
			JobStatus:      int(status),
			Status:         statusText(int(status), int(holdCode)),
			HoldReason:     holdReason,
			HoldReasonCode: int(holdCode),
		}
		if int(holdCode) == holdReasonSpoolingInput {
			// Reported as "starting", so the hold text goes with it. A
			// caller shown status=starting next to hold_reason="Spooling
			// input data files" reasonably concludes something is wrong;
			// nothing is.
			info.HoldReason = ""
		}
		if qdate > 0 {
			info.SubmittedAt = time.Unix(qdate, 0).UTC()
		}
		out = append(out, info)
	}
	return out, nil
}

// lookup resolves a session name to its job, adopting it into this
// process if the name is live in the queue but unknown here (a fresh
// process, or one that restarted since the session was created).
func (m *Manager) lookup(ctx context.Context, caller Caller, name string) (*Info, error) {
	infos, err := m.listAds(ctx, caller, name)
	if err != nil {
		return nil, err
	}
	// Two jobs can answer to one name only if two Creates raced past
	// each other's duplicate check. The first is used and the second
	// is left to its lease; log it, because a name that is not unique
	// makes every later answer about "that session" ambiguous.
	if matches := countNamed(infos, name); matches > 1 {
		m.log().Warn(m.opts.LogDest, "interactive session name is ambiguous",
			"session", name, "owner", caller.Owner, "jobs", matches)
	}
	for i := range infos {
		if infos[i].Name != name {
			continue
		}
		info := infos[i]
		m.adopt(ctx, caller, &info)
		m.mu.Lock()
		if sess, ok := m.sessions[sessionKey(caller.Owner, name)]; ok {
			info.LeaseExpires = sess.leaseExpires
			info.Attached = sess.shell != nil
		}
		m.mu.Unlock()
		return &info, nil
	}
	// The name resolves to nothing live, so any entry still held for it
	// describes a job that is gone -- reclaimed by its watchdog, removed
	// from outside, or finished. Drop it: otherwise the map grows for
	// the daemon's lifetime, and the stale entry is what lets a later
	// Create collide with a heartbeat goroutine that outlived its job.
	m.forgetNamed(caller.Owner, name, "no live job answers to this name")
	return nil, fmt.Errorf("no interactive session named %q (it may have ended; start a new one)", name)
}

// sessionFor returns the session currently registered under a name.
func (m *Manager) sessionFor(owner, name string) *session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[sessionKey(owner, name)]
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// combineRequirements ANDs the operator's Requirements with the
// caller's. The operator's is not optional: a caller narrowing where
// their session runs must not be able to widen it past what the site
// allows, so both apply and neither replaces the other.
func combineRequirements(operator, caller string) string {
	operator = strings.TrimSpace(operator)
	caller = strings.TrimSpace(caller)
	switch {
	case operator == "":
		return caller
	case caller == "":
		return operator
	default:
		return fmt.Sprintf("(%s) && (%s)", operator, caller)
	}
}

func countNamed(infos []Info, name string) int {
	n := 0
	for i := range infos {
		if infos[i].Name == name {
			n++
		}
	}
	return n
}

// adopt makes sure this process has a lease entry for a session that
// exists in the queue. Idempotent.
func (m *Manager) adopt(ctx context.Context, caller Caller, info *Info) {
	key := sessionKey(caller.Owner, info.Name)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	sess, ok := m.sessions[key]
	if !ok {
		sess = &session{
			name:         info.Name,
			owner:        caller.Owner,
			cluster:      info.ClusterID,
			proc:         info.ProcID,
			leaseExpires: m.opts.Now().Add(m.opts.DefaultLease),
		}
		m.sessions[key] = sess
		m.log().Info(m.opts.LogDest, "interactive session adopted",
			"session", info.Name, "owner", caller.Owner, "job_id", info.JobID)
	}
	// The job can come back on a different cluster only by being
	// resubmitted, but keeping these in sync costs nothing and a stale
	// pair would have us dial the wrong sandbox.
	sess.cluster = info.ClusterID
	sess.proc = info.ProcID
	if sc := securityConfigFrom(ctx); sc != nil {
		sess.secConfig = sc
	}
}

// waitForRunning resolves the session and waits for its job to reach
// Running, polling the schedd. A held job is a terminal answer: it
// will not start on its own, and the hold reason is what the caller
// needs to see.
func (m *Manager) waitForRunning(ctx context.Context, caller Caller, name string, wait time.Duration) (*Info, error) {
	deadline := m.opts.Now().Add(wait)
	// Back off as the wait drags on. A session that starts quickly is
	// noticed within a couple of seconds; one that is genuinely queued
	// behind the pool should not cost the schedd a query every two
	// seconds for the next quarter hour.
	pollInterval := 2 * time.Second
	const maxPollInterval = 15 * time.Second
	for {
		info, err := m.lookup(ctx, caller, name)
		if err != nil {
			return nil, err
		}
		switch info.JobStatus {
		case jobStatusRunning:
			return info, nil
		case jobStatusHeld:
			if info.HoldReasonCode == holdReasonSpoolingInput {
				// Still finishing the submit that created it: the
				// spooling hold is part of starting, not a failure.
				break
			}
			reason := info.HoldReason
			if reason == "" {
				reason = "no reason reported"
			}
			return nil, fmt.Errorf("session %q is held and will not start: %s", name, reason)
		}
		if !m.opts.Now().Before(deadline) {
			return nil, fmt.Errorf("session %q is still %s after %s; it is waiting for a slot in the pool — retry, or check the queue",
				name, info.Status, wait)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
		if pollInterval < maxPollInterval {
			pollInterval *= 2
		}
	}
}

// attach returns a live Shell for the session, dialing one if this
// process does not already hold it, and starts the heartbeat.
func (m *Manager) attach(ctx context.Context, caller Caller, info *Info) (Shell, error) {
	key := sessionKey(caller.Owner, info.Name)

	m.mu.Lock()
	sess, ok := m.sessions[key]
	if !ok || m.closed {
		m.mu.Unlock()
		return nil, fmt.Errorf("session %q is no longer tracked", info.Name)
	}
	if sess.shell != nil {
		shell := sess.shell
		m.mu.Unlock()
		return shell, nil
	}
	m.mu.Unlock()

	// Dial outside the lock: it is a CEDAR handshake plus an sshd
	// spawn inside the sandbox, which is far too long to hold a mutex
	// every other session shares.
	shell, err := m.opts.Dial(ctx, info.ClusterID, info.ProcID)
	if err != nil {
		return nil, fmt.Errorf("connect to session %q (job %s): %w", info.Name, info.JobID, err)
	}

	m.mu.Lock()
	sess, ok = m.sessions[key]
	if !ok || m.closed {
		m.mu.Unlock()
		_ = shell.Close()
		return nil, fmt.Errorf("session %q was stopped while connecting", info.Name)
	}
	if sess.shell != nil {
		// Another call dialed while we were. Keep theirs; two clients
		// into one sandbox means two sshd processes and two heartbeat
		// loops.
		existing := sess.shell
		m.mu.Unlock()
		_ = shell.Close()
		return existing, nil
	}
	sess.shell = shell
	if sc := securityConfigFrom(ctx); sc != nil {
		sess.secConfig = sc
	}
	m.startHeartbeatLocked(sess)
	m.mu.Unlock()

	m.log().Info(m.opts.LogDest, "interactive session attached",
		"session", info.Name, "owner", caller.Owner, "job_id", info.JobID)
	return shell, nil
}

// startHeartbeatLocked launches the heartbeat loop for a session.
// Caller holds m.mu.
func (m *Manager) startHeartbeatLocked(sess *session) {
	if sess.heartbeatOn {
		return
	}
	sess.heartbeatOn = true
	stop := make(chan struct{})
	sess.stopHeartbeat = stop
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.heartbeatLoop(sess, stop)
	}()
}

// heartbeatLoop touches the heartbeat file until the lease runs out.
//
// Note what is NOT here: any test of whether the caller has been
// "active recently". The lease is that test. The browser terminal's
// version of this loop gated each beat on a recent keystroke, which
// meant a user who read output for two minutes lost their shell —
// under MCP, where an agent routinely thinks for minutes between
// calls, that gate would end every session.
func (m *Manager) heartbeatLoop(sess *session, stop chan struct{}) {
	ticker := time.NewTicker(m.opts.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-m.done:
			// The manager is shutting down. Whether or not this
			// session is still the one registered under its name,
			// this goroutine has to end.
			return
		case <-ticker.C:
		}

		m.mu.Lock()
		shell := sess.shell
		expires := sess.leaseExpires
		inFlight := sess.running
		cluster, proc := sess.cluster, sess.proc
		m.mu.Unlock()

		if shell == nil {
			return
		}
		// A command in flight holds the session open past its lease:
		// reclaiming it here would condor_rm the job out from under
		// work that is still running.
		if inFlight == 0 && !m.opts.Now().Before(expires) {
			m.log().Info(m.opts.LogDest, "interactive session lease expired",
				"session", sess.name, "owner", sess.owner,
				"job_id", jobIDOf(cluster, proc))
			m.expire(sess)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := shell.Run(ctx, HeartbeatCmd, discard{}, discard{})
		cancel()
		if err != nil {
			// Logged at Warn, not Debug. A heartbeat that silently
			// stopped working presents to the user as "my session
			// vanished a couple of minutes in" with nothing in the
			// log at default level to say why.
			m.log().Warn(m.opts.LogDest, "interactive session heartbeat failed",
				"session", sess.name, "owner", sess.owner,
				"job_id", jobIDOf(cluster, proc), "error", err)
			m.detach(sess, "heartbeat failed")
			return
		}
	}
}

// expire ends a session whose lease ran out: sentinel, then remove.
func (m *Manager) expire(sess *session) {
	m.mu.Lock()
	shell := sess.shell
	secConfig := sess.secConfig
	cluster, proc := sess.cluster, sess.proc
	owner, name := sess.owner, sess.name
	m.mu.Unlock()

	if shell != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if _, err := shell.Run(ctx, ShutdownCmd, discard{}, discard{}); err != nil {
			m.log().Debug(m.opts.LogDest, "interactive session expiry sentinel failed",
				"session", name, "owner", owner, "error", err)
		}
		cancel()
	}
	m.forget(sess, "lease expired")

	// condor_rm as well as the sentinel: the sentinel only works if we
	// are still attached, and an expired session is exactly the case
	// where we might not be.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if secConfig != nil {
		ctx = htcondor.WithSecurityConfig(ctx, secConfig)
	}
	m.removeJob(ctx, Caller{Actor: owner, Owner: owner}, cluster, proc, "Interactive session lease expired")
}

// detach drops this process's connection to a session without ending
// the session itself. The next call that names it dials again.
//
// It is keyed on the session VALUE. Addressing it by (owner, name) meant
// a goroutine that had already been superseded -- the heartbeat of a
// connection Exec's retry path had just replaced -- closed whatever now
// answered to that name, which was the freshly dialed shell the retry
// was running its command on.
func (m *Manager) detach(sess *session, why string) {
	m.mu.Lock()
	current, ok := m.sessions[sessionKey(sess.owner, sess.name)]
	if !ok || current != sess {
		m.mu.Unlock()
		return
	}
	shell := sess.shell
	sess.shell = nil
	if sess.stopHeartbeat != nil {
		close(sess.stopHeartbeat)
		sess.stopHeartbeat = nil
	}
	sess.heartbeatOn = false
	m.mu.Unlock()

	if shell != nil {
		_ = shell.Close()
	}
	m.log().Debug(m.opts.LogDest, "interactive session detached",
		"session", sess.name, "owner", sess.owner, "reason", why)
}

// forget drops a session from this process entirely. Like detach, it is
// keyed on the session value so a stale holder cannot evict its
// successor.
func (m *Manager) forget(sess *session, why string) {
	key := sessionKey(sess.owner, sess.name)
	m.mu.Lock()
	current, ok := m.sessions[key]
	if !ok || current != sess {
		m.mu.Unlock()
		return
	}
	delete(m.sessions, key)
	shell := sess.shell
	sess.shell = nil
	if sess.stopHeartbeat != nil {
		close(sess.stopHeartbeat)
		sess.stopHeartbeat = nil
	}
	sess.heartbeatOn = false
	m.mu.Unlock()

	if shell != nil {
		_ = shell.Close()
	}
	m.log().Info(m.opts.LogDest, "interactive session released",
		"session", sess.name, "owner", sess.owner, "reason", why)
}

// forgetNamed drops whatever session currently answers to a name.
func (m *Manager) forgetNamed(owner, name, why string) {
	m.mu.Lock()
	sess, ok := m.sessions[sessionKey(owner, name)]
	m.mu.Unlock()
	if !ok {
		return
	}
	m.forget(sess, why)
}

// extendLease pushes a session's expiry out by ITS lease duration and
// returns the new expiry. Every call that names a session extends it:
// that is the whole liveness signal.
func (m *Manager) extendLease(owner, name string) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionKey(owner, name)]
	if !ok {
		return time.Time{}
	}
	m.extendLeaseLocked(sess)
	return sess.leaseExpires
}

func (m *Manager) extendLeaseLocked(sess *session) {
	d := sess.leaseDuration
	if d <= 0 {
		d = m.opts.DefaultLease
	}
	sess.leaseExpires = m.opts.Now().Add(d)
}

// beginCommand marks a command in flight on a session and extends its
// lease, reporting false when the session is no longer tracked.
func (m *Manager) beginCommand(owner, name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionKey(owner, name)]
	if !ok {
		return false
	}
	sess.running++
	m.extendLeaseLocked(sess)
	return true
}

// endCommand releases the in-flight mark and extends the lease again,
// so the countdown runs from when the command finished rather than from
// when it started.
func (m *Manager) endCommand(owner, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionKey(owner, name)]
	if !ok {
		return
	}
	if sess.running > 0 {
		sess.running--
	}
	m.extendLeaseLocked(sess)
}

func (m *Manager) clampLease(requested time.Duration) time.Duration {
	if requested <= 0 {
		return m.opts.DefaultLease
	}
	if requested > m.opts.MaxLease {
		return m.opts.MaxLease
	}
	return requested
}

// removeJob issues a condor_rm for one job. Best effort: every caller
// has already done the thing that matters (dropped the sentinel, or
// given up on the session), and a failure here costs a slot that the
// watchdog reclaims on its own.
func (m *Manager) removeJob(ctx context.Context, caller Caller, cluster, proc int, reason string) {
	schedd := m.opts.Schedd()
	if schedd == nil {
		return
	}
	constraint := fmt.Sprintf(`ClusterId == %d && ProcId == %d && Owner == %q`, cluster, proc, caller.Owner)
	if _, err := schedd.RemoveJobs(ctx, constraint, reason); err != nil {
		m.log().Warn(m.opts.LogDest, "interactive session condor_rm failed",
			"owner", caller.Owner, "job_id", jobIDOf(cluster, proc), "error", err)
	}
}

// securityConfigFrom copies the caller's credential off a request
// context so background work can reuse it. Returns nil when the host
// runs as the user (the stdio server), where no credential is carried
// on the context in the first place.
func securityConfigFrom(ctx context.Context) *security.SecurityConfig {
	if ctx == nil {
		return nil
	}
	sc, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if !ok {
		return nil
	}
	copied := sc
	return &copied
}

func applySpecDefaults(spec *CreateSpec) {
	if spec.Cpus == 0 {
		spec.Cpus = 1
	}
	if spec.MemoryMB == 0 {
		spec.MemoryMB = 1024
	}
	if spec.DiskMB == 0 {
		spec.DiskMB = 1024
	}
}

// validateSpec bounds the resource request. Same limits as the REST
// interactive surface: these jobs sit idle holding whatever they asked
// for, so an accidental zero or an agent's optimistic "give me 512 GB"
// should fail here rather than in the negotiator.
func validateSpec(spec CreateSpec) error {
	if spec.Cpus < 1 || spec.Cpus > 64 {
		return fmt.Errorf("cpus must be between 1 and 64, got %d", spec.Cpus)
	}
	if spec.MemoryMB < 256 || spec.MemoryMB > 256*1024 {
		return fmt.Errorf("memory_mb must be between 256 and %d, got %d", 256*1024, spec.MemoryMB)
	}
	if spec.DiskMB < 256 || spec.DiskMB > 1024*1024 {
		return fmt.Errorf("disk_mb must be between 256 and %d, got %d", 1024*1024, spec.DiskMB)
	}
	if spec.Gpus < 0 || spec.Gpus > 16 {
		return fmt.Errorf("gpus must be between 0 and 16, got %d", spec.Gpus)
	}
	// A caller's Requirements must parse: the operator's own Requirements
	// and submit policy land in the same file, and an expression that
	// does not parse takes them down with it. Parsing here also names
	// the offending expression instead of leaving a schedd transaction
	// failure to interpret.
	if req := strings.TrimSpace(spec.Requirements); req != "" {
		if _, err := classad.ParseExpr(req); err != nil {
			return fmt.Errorf("requirements %q is not a valid ClassAd expression: %w", req, err)
		}
	}
	if err := ValidateCallerSubmitLines(spec.SubmitLines); err != nil {
		return fmt.Errorf("submit_lines: %w", err)
	}

	// The GPU strings are concatenated raw into the submit file, so a
	// value containing a newline would inject arbitrary submit
	// directives. A caller could submit whatever they liked through
	// submit_job anyway — the point is that this tool's arguments mean
	// what they say.
	for _, s := range []string{spec.GpusMinimumCapability, spec.GpusMinimumRuntime, spec.CudaVersion, spec.RequireGpus} {
		if strings.ContainsAny(s, "\n\r") {
			return fmt.Errorf("GPU request fields may not contain newlines")
		}
	}
	return nil
}
