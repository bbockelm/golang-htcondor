package interactive

import (
	"context"
	"fmt"
	"strings"
)

// RunInJob runs one command inside a job this manager does not own, and
// closes the connection when it returns.
//
// This is the other half of the exec surface. A SESSION is a job the
// manager submitted and keeps alive: it has a lease, a heartbeat, a
// registry entry and a watchdog, all of which exist because something
// has to decide when the job ends. None of that applies to a job that
// was already running -- its lifetime belongs to whoever submitted it,
// and the worst thing this could do is attach machinery that outlives
// the caller's interest and then acts on a job it does not own.
//
// So there is deliberately no connection cache here. Each call pays a
// CEDAR handshake and an sshd spawn inside the sandbox, which is real
// latency (order of a second) but leaves nothing behind: no goroutine
// watching a job that may end mid-command, no client to reap, no lease
// to expire against somebody else's work. A caller running many
// commands against the same machine should start a session instead,
// which is what that machinery is for.
//
// Ownership is NOT checked here. The schedd checks it -- it refuses
// GET_JOB_CONNECT_INFO for a job the caller does not own, and mints the
// starter session as the job's owner -- and the caller (see the MCP
// tool) checks it first so that somebody else's job id comes back "not
// found" rather than as a refusal that has already confirmed the job
// exists.
func (m *Manager) RunInJob(ctx context.Context, cluster, proc int, req ExecRequest) (*ExecResult, error) {
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

	shell, err := m.opts.Dial(ctx, cluster, proc)
	if err != nil {
		return nil, fmt.Errorf("connect to job %s: %w", jobIDOf(cluster, proc), err)
	}
	defer func() { _ = shell.Close() }()

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout := newCappedBuffer(m.opts.MaxOutputBytes)
	stderr := newCappedBuffer(m.opts.MaxOutputBytes)
	started := m.opts.Now()
	code, runErr := shell.Run(runCtx, req.Command, stdout, stderr)
	elapsed := m.opts.Now().Sub(started)

	result := &ExecResult{
		JobID:           jobIDOf(cluster, proc),
		ExitCode:        code,
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		StdoutTruncated: stdout.truncated(),
		StderrTruncated: stderr.truncated(),
		Duration:        elapsed,
		MaxOutputBytes:  m.opts.MaxOutputBytes,
	}
	if runErr != nil {
		// A command that outlived its timeout is a result: its partial
		// output is the useful part of the answer. Anything else failed
		// the dispatch, and there is nothing to retry against -- unlike
		// a session, this connection was never going to be reused.
		if runCtx.Err() != nil && ctx.Err() == nil {
			result.TimedOut = true
			result.ExitCode = -1
			return result, nil
		}
		return nil, runErr
	}
	return result, nil
}
