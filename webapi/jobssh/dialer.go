package jobssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	htcondor "github.com/bbockelm/golang-htcondor"
)

var _ Conn = (*sshConn)(nil)

// sshConn is an *ssh.Client plus the one thing the cache needs that
// the client does not offer directly: running a command and collecting
// its output.
type sshConn struct{ *ssh.Client }

// Run executes cmd in the sandbox and returns its standard output.
//
// Note what the command has to survive: condor_ssh_to_job_shell_setup
// runs `eval ${SSH_ORIGINAL_COMMAND}` with the expansion unquoted, so
// the command is word-split on IFS -- newlines included -- and
// rejoined with spaces before eval re-parses it. A multi-line script
// arrives as one line. Keep callers to a single line.
func (c *sshConn) Run(ctx context.Context, cmd string) (string, error) {
	sess, err := c.NewSession()
	if err != nil {
		return "", fmt.Errorf("opening a session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	var out, stderr bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &stderr
	if err := sess.Start(cmd); err != nil {
		return "", fmt.Errorf("starting %q: %w", cmd, err)
	}

	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case werr := <-done:
		if werr != nil {
			return "", fmt.Errorf("%q failed: %w (stderr: %s)", cmd, werr, strings.TrimSpace(stderr.String()))
		}
		return out.String(), nil
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		return "", ctx.Err()
	}
}

// ScheddDialer returns a Dialer backed by condor_ssh_to_job over CEDAR.
//
// ccb decides how a starter behind a Connection Broker is reached. It
// matters: the default -- have the execute node dial back -- needs this
// process to be reachable from that node, which is not true of an API
// server in a container or behind NAT, and the attempt then times out
// with nothing to show for it. Callers on a pool host can pass nil.
func ScheddDialer(scheddFn func() *htcondor.Schedd, ccb *htcondor.CCBDialer) Dialer {
	return func(ctx context.Context, key Key) (Conn, error) {
		schedd := scheddFn()
		if schedd == nil {
			return nil, errors.New("no schedd configured; condor_ssh_to_job needs one")
		}
		client, err := openJobShell(ctx, schedd, key.Cluster, key.Proc, &htcondor.JobShellOptions{CCB: ccb})
		if err != nil {
			return nil, err
		}
		return &sshConn{Client: client}, nil
	}
}

// openJobShell is the indirection that lets a test see what the dialer
// asks for. Which CCB mode it picks is otherwise invisible without a
// live starter behind a real broker -- and reaching the wire is the
// whole point of the call.
var openJobShell = func(ctx context.Context, schedd *htcondor.Schedd, cluster, proc int, opts *htcondor.JobShellOptions) (*ssh.Client, error) {
	return schedd.OpenJobShell(ctx, cluster, proc, opts)
}
