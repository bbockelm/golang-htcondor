package jobssh

import (
	"context"
	"errors"

	"golang.org/x/crypto/ssh"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// Compile-time check that an *ssh.Client is a Conn. It is, and the
// interface exists only so the cache can be tested without a pool.
var _ Conn = (*ssh.Client)(nil)

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
		return openJobShell(ctx, schedd, key.Cluster, key.Proc, &htcondor.JobShellOptions{CCB: ccb})
	}
}

// openJobShell is the indirection that lets a test see what the dialer
// asks for. Which CCB mode it picks is otherwise invisible without a
// live starter behind a real broker -- and reaching the wire is the
// whole point of the call.
var openJobShell = func(ctx context.Context, schedd *htcondor.Schedd, cluster, proc int, opts *htcondor.JobShellOptions) (*ssh.Client, error) {
	return schedd.OpenJobShell(ctx, cluster, proc, opts)
}
