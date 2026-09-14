package interactive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"golang.org/x/crypto/ssh"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// Shell is one live connection into a running job's sandbox: the
// condor_ssh_to_job transport, already authenticated, with commands
// dispatched over it one at a time.
//
// It is an interface so the manager can be tested without a pool. The
// production implementation is sshShell; tests substitute a fake.
type Shell interface {
	// Run executes cmd inside the job and returns its exit status.
	// A non-zero exit status is NOT an error: it is the command's
	// answer, reported through the int. err is reserved for the
	// connection or the dispatch failing, which is what tells the
	// manager its Shell is no longer usable.
	Run(ctx context.Context, cmd string, stdout, stderr io.Writer) (int, error)
	Close() error
}

// errNotDispatched marks a failure that happened BEFORE the command
// began running — opening the SSH channel, or starting the process.
//
// The distinction decides whether retrying is safe. A command that
// never started can be retried on a fresh connection; a command that
// started and then lost its transport may have done half its work
// already, and running it again would repeat whatever it did. So the
// manager retries only what is marked here, and everything else is
// reported to the caller as-is.
var errNotDispatched = errors.New("command was not dispatched")

// Dialer opens a Shell into cluster.proc. The context carries the
// caller's credentials — see Manager.redialContext for why the manager
// keeps one around rather than taking whatever context is handy.
type Dialer func(ctx context.Context, cluster, proc int) (Shell, error)

// ScheddClient is the slice of the schedd API this package uses:
// submit a session job, spool its watchdog, find sessions, remove one.
// *htcondor.Schedd implements it.
//
// It exists so a test can drive the whole lease lifecycle — create,
// adopt, exec, expire — against a fake queue. The alternative is that
// none of that logic is covered except by an integration test needing
// a real pool, which is how the heartbeat this package replaces came
// to have no tests at all.
type ScheddClient interface {
	SubmitRemote(ctx context.Context, submitFileContent string) (int, []*classad.ClassAd, error)
	SpoolJobFilesFromFS(ctx context.Context, jobAds []*classad.ClassAd, fsys fs.FS) error
	QueryWithOptions(ctx context.Context, constraint string, opts *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error)
	RemoveJobs(ctx context.Context, constraint string, reason string) (*htcondor.JobActionResults, error)
}

// sshDialer returns a Dialer backed by condor_ssh_to_job over CEDAR.
//
// It needs the concrete schedd, not ScheddClient: OpenJobShell is the
// one operation here that is not part of the narrow interface, because
// nothing about it is faked in tests — the fake substitutes at the
// Dialer instead.
func sshDialer(scheddFn func() ScheddClient, ccbStreaming bool) Dialer {
	return func(ctx context.Context, cluster, proc int) (Shell, error) {
		schedd, ok := scheddFn().(*htcondor.Schedd)
		if !ok || schedd == nil {
			return nil, errors.New("condor_ssh_to_job needs a real schedd connection")
		}
		client, err := openJobShell(ctx, schedd, cluster, proc, &htcondor.JobShellOptions{
			CCBStreaming: ccbStreaming,
		})
		if err != nil {
			return nil, err
		}
		return &sshShell{client: client}, nil
	}
}

// openJobShell is the indirection that lets a test see what the dialer
// asks for. The options it passes decide whether a job behind CCB is
// reachable at all, and nothing short of a CCB pool exercises that --
// which is how the manager came to pass nil (dial back) while the REST
// terminal passed the operator's setting.
var openJobShell = func(ctx context.Context, schedd *htcondor.Schedd, cluster, proc int, opts *htcondor.JobShellOptions) (*ssh.Client, error) {
	return schedd.OpenJobShell(ctx, cluster, proc, opts)
}

// sshShell runs each command as its own SSH session on a shared
// client. Sessions are cheap once the transport is up; the expensive
// part is the CEDAR handshake behind the client, which is exactly what
// gets reused.
//
// Note what this does NOT provide: state between calls. Each Run gets
// a fresh shell whose cwd is the job's working directory, so `cd` in
// one call is not visible in the next. That is a deliberate trade —
// see the exec tool's description, which tells callers to chain with
// `&&` instead.
type sshShell struct {
	client *ssh.Client
}

func (s *sshShell) Run(ctx context.Context, cmd string, stdout, stderr io.Writer) (int, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return -1, fmt.Errorf("%w: open ssh session: %w", errNotDispatched, err)
	}
	defer func() { _ = sess.Close() }()

	sess.Stdout = stdout
	sess.Stderr = stderr

	if err := sess.Start(cmd); err != nil {
		return -1, fmt.Errorf("%w: start command: %w", errNotDispatched, err)
	}

	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	select {
	case err := <-done:
		return exitStatus(err)
	case <-ctx.Done():
		// Ask the remote process to die, then give Wait a moment to
		// reap it so the caller still gets whatever output was
		// produced before the deadline. The session Close in the
		// defer is what actually frees the channel if the signal does
		// not land.
		_ = sess.Signal(ssh.SIGKILL)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		return -1, ctx.Err()
	}
}

func (s *sshShell) Close() error { return s.client.Close() }

// exitStatus maps ssh.Session.Wait's error into an exit code. A
// command that exits non-zero reports an *ssh.ExitError, which is a
// result rather than a failure; anything else means the session itself
// went wrong and the Shell should be considered dead.
func exitStatus(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), nil
	}
	var missing *ssh.ExitMissingError
	if errors.As(err, &missing) {
		return -1, fmt.Errorf("command terminated without an exit status (the job may have ended): %w", err)
	}
	return -1, err
}
