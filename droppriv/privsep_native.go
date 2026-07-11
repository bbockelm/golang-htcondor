package droppriv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// nativePrivsep is the in-process backend. Filesystem operations reuse the
// Manager's per-thread credential switching (runAsUser via withUser); process
// launch uses exec.Cmd with SysProcAttr.Credential. It can only actually switch
// credentials when the process is privileged; when the Manager is disabled or
// the user is "", operations simply run as the current user in-process, exactly
// as the older Manager helpers did.
type nativePrivsep struct {
	mgr *Manager
}

var _ Privsep = (*nativePrivsep)(nil)

func (n *nativePrivsep) OpenFile(_ context.Context, user, path string, flag int, perm os.FileMode) (*os.File, error) {
	return n.mgr.OpenFile(user, path, flag, perm)
}

func (n *nativePrivsep) MkdirAll(_ context.Context, user, path string, perm os.FileMode) error {
	return n.mgr.MkdirAll(user, path, perm)
}

func (n *nativePrivsep) Chown(_ context.Context, user, path string, uid, gid int) error {
	return n.mgr.Chown(user, path, uid, gid)
}

func (n *nativePrivsep) Stat(_ context.Context, user, path string) (os.FileInfo, error) {
	var fi os.FileInfo
	err := n.mgr.withUser(user, func() error {
		var e error
		fi, e = os.Stat(path)
		return e
	})
	return fi, err
}

func (n *nativePrivsep) Remove(_ context.Context, user, path string) error {
	return n.mgr.withUser(user, func() error {
		return os.Remove(path)
	})
}

func (n *nativePrivsep) Rename(_ context.Context, user, oldpath, newpath string) error {
	return n.mgr.withUser(user, func() error {
		return os.Rename(oldpath, newpath)
	})
}

// Command launches spec as the user using exec.Cmd. When a credential switch is
// required (a non-empty user that resolves to a different identity and the
// Manager is enabled) SysProcAttr.Credential is set, which requires the parent
// to be privileged. Otherwise the child runs as the current user.
func (n *nativePrivsep) Command(ctx context.Context, user string, spec CommandSpec) (Process, error) {
	if err := validateUsername(user); err != nil {
		return nil, err
	}

	//nolint:gosec // G204 - the executable and arguments are supplied by the trusted schedd/shadow caller, not external input.
	cmd := exec.CommandContext(ctx, spec.Path, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = spec.Env
	cmd.Stdin = fileOrNil(spec.Stdin)
	cmd.Stdout = fileOrNil(spec.Stdout)
	cmd.Stderr = fileOrNil(spec.Stderr)

	if strings.TrimSpace(user) != "" && n.mgr.enabled {
		identity, err := n.mgr.resolveUser(user)
		if err != nil {
			return nil, err
		}
		cmd.SysProcAttr = credentialSysProcAttr(identity)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("droppriv: launching %q: %w", spec.Path, err)
	}
	return &nativeProcess{cmd: cmd}, nil
}

// Close is a no-op for the native backend: it owns no long-lived resources.
func (n *nativePrivsep) Close() error { return nil }

// fileOrNil avoids assigning a typed-nil *os.File into the io.Reader/Writer
// interface fields of exec.Cmd, which would otherwise be a non-nil interface
// wrapping a nil pointer and cause a panic when used.
func fileOrNil(f *os.File) *os.File {
	if f == nil {
		return nil
	}
	return f
}

// nativeProcess adapts *exec.Cmd to the Process interface.
type nativeProcess struct {
	cmd *exec.Cmd
}

func (p *nativeProcess) Wait() error {
	err := p.cmd.Wait()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return &ProcessExitError{Signaled: true, Signal: int(ws.Signal())}
			}
			return &ProcessExitError{Code: ws.ExitStatus()}
		}
	}
	return err
}

func (p *nativeProcess) Pid() int {
	if p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

func (p *nativeProcess) Signal(sig os.Signal) error {
	if p.cmd.Process == nil {
		return fmt.Errorf("droppriv: process not started")
	}
	return p.cmd.Process.Signal(sig)
}
