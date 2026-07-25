package droppriv

import (
	"os/exec"
	"strings"
)

// StartAsUser starts cmd with the child process running as userName (its uid/gid) -- so a daemon
// can launch a supervised subprocess under an unprivileged account (e.g. "nobody"). It reuses
// the package's per-thread root elevation: only the forking thread briefly regains root, just
// long enough for the child to setuid to the target user, then the thread's credentials are
// restored. The rest of the process never runs as root.
//
// It starts cmd as the current user (no drop) when userName is "" or when the process is not
// privileged to change the child's user (a development/unprivileged run). "root" and "condor"
// are rejected (validateUsername) -- use the manager's own facilities for those.
//
// The caller sets everything else on cmd (Args, Env, Stdin/out/err, Dir) as usual; StartAsUser
// only sets SysProcAttr.Credential. cmd.Wait is the caller's responsibility.
func (m *Manager) StartAsUser(userName string, cmd *exec.Cmd) error {
	if strings.TrimSpace(userName) == "" {
		return cmd.Start()
	}
	if err := validateUsername(userName); err != nil {
		return err
	}
	target, err := m.resolveUser(userName)
	if err != nil {
		return err
	}
	return startAsUser(target, cmd)
}

// StartAsUser is the package-level helper delegating to the default Manager.
func StartAsUser(userName string, cmd *exec.Cmd) error {
	return DefaultManager().StartAsUser(userName, cmd)
}
