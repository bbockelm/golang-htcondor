//go:build linux

package droppriv

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// credentialSysProcAttr builds a SysProcAttr that launches the child under the
// target identity. This requires the parent to be privileged. NoSetGroups is
// left false so the kernel resets supplementary groups to the target's primary
// group rather than inheriting the parent's.
func credentialSysProcAttr(id Identity) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:         id.UID,
			Gid:         id.GID,
			NoSetGroups: false,
		},
	}
}

// setChildPdeathsig requests SIGKILL be delivered to a launched child if this
// (helper) process dies, so a launched command is never orphaned.
func setChildPdeathsig(attr *syscall.SysProcAttr) {
	attr.Pdeathsig = syscall.SIGKILL
}

// helperSetParentDeathSignal asks the kernel to SIGKILL this helper if its
// parent (the pool) dies. Set after any credential switch so the switch does
// not clear it via the dumpable-flag reset.
func helperSetParentDeathSignal() {
	// Best effort; EOF on the control socket is the portable backstop.
	_ = unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0)
}

// switchHelperCredentials permanently drops this helper to the target identity:
// setgroups to the primary group, then setgid, then setuid. On Go 1.16+ these
// syscall wrappers apply to every OS thread in the process.
func switchHelperCredentials(id Identity) error {
	if err := syscall.Setgroups([]int{int(id.GID)}); err != nil {
		return fmt.Errorf("setgroups(%d): %w", id.GID, err)
	}
	if err := syscall.Setgid(int(id.GID)); err != nil {
		return fmt.Errorf("setgid(%d): %w", id.GID, err)
	}
	if err := syscall.Setuid(int(id.UID)); err != nil {
		return fmt.Errorf("setuid(%d): %w", id.UID, err)
	}
	return nil
}
