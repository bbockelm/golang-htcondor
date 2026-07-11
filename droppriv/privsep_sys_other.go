//go:build !linux

package droppriv

import "syscall"

// credentialSysProcAttr builds a SysProcAttr that launches the child under the
// target identity. NoSetGroups is Linux-only, so it is omitted here; on
// non-Linux platforms the child inherits the parent's supplementary groups.
func credentialSysProcAttr(id Identity) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: id.UID,
			Gid: id.GID,
		},
	}
}

// setChildPdeathsig is a no-op: parent-death signals are a Linux feature. The
// helper relies on control-socket EOF instead.
func setChildPdeathsig(_ *syscall.SysProcAttr) {}

// helperSetParentDeathSignal is a no-op on non-Linux platforms; the helper
// exits on control-socket EOF instead.
func helperSetParentDeathSignal() {}

// switchHelperCredentials is unsupported on non-Linux platforms. The pool only
// calls it when a credential switch was requested, which auto mode never does
// off Linux; forced-unprivileged mode never switches.
func switchHelperCredentials(_ Identity) error {
	return ErrUnsupported
}
