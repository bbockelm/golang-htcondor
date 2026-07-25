//go:build linux

package droppriv

import (
	"os/exec"
	"runtime"
	"syscall"
)

// startAsUser starts cmd with the child dropped to target. It elevates euid to 0 on ONLY the
// forking (locked) OS thread across the fork -- exactly as withRoot does for in-process work --
// so the child inherits the privilege to setuid/setgid to target, then the thread's credentials
// are restored. If the process cannot regain root (unprivileged run), cmd is started as the
// current user (best effort), matching withRoot's fallback.
func startAsUser(target Identity, cmd *exec.Cmd) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	state, err := captureThreadCredentials()
	if err != nil {
		return cmd.Start() // cannot inspect thread credentials: run as the current user
	}
	if err := elevateToRoot(state); err != nil {
		_ = restoreThreadCredentials(state)
		return cmd.Start() // not privileged to regain root: run as the current user
	}
	setChildCredential(cmd, target)
	startErr := cmd.Start()
	restoreErr := restoreThreadCredentials(state)
	if startErr != nil {
		return startErr
	}
	return restoreErr
}

// setChildCredential makes the forked child setgid/setuid to target before exec. Leaving
// Credential.Groups nil with NoSetGroups false makes the child also drop supplementary groups
// (setgroups to the empty set), so it runs with exactly target's uid/gid.
func setChildCredential(cmd *exec.Cmd, target Identity) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: target.UID, Gid: target.GID}
}
