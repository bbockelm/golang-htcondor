//go:build !linux

package droppriv

import "os/exec"

// startAsUser on non-Linux platforms starts cmd as the current user; setuid-to-user launching
// relies on the Linux privilege model the daemon runs under in production.
func startAsUser(_ Identity, cmd *exec.Cmd) error {
	return cmd.Start()
}
