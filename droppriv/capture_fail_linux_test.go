//go:build linux

package droppriv

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

// failCapture makes reading the thread's credentials fail for the rest
// of the test.
func failCapture(t *testing.T) {
	t.Helper()
	orig := captureCredentials
	captureCredentials = func() (threadCredentials, error) {
		return threadCredentials{}, errors.New("getresuid failed")
	}
	t.Cleanup(func() { captureCredentials = orig })
}

// When it cannot tell who the thread is, withRoot must not run the
// operation: it would happen as whoever that is instead of as root, and
// a write meant for root would land owned by the wrong account.
func TestWithRootRefusesUnreadableCredentials(t *testing.T) {
	failCapture(t)
	ran := false
	err := withRoot(func() error { ran = true; return nil })
	if err == nil {
		t.Error("withRoot returned nil with unreadable thread credentials")
	}
	if ran {
		t.Error("withRoot ran the operation with unreadable thread credentials")
	}
}

// The same for a launch: the child was meant to run as another user,
// and starting it as the current one could mean starting it as root.
func TestStartAsUserRefusesUnreadableCredentials(t *testing.T) {
	failCapture(t)
	cmd := exec.CommandContext(context.Background(), "true")
	if err := startAsUser(Identity{UID: 65534, GID: 65534}, cmd); err == nil {
		t.Error("startAsUser returned nil with unreadable thread credentials")
	}
	if cmd.Process != nil {
		_ = cmd.Wait()
		t.Error("startAsUser started the command with unreadable thread credentials")
	}
}
