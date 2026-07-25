package droppriv

import (
	"errors"
	"testing"
)

// TestManagerRunAsCondorDisabled: a disabled manager (an unprivileged process) runs fn
// under the current identity and propagates its error, without attempting a switch.
func TestManagerRunAsCondorDisabled(t *testing.T) {
	ran := false
	if err := (&Manager{}).RunAsCondor(func() error { ran = true; return nil }); err != nil {
		t.Fatalf("RunAsCondor: %v", err)
	}
	if !ran {
		t.Error("fn should run when the manager is disabled")
	}

	boom := errors.New("boom")
	if err := (&Manager{}).RunAsCondor(func() error { return boom }); !errors.Is(err, boom) {
		t.Errorf("RunAsCondor error = %v, want boom", err)
	}
}
