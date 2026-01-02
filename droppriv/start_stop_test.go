package droppriv

import (
	"os"
	"runtime"
	"testing"
)

// TestStartStop tests the Start/Stop cycle without requiring root.
func TestStartStop(t *testing.T) {
	conf := Config{
		Enabled: false, // disabled so it doesn't try to actually drop
	}

	mgr, err := NewManager(conf)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Start with disabled manager should be no-op
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Stop with disabled manager should be no-op
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

// TestStartStopEnabled tests that enabled managers on Linux require root.
func TestStartStopEnabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Test only applicable on Linux")
	}

	if os.Geteuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	conf := Config{
		Enabled:    true,
		CondorUser: "nobody",
	}

	mgr, err := NewManager(conf)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Should still be root after NewManager
	if os.Geteuid() != 0 {
		t.Fatalf("Expected to still be root after NewManager, got euid=%d", os.Geteuid())
	}

	// Start should drop privileges
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Should now be running as nobody
	if os.Geteuid() == 0 {
		t.Fatalf("Expected to drop privileges after Start, still running as root")
	}

	droppedUID := os.Geteuid()

	// Stop should restore privileges
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Should be back to root
	if os.Geteuid() != 0 {
		t.Fatalf("Expected to restore root privileges after Stop, got euid=%d", os.Geteuid())
	}

	t.Logf("Successfully dropped to uid=%d and restored to root", droppedUID)
}
