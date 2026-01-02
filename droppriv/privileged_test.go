//go:build linux

package droppriv

import (
	"os"
	"syscall"
	"testing"
)

// TestStartStopPrivileges tests the Start/Stop cycle for privilege dropping.
// This test requires running as root and will be skipped otherwise.
func TestStartStopPrivileges(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// Create a manager with a non-root target user
	// Use nobody:nogroup which should exist on most Linux systems
	conf := Config{
		Enabled:    true,
		CondorUser: "nobody",
	}

	mgr, err := NewManager(conf)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Should still be running as root
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
	droppedGID := os.Getegid()

	// Stop should restore privileges
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Should be back to root
	if os.Geteuid() != 0 {
		t.Fatalf("Expected to restore root privileges after Stop, got euid=%d", os.Geteuid())
	}

	t.Logf("Successfully dropped to uid=%d gid=%d and restored to root", droppedUID, droppedGID)
}

// TestStartWithSpecificUIDs tests privilege dropping with explicit UID/GID.
// This test requires running as root and will be skipped otherwise.
func TestStartWithSpecificUIDs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	targetUID := uint32(65534) // nobody
	targetGID := uint32(65534) // nogroup

	conf := Config{
		Enabled: true,
		CondorIDs: &Identity{
			UID: targetUID,
			GID: targetGID,
		},
	}

	mgr, err := NewManager(conf)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	//nolint:gosec // G115 - test code, uid/gid conversion is safe
	if uint32(os.Geteuid()) != targetUID {
		t.Errorf("Expected euid=%d, got %d", targetUID, os.Geteuid())
	}

	//nolint:gosec // G115 - test code, uid/gid conversion is safe
	if uint32(os.Getegid()) != targetGID {
		t.Errorf("Expected egid=%d, got %d", targetGID, os.Getegid())
	}

	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if os.Geteuid() != 0 {
		t.Fatalf("Expected to restore root privileges, got euid=%d", os.Geteuid())
	}
}

// TestDisabledManagerNoPrivilegeDrop tests that disabled managers don't drop privileges.
func TestDisabledManagerNoPrivilegeDrop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	conf := Config{
		Enabled:    false,
		CondorUser: "nobody",
	}

	mgr, err := NewManager(conf)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	originalUID := os.Geteuid()

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Should still be at original UID
	if os.Geteuid() != originalUID {
		t.Errorf("Expected euid to remain %d, got %d", originalUID, os.Geteuid())
	}

	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

// TestMultipleStartStopCycles tests that Start/Stop can be called multiple times.
func TestMultipleStartStopCycles(t *testing.T) {
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

	for i := 0; i < 3; i++ {
		// Start
		if err := mgr.Start(); err != nil {
			t.Fatalf("Start cycle %d failed: %v", i, err)
		}

		if os.Geteuid() == 0 {
			t.Fatalf("Cycle %d: privileges not dropped", i)
		}

		// Stop
		if err := mgr.Stop(); err != nil {
			t.Fatalf("Stop cycle %d failed: %v", i, err)
		}

		if os.Geteuid() != 0 {
			t.Fatalf("Cycle %d: privileges not restored", i)
		}
	}
}

// TestTemporaryPrivilegeElevation tests that filesystem operations can temporarily elevate privileges.
func TestTemporaryPrivilegeElevation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// Use os.MkdirTemp for secure temp dir creation, then chmod for accessibility
	tempDir, err := os.MkdirTemp("", "droppriv_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to remove temp directory: %v", err)
		}
	}()
	// Make it accessible to dropped-privilege user (MkdirTemp creates 0700)
	//nolint:gosec // G302 - 0755 is appropriate for test temp directory
	if err = os.Chmod(tempDir, 0o755); err != nil {
		t.Fatalf("Failed to chmod temp dir: %v", err)
	}

	conf := Config{
		Enabled:    true,
		CondorUser: "nobody",
	}

	mgr, err := NewManager(conf)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() {
		if err := mgr.Stop(); err != nil {
			t.Logf("Failed to stop manager: %v", err)
		}
	}()

	droppedUID := os.Geteuid()
	if droppedUID == 0 {
		t.Fatalf("Expected privileges to be dropped")
	}

	// Test MkdirAll as root
	rootDir := tempDir + "/root_dir"
	if err := mgr.MkdirAll("root", rootDir, 0o755); err != nil {
		t.Fatalf("MkdirAll as root failed: %v", err)
	}

	// Verify privileges are still dropped
	if os.Geteuid() != droppedUID {
		t.Fatalf("Privileges changed after MkdirAll, expected %d got %d", droppedUID, os.Geteuid())
	}

	// Verify directory was created - need to elevate to root to stat it
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	info, err := os.Stat(rootDir)
	if err != nil {
		t.Fatalf("Failed to stat directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("Expected directory to be created")
	}
	// Restart to continue testing
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Create a work directory for nobody that's accessible
	// Create with proper permissions and chown to nobody
	nobodyWorkDir := tempDir + "/nobody_work"
	if err := mgr.MkdirAll("root", nobodyWorkDir, 0o755); err != nil {
		t.Fatalf("MkdirAll nobody work dir failed: %v", err)
	}
	// Chown to nobody so they can write to it
	if err := mgr.Chown("root", nobodyWorkDir, 65534, 65534); err != nil {
		t.Fatalf("Chown nobody work dir failed: %v", err)
	}

	// Test OpenFile to create a file as nobody in the accessible directory
	nobodyFile := nobodyWorkDir + "/file.txt"
	file, err := mgr.OpenFile("nobody", nobodyFile, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("OpenFile as nobody failed: %v", err)
	}
	if _, err := file.WriteString("test content\n"); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Failed to close file: %v", err)
	}

	// Verify file ownership - stop manager to stat as root
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	fileInfo, err := os.Stat(nobodyFile)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}
	fileStat := fileInfo.Sys().(*syscall.Stat_t)
	if fileStat.Uid != 65534 || fileStat.Gid != 65534 {
		t.Errorf("File ownership incorrect: expected uid=65534 gid=65534, got uid=%d gid=%d", fileStat.Uid, fileStat.Gid)
	}
	t.Logf("File correctly owned by nobody: uid=%d gid=%d", fileStat.Uid, fileStat.Gid)
	// Restart for remaining tests
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify privileges are still dropped
	if os.Geteuid() != droppedUID {
		t.Fatalf("Privileges changed after OpenFile, expected %d got %d", droppedUID, os.Geteuid())
	}

	// Test Open to read the file we just created
	readFile, err := mgr.Open("nobody", nobodyFile)
	if err != nil {
		t.Fatalf("Open as nobody failed: %v", err)
	}
	if err := readFile.Close(); err != nil {
		t.Fatalf("Failed to close file: %v", err)
	}

	// Verify privileges are still dropped
	if os.Geteuid() != droppedUID {
		t.Fatalf("Privileges changed after Open, expected %d got %d", droppedUID, os.Geteuid())
	}

	t.Logf("Successfully performed operations as root and nobody while maintaining dropped privileges")
}

// TestOperationFailsWithWrongUser tests that operations fail appropriately when user doesn't have permission.
func TestOperationFailsWithWrongUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	tempDir := t.TempDir()

	// Create a root-only directory before dropping privileges
	rootOnlyDir := tempDir + "/root_only"
	if err := os.Mkdir(rootOnlyDir, 0o700); err != nil {
		t.Fatalf("Failed to create root-only directory: %v", err)
	}

	conf := Config{
		Enabled:    true,
		CondorUser: "nobody",
	}

	mgr, err := NewManager(conf)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() {
		if err := mgr.Stop(); err != nil {
			t.Logf("Failed to stop manager: %v", err)
		}
	}()

	// Try to create a file in root-only directory as nobody - should fail
	nobodyFile := rootOnlyDir + "/nobody_file.txt"
	_, err = mgr.OpenFile("nobody", nobodyFile, os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		t.Fatalf("Expected OpenFile as nobody in root-only directory to fail, but it succeeded")
	}

	t.Logf("Operation correctly failed when user lacks permission: %v", err)
}

// TestDefaultUserOperations tests that empty username uses the default (condor) user.
func TestDefaultUserOperations(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// Use os.MkdirTemp for secure temp dir creation, then chmod for accessibility
	tempDir, err := os.MkdirTemp("/tmp", "droppriv_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to remove temp directory: %v", err)
		}
	}()
	// Make it accessible to dropped-privilege user (MkdirTemp creates 0700)
	//nolint:gosec // G302 - 0755 is appropriate for test temp directory
	if err = os.Chmod(tempDir, 0o755); err != nil {
		t.Fatalf("Failed to chmod temp dir: %v", err)
	}

	conf := Config{
		Enabled:    true,
		CondorUser: "nobody",
	}

	mgr, err2 := NewManager(conf)
	if err2 != nil {
		t.Fatalf("NewManager failed: %v", err2)
	}

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() {
		if err := mgr.Stop(); err != nil {
			t.Logf("Failed to stop manager: %v", err)
		}
	}()

	// Create a work directory that's accessible (as root, with proper permissions)
	workDir := tempDir + "/work"
	if err := mgr.MkdirAll("root", workDir, 0o755); err != nil {
		t.Fatalf("MkdirAll work dir failed: %v", err)
	}
	// Chown to nobody so they can write to it
	if err := mgr.Chown("root", workDir, 65534, 65534); err != nil {
		t.Fatalf("Chown work dir failed: %v", err)
	}

	// Use empty username - should default to condor user (nobody)
	defaultDir := workDir + "/default_user_dir"
	if err := mgr.MkdirAll("", defaultDir, 0o755); err != nil {
		t.Fatalf("MkdirAll with default user failed: %v", err)
	}

	// Verify directory ownership - stop manager to stat as root
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	dirInfo, err := os.Stat(defaultDir)
	if err != nil {
		t.Fatalf("Failed to stat directory: %v", err)
	}
	dirStat := dirInfo.Sys().(*syscall.Stat_t)
	if dirStat.Uid != 65534 || dirStat.Gid != 65534 {
		t.Errorf("Directory ownership incorrect: expected uid=65534 gid=65534, got uid=%d gid=%d", dirStat.Uid, dirStat.Gid)
	}

	t.Logf("Successfully created directory using default user, owned by uid=%d gid=%d", dirStat.Uid, dirStat.Gid)
}
