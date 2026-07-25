//go:build linux

package droppriv

import (
	"context"
	"os"
	"strconv"
	"testing"
)

// TestStartAsUserDropsToNobody verifies that, running as root, StartAsUser actually launches the
// child as the target user (nobody) -- not as root -- while the parent process stays root.
func TestStartAsUserDropsToNobody(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root privileges")
	}
	target, err := LookupUser(context.Background(), "nobody")
	if err != nil {
		t.Skipf("could not resolve nobody: %v", err)
	}
	uid, err := runIDU(t, "nobody")
	if err != nil {
		t.Fatalf("StartAsUser(nobody): %v", err)
	}
	if uid == "0" {
		t.Fatal("child ran as root, not nobody")
	}
	if uid != strconv.Itoa(int(target.UID)) {
		t.Errorf("child uid = %s, want nobody %d", uid, target.UID)
	}
	// The parent (this process) must remain root -- the elevation is thread-local and restored.
	if os.Geteuid() != 0 {
		t.Errorf("parent euid = %d after launch, want 0 (elevation leaked)", os.Geteuid())
	}
}
