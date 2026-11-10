//go:build linux

package droppriv

import (
	"os"
	"runtime"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// rootGroups gives the process a supplementary group list a dropped
// identity must not keep, restoring the original when the test ends.
// Set explicitly rather than inherited: root in a container may belong
// to nothing but group 0, and then a drop that kept root's groups
// would be indistinguishable from one that set them.
func rootGroups(t *testing.T) []int {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root privileges")
	}
	orig, err := os.Getgroups()
	if err != nil {
		t.Fatalf("getgroups: %v", err)
	}
	want := []int{0, 4242}
	if err := syscall.Setgroups(want); err != nil {
		t.Fatalf("setgroups: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Setgroups(orig) })
	return want
}

func nobodyManager(t *testing.T) *Manager {
	t.Helper()
	mgr, err := NewManager(Config{Enabled: true, CondorUser: "nobody"})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if mgr.defaultIdentity.UID == 0 {
		t.Skip("no nobody account to drop to")
	}
	return mgr
}

// Dropping the process to the condor account must leave it with that
// account's group and none of root's, and Stop must give root's back.
func TestStartReplacesSupplementaryGroups(t *testing.T) {
	before := rootGroups(t)
	mgr := nobodyManager(t)

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	dropped, err := os.Getgroups()
	stopErr := mgr.Stop()
	if err != nil {
		t.Fatalf("getgroups after Start: %v", err)
	}
	if stopErr != nil {
		t.Fatalf("Stop: %v", stopErr)
	}

	if want := []int{int(mgr.defaultIdentity.GID)}; !slices.Equal(dropped, want) {
		t.Errorf("groups after Start = %v, want %v (root's must not survive the drop)", dropped, want)
	}
	restored, err := os.Getgroups()
	if err != nil {
		t.Fatalf("getgroups after Stop: %v", err)
	}
	slices.Sort(restored)
	if !slices.Equal(restored, before) {
		t.Errorf("groups after Stop = %v, want %v", restored, before)
	}
}

// An operation run on a user's behalf must carry that user's group
// only, not the groups of the process doing it, and the thread must get
// its own back afterwards.
func TestRunAsUserReplacesSupplementaryGroups(t *testing.T) {
	before := rootGroups(t)
	mgr := nobodyManager(t)

	// Locked so the reads after withUser see the same thread it ran on:
	// supplementary groups are per thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var during []int
	err := mgr.withUser("nobody", func() error {
		var err error
		during, err = unix.Getgroups()
		return err
	})
	if err != nil {
		t.Fatalf("withUser: %v", err)
	}
	if want := []int{int(mgr.defaultIdentity.GID)}; !slices.Equal(during, want) {
		t.Errorf("groups while acting as nobody = %v, want %v", during, want)
	}

	after, err := unix.Getgroups()
	if err != nil {
		t.Fatalf("getgroups: %v", err)
	}
	slices.Sort(after)
	if !slices.Equal(after, before) {
		t.Errorf("thread groups after withUser = %v, want %v", after, before)
	}
}
