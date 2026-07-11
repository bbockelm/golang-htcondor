//go:build !windows

package userlog

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an advisory exclusive (LOCK_EX) flock on f and returns a
// function that releases it. On any error the returned unlock is a no-op:
// locking is best-effort, matching the C++ writer's default of
// ENABLE_USERLOG_LOCKING=false (O_APPEND already makes a single write
// atomic on local filesystems).
func lockFile(f *os.File) func() {
	fd := int(f.Fd()) //nolint:gosec // a file descriptor always fits in int
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return func() {}
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN) }
}
