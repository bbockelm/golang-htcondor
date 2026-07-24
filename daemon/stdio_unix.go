//go:build unix

package daemon

import (
	"os"

	"golang.org/x/sys/unix"

	"github.com/bbockelm/golang-htcondor/logging"
)

// captureStdoutStderr points the process's stdout(1) and stderr(2) file descriptors at the
// logger's current log file, and re-points them whenever the log rotates. This captures
// output that bypasses the structured logger -- panic stacks (the runtime writes them to
// fd 2 directly), a dependency writing to stderr, or a bare fmt.Print on an early
// misconfiguration path -- which condor_master otherwise sends to /dev/null.
//
// It is a no-op when the logger writes to a std stream already (File() == nil), avoiding a
// self-referential redirect. dup2 duplicates onto the real fds, so it also covers any
// child or C library that inherits and writes fd 1/2, not just Go's os.Stdout/os.Stderr.
func captureStdoutStderr(logger *logging.Logger) {
	redirect := func(f *os.File) {
		if f == nil {
			return
		}
		fd := int(f.Fd())
		_ = unix.Dup2(fd, int(os.Stdout.Fd()))
		_ = unix.Dup2(fd, int(os.Stderr.Fd()))
	}

	f := logger.File()
	if f == nil {
		return // logging to stdout/stderr already, or the file failed to open
	}
	redirect(f)
	logger.OnRotate(redirect) // follow the file across rotations
	logger.Info(logging.DestinationGeneral, "captured stdout/stderr into the log file", "path", f.Name())
}
