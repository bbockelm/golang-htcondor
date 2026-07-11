package droppriv

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sync"
	"time"
)

// Privsep performs filesystem and process operations on behalf of a specific
// Unix user. It is expressed as a set of concrete, RPC-able operations rather
// than an arbitrary closure so that it can be implemented either in-process
// (the native backend) or by delegating to a per-user helper process (the pool
// backend). A closure "run as the user" cannot cross a process boundary; these
// concrete operations can.
//
// In every method a user of "" means "the current user, no privilege switch",
// preserving the semantics of the older Manager.Open/OpenFile helpers. A
// non-empty user is validated (root and condor are rejected; use the *AsRoot
// helpers for root) and resolved to a Unix identity via the package's uid/gid
// lookup system.
type Privsep interface {
	// OpenFile opens or creates path as the user and returns a live *os.File
	// owned by the caller. The native backend switches thread credentials and
	// calls os.OpenFile; the pool backend has the helper open the file under
	// the user's credentials and passes the file descriptor back over the
	// control socket (SCM_RIGHTS), which the parent wraps with os.NewFile.
	OpenFile(ctx context.Context, user, path string, flag int, perm os.FileMode) (*os.File, error)
	// MkdirAll creates path and any missing parents as the user.
	MkdirAll(ctx context.Context, user, path string, perm os.FileMode) error
	// Chown changes ownership of path as the user.
	Chown(ctx context.Context, user, path string, uid, gid int) error
	// Stat returns file information for path as the user.
	Stat(ctx context.Context, user, path string) (os.FileInfo, error)
	// Remove removes path as the user.
	Remove(ctx context.Context, user, path string) error
	// Rename renames oldpath to newpath as the user.
	Rename(ctx context.Context, user, oldpath, newpath string) error
	// Command launches spec as the user and returns a handle to wait on. The
	// native backend uses exec.Cmd with SysProcAttr.Credential; the pool
	// backend has the helper (which already runs as the user) fork/exec the
	// child.
	Command(ctx context.Context, user string, spec CommandSpec) (Process, error)
	// Close releases all resources. For the pool backend it shuts down and
	// reaps every helper process so none are leaked.
	Close() error
}

// CommandSpec describes a child process to launch as a user.
//
// Stdin, Stdout and Stderr, when non-nil, become the child's standard streams.
// In the pool backend their file descriptors are passed to the helper via
// SCM_RIGHTS; the caller retains ownership of its own copies and may close them
// once Command returns (the child has already been started). A nil stream is
// connected to /dev/null.
type CommandSpec struct {
	// Path is the executable to run.
	Path string
	// Args are the arguments to the program, NOT including argv[0]; Path is
	// used as argv[0]. This mirrors exec.Command(path, args...).
	Args []string
	// Dir is the working directory; empty means the backend's default.
	Dir string
	// Env is the child environment; nil means inherit the launching process's
	// environment.
	Env []string
	// Stdin, Stdout and Stderr are the child's standard streams.
	Stdin  *os.File
	Stdout *os.File
	Stderr *os.File
}

// Process is a handle to a launched child. It is safe to call Wait exactly
// once; Pid and Signal may be called concurrently before Wait returns.
type Process interface {
	// Wait blocks until the process exits and returns its result. A non-zero
	// exit is reported as a *ProcessExitError.
	Wait() error
	// Pid returns the process id.
	Pid() int
	// Signal sends a signal to the process.
	Signal(sig os.Signal) error
}

// ProcessExitError reports a non-zero child exit or a termination by signal.
type ProcessExitError struct {
	// Code is the exit status (valid when Signaled is false).
	Code int
	// Signaled is true when the process was terminated by a signal.
	Signaled bool
	// Signal is the terminating signal number (valid when Signaled is true).
	Signal int
}

func (e *ProcessExitError) Error() string {
	if e.Signaled {
		return "process terminated by signal " + itoa(e.Signal)
	}
	return "process exited with status " + itoa(e.Code)
}

// Mode selects which Privsep backend NewPrivsep constructs.
type Mode int

const (
	// ModeAuto selects the native backend on privileged Linux and the pooled
	// helper backend everywhere else (non-Linux, or unprivileged).
	ModeAuto Mode = iota
	// ModeNative forces the in-process native backend.
	ModeNative
	// ModePool forces the pooled helper-process backend.
	ModePool
)

// Default limits for the helper pool.
const (
	defaultMaxHelpers        = 16
	defaultHelperIdleTimeout = 60 * time.Second
)

// PrivsepConfig configures a Privsep built by NewPrivsep.
type PrivsepConfig struct {
	// Mode selects the backend. The zero value is ModeAuto.
	Mode Mode
	// ForceHelperUnprivileged makes the pool backend spawn helpers that do NOT
	// switch credentials (they keep running as the current user) while still
	// serving the full RPC + FD-passing protocol. This lets CI exercise the
	// whole machinery without root. It has no effect on the native backend.
	ForceHelperUnprivileged bool
	// MaxHelpers bounds the number of live helper processes in the pool. Zero
	// selects a default.
	MaxHelpers int
	// HelperIdleTimeout reaps helpers idle for longer than this. Zero selects a
	// default.
	HelperIdleTimeout time.Duration
	// Manager supplies identity resolution and, for the native backend, the
	// per-thread credential switching. Nil uses DefaultManager().
	Manager *Manager
}

// ErrPoolClosed is returned when an operation is attempted on a closed pool.
var ErrPoolClosed = errors.New("droppriv: privsep pool is closed")

// ErrPoolExhausted is returned when every helper slot is busy and none can be
// evicted within the wait budget.
var ErrPoolExhausted = errors.New("droppriv: no idle helper available")

// NewPrivsep constructs a Privsep according to cfg.
func NewPrivsep(cfg PrivsepConfig) (Privsep, error) {
	mgr := cfg.Manager
	if mgr == nil {
		mgr = DefaultManager()
	}

	mode := cfg.Mode
	if mode == ModeAuto {
		if nativeAvailable() {
			mode = ModeNative
		} else {
			mode = ModePool
		}
	}

	switch mode {
	case ModeNative:
		return &nativePrivsep{mgr: mgr}, nil
	case ModePool:
		return newPool(cfg, mgr), nil
	default:
		return nil, errors.New("droppriv: unknown privsep mode")
	}
}

// nativeAvailable reports whether the in-process native backend can actually
// switch credentials on this platform: privileged Linux.
func nativeAvailable() bool {
	return runtime.GOOS == "linux" && os.Geteuid() == 0
}

var (
	defaultPrivsep     Privsep
	defaultPrivsepOnce sync.Once
)

// DefaultPrivsep returns the process-wide native Privsep wrapping
// DefaultManager(). The package-level OpenFile/MkdirAll/Chown helpers delegate
// to it, so existing callers keep their in-process behavior.
func DefaultPrivsep() Privsep {
	defaultPrivsepOnce.Do(func() {
		defaultPrivsep = &nativePrivsep{mgr: DefaultManager()}
	})
	return defaultPrivsep
}

// itoa is a tiny strconv.Itoa without importing strconv into hot error paths.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
