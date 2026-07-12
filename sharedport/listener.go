package sharedport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// LogFunc lets callers redirect this package's diagnostics to whatever
// logger they're already using. Defaults to a no-op.
type LogFunc func(format string, args ...any)

// Options controls listener construction. Zero values are sensible.
type Options struct {
	// HandshakeTimeout caps how long a single fd-pass handshake on the
	// UDS may take. Zero defaults to 10s — shared_port handshakes are
	// effectively local and should complete in milliseconds, so a tight
	// bound mostly serves to catch misconfigured peers.
	HandshakeTimeout time.Duration

	// Logf is invoked for protocol errors (bad header, recvmsg
	// failures, etc.). Set to nil to silence.
	Logf LogFunc
}

const defaultHandshakeTimeout = 10 * time.Second

// Listener accepts connections forwarded by condor_shared_port via
// SCM_RIGHTS over a Unix domain socket and exposes them as net.Conn
// values. It implements net.Listener so callers can plug it directly
// into http.Server.Serve / ServeTLS.
type Listener struct {
	socketPath string
	uln        *net.UnixListener
	conns      chan net.Conn
	closed     chan struct{}
	closeOnce  sync.Once

	// closeErr is the first error reported by the accept loop, surfaced
	// through Accept() once the channel drains. atomic so the accept
	// goroutine and Accept callers don't race on assignment.
	closeErr atomic.Pointer[error]

	// handlers tracks the per-connection handler goroutines spawned by
	// acceptLoop so Close can wait for them to finish before
	// returning. Without this, a malformed-handshake handler that's
	// just about to call l.logf could race with the consumer's test
	// teardown — Go's testing.T panics if t.Logf is called after the
	// test completes ("Log in goroutine after Test... has completed").
	handlers sync.WaitGroup

	timeout time.Duration
	logf    LogFunc
}

// Listen creates a UDS at socketPath, starts accepting fd-pass
// handshakes from shared_port, and returns a Listener whose Accept
// hands back the forwarded connections.
//
// Any pre-existing socket file at socketPath is unlinked first; this
// matches the behavior of HTCondor's own SharedPortEndpoint, which
// must tolerate dead sockets left by a crash.
func Listen(socketPath string, opts Options) (*Listener, error) {
	if socketPath == "" {
		return nil, errors.New("sharedport: empty socket path")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, fmt.Errorf("sharedport: ensure socket dir: %w", err)
	}
	// Best-effort unlink. If we hit a real error here (e.g. EISDIR),
	// the subsequent Listen will surface it.
	_ = os.Remove(socketPath)

	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("sharedport: resolve %s: %w", socketPath, err)
	}
	uln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("sharedport: listen %s: %w", socketPath, err)
	}
	// shared_port_server runs as the same user as the daemon process,
	// so 0700 on the socket is fine and matches the C++ endpoint
	// default. Lock down anyway — shared_port handshakes are unauthen-
	// ticated at this layer.
	//
	//nolint:gosec // G302: 0700 is intentional for a UDS shared with one peer
	if err := os.Chmod(socketPath, 0o700); err != nil {
		_ = uln.Close()
		return nil, fmt.Errorf("sharedport: chmod %s: %w", socketPath, err)
	}

	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	l := &Listener{
		socketPath: socketPath,
		uln:        uln,
		conns:      make(chan net.Conn),
		closed:     make(chan struct{}),
		timeout:    timeout,
		logf:       logf,
	}
	go l.acceptLoop()
	return l, nil
}

// SocketPath returns the absolute UDS path the listener is bound to —
// useful for tests and for emitting log lines that point at the address
// shared_port has been told to forward to. Returns "" for listeners
// adopted via AdoptFD (the parent owns the path, not us).
func (l *Listener) SocketPath() string { return l.socketPath }

// AdoptFD wraps a Unix-domain listening fd that was passed to us via
// process inheritance (typically from condor_master through
// CONDOR_INHERIT's SharedPort: token) and returns a Listener that
// runs the same shared-port handshake on incoming connections as
// Listen does.
//
// The fd must already be in listening state and inheritable. After
// AdoptFD returns successfully, the Listener owns the fd's lifecycle
// — its Close will close the listener but will NOT remove the
// underlying socket file: condor_master created that path under
// $(DAEMON_SOCKET_DIR), and unlinking it would break the parent's
// shared_port routing for sibling daemons.
//
// On error the fd is closed before returning so the caller doesn't
// have to track ownership during failure paths.
func AdoptFD(fd uintptr, opts Options) (*Listener, error) {
	// os.NewFile takes ownership of the fd; if we hand the fd to
	// net.FileListener it gets dup'd — we then close ours so we
	// don't keep a stray reference. Any error path below must close
	// either the os.File or the resulting net.Listener so the fd
	// doesn't leak.
	f := os.NewFile(fd, "shared-port-inherited")
	if f == nil {
		return nil, fmt.Errorf("sharedport: invalid inherited fd %d", fd)
	}
	ln, err := net.FileListener(f)
	// FileListener dup'd the fd internally (Go runtime does that for
	// every os.File-backed listener), so we must close our handle on
	// success to avoid keeping the original around.
	if cerr := f.Close(); cerr != nil && err == nil {
		err = fmt.Errorf("sharedport: close adopted fd dup: %w", cerr)
	}
	if err != nil {
		if ln != nil {
			_ = ln.Close()
		}
		return nil, fmt.Errorf("sharedport: wrap inherited fd %d: %w", fd, err)
	}

	uln, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("sharedport: inherited fd %d is not a Unix-domain listener (got %T)", fd, ln)
	}

	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	l := &Listener{
		// socketPath intentionally empty — see Close.
		uln:     uln,
		conns:   make(chan net.Conn),
		closed:  make(chan struct{}),
		timeout: timeout,
		logf:    logf,
	}
	go l.acceptLoop()
	return l, nil
}

func (l *Listener) acceptLoop() {
	for {
		c, err := l.uln.AcceptUnix()
		if err != nil {
			// Close() invokes uln.Close which makes AcceptUnix return
			// ErrNetClosing. Suppress in that case.
			select {
			case <-l.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			err = fmt.Errorf("sharedport: accept: %w", err)
			l.closeErr.Store(&err)
			_ = l.Close()
			return
		}
		// Track the handler so Close can drain in-flight goroutines
		// before returning. Add must happen on the parent goroutine —
		// adding inside `handle` would race with Close's Wait.
		l.handlers.Add(1)
		go l.handle(c)
	}
}

// handle runs the fd-pass handshake on a single UDS connection.
func (l *Listener) handle(c *net.UnixConn) {
	defer l.handlers.Done()
	defer func() { _ = c.Close() }()

	// Bound the entire handshake. Local UDS handshakes finish in
	// microseconds; anything slower is misbehavior we'd rather drop.
	if err := c.SetDeadline(time.Now().Add(l.timeout)); err != nil {
		l.logf("sharedport: SetDeadline: %v", err)
		return
	}

	if err := readPassSockHeader(c); err != nil {
		l.logf("sharedport: %v", err)
		return
	}

	conn, err := ReceiveForwardedConn(c)
	if err != nil {
		l.logf("sharedport: receive fd: %v", err)
		return
	}

	// Hand off the forwarded conn to whoever's calling Accept(). If we
	// shut down before a consumer takes it, close the conn ourselves
	// so we don't leak the fd.
	select {
	case l.conns <- conn:
	case <-l.closed:
		_ = conn.Close()
	}
}

// ReceiveForwardedConn is the consumer side of the fd-pass handshake: it does a
// single recvmsg on c expecting a 1-byte data record and an SCM_RIGHTS
// ancillary message carrying exactly one fd, and returns a net.Conn wrapping
// that fd. It is the receive-side counterpart of SendForwardedConn.
//
// This is the primitive the shared_port Listener uses internally after reading
// the PASS_SOCK header, but it is exported so callers implementing their own
// fd-passing rendezvous (e.g. an EP startd handing an activated syscall socket
// to a process-mode starter over a private Unix socket) can drive the receive
// half directly, pairing it with SendForwardedConn on the sending end. The
// caller is responsible for any framing/header exchange that precedes the fd
// (SendForwardedConn writes a PASS_SOCK header; a private protocol may send its
// own control message instead and call this once the fd is announced).
//
// Any extra fds in the cmsg (which shared_port never sends, but we tolerate)
// are closed immediately to avoid descriptor leaks.
func ReceiveForwardedConn(c *net.UnixConn) (net.Conn, error) {
	oob := make([]byte, syscall.CmsgSpace(4))
	buf := make([]byte, 1)
	_, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, fmt.Errorf("ReadMsgUnix: %w", err)
	}
	if oobn == 0 {
		return nil, errors.New("no ancillary data; shared_port did not pass an fd")
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("ParseSocketControlMessage: %w", err)
	}
	for _, msg := range msgs {
		if msg.Header.Level != syscall.SOL_SOCKET || msg.Header.Type != syscall.SCM_RIGHTS {
			continue
		}
		fds, err := syscall.ParseUnixRights(&msg)
		if err != nil {
			return nil, fmt.Errorf("ParseUnixRights: %w", err)
		}
		if len(fds) == 0 {
			continue
		}
		// Take the first; close any extras so descriptors don't pile up.
		for i := 1; i < len(fds); i++ {
			_ = syscall.Close(fds[i])
		}
		fd := fds[0]

		// Wrap the raw fd as a net.Conn. os.NewFile takes ownership of
		// the fd; net.FileConn duplicates it (returns its own copy)
		// and we close the os.File so the original fd doesn't dangle.
		f := os.NewFile(uintptr(fd), "shared-port-conn")
		if f == nil {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("os.NewFile returned nil for fd %d", fd)
		}
		conn, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("net.FileConn: %w", err)
		}
		return conn, nil
	}
	return nil, errors.New("cmsg did not carry SCM_RIGHTS")
}

// Accept waits for the next connection forwarded by shared_port.
//
// Implements net.Listener so callers can pass us directly to
// http.Server.Serve (or ServeTLS).
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.conns:
		if !ok {
			return nil, l.terminalErr()
		}
		return c, nil
	case <-l.closed:
		return nil, l.terminalErr()
	}
}

func (l *Listener) terminalErr() error {
	if p := l.closeErr.Load(); p != nil {
		return *p
	}
	return errClosed
}

// Close stops accepting new fd-pass handshakes, unlinks the UDS file,
// unblocks any pending Accept calls, and waits for in-flight handler
// goroutines to finish before returning. Safe to call multiple times.
//
// The wait-for-handlers part exists because each handler may call
// l.logf as it returns (on a malformed handshake from a peer,
// typically). Tests that wire `Logf: t.Logf` would otherwise see a
// goroutine still emitting log lines after the test exited — Go's
// testing.T panics on that with
// "Log in goroutine after Test... has completed".
//
// In production this is also the right thing: a graceful shutdown
// shouldn't leak goroutines that might still touch a logger the
// caller's about to tear down.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		_ = l.uln.Close()
		// Only unlink the socket file when we own it (created via
		// Listen). Listeners adopted via AdoptFD borrow the parent's
		// listening socket — removing it would orphan any other
		// daemons the parent is forwarding to.
		if l.socketPath != "" {
			_ = os.Remove(l.socketPath)
		}
	})
	// Wait outside the Once: it's idempotent (Wait on a
	// drained WaitGroup is a no-op) and we want every Close caller —
	// including the second concurrent one racing the first through
	// the Once — to block until handlers really are done.
	l.handlers.Wait()
	return nil
}

// Addr returns the UDS address the listener is bound to.
func (l *Listener) Addr() net.Addr { return l.uln.Addr() }

// SendForwardedConn is the producer side of the fd-pass handshake.
// Tests use it to drive the receiver in-process; production callers
// should never need it (real condor_shared_port talks the C++ side of
// this protocol).
//
// SendForwardedConn writes the CEDAR-framed PASS_SOCK header on c then
// uses sendmsg(2) (via WriteMsgUnix) to attach toPass.Fd as ancillary
// data. The caller still owns toPass after the call returns; closing
// it on this side does not affect the duplicated fd that arrives on
// the receiver.
func SendForwardedConn(ctx context.Context, c *net.UnixConn, toPass uintptr) error {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
		defer func() { _ = c.SetDeadline(time.Time{}) }()
	}
	if err := writePassSockHeader(c); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	rights := syscall.UnixRights(int(toPass))
	junk := []byte{0}
	if _, _, err := c.WriteMsgUnix(junk, rights, nil); err != nil {
		return fmt.Errorf("WriteMsgUnix: %w", err)
	}
	return nil
}
