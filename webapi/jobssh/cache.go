// Package jobssh keeps one condor_ssh_to_job transport alive per
// (caller, job) and hands out TCP connections into the job's sandbox
// over it.
//
// Opening a transport is expensive: a schedd RPC (GET_JOB_CONNECT_INFO),
// a CEDAR handshake to the starter that may be relayed through CCB, an
// SSH handshake, and an sshd spawn inside the sandbox. Anything talking
// to a server running in the job -- an editor, a notebook, a debugger --
// opens connections constantly, so paying that per connection is not an
// option. Hence a cache rather than a dial per use.
package jobssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-htcondor/logging"
)

// DefaultIdleTimeout is how long a transport with no connections open
// is kept before it is closed.
//
// The cost of keeping one is an idle TCP connection and an sshd in the
// sandbox; the cost of dropping one too eagerly is a full handshake in
// front of the next request, which a user sees as the editor hanging.
// So this leans long.
const DefaultIdleTimeout = 10 * time.Minute

// Key identifies a cached transport.
//
// Owner is part of it because a transport authenticates as somebody,
// and two callers must never share one. cedar's own client session
// cache had exactly this bug -- keyed by {address, command} alone, so
// one user's request could resume a session another user had
// authenticated and run as them. Same reasoning here, different cache.
type Key struct {
	Owner   string
	Cluster int
	Proc    int
}

func (k Key) String() string { return fmt.Sprintf("%s/%d.%d", k.Owner, k.Cluster, k.Proc) }

// Conn is the slice of *ssh.Client this package needs: open a TCP
// connection inside the sandbox, notice when the transport dies, and
// shut it down. An interface so the cache is testable without a pool.
type Conn interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	// OpenSession starts a session channel in the sandbox: a shell, a
	// PTY, or a command. Sessions are what an interactive client needs
	// and what MaxSessionsPerTransport counts.
	OpenSession(ctx context.Context) (JobSession, error)
	// Run executes cmd in the sandbox and returns its standard output.
	// Used for the one thing only the sandbox knows: where its scratch
	// directory is.
	Run(ctx context.Context, cmd string) (string, error)
	// Wait blocks until the transport is finished, and is how the
	// cache learns the job ended.
	Wait() error
	Close() error
}

// JobSession is a session channel inside the sandbox.
//
// It is the slice of *ssh.Session this package hands out, as an
// interface so the cache stays testable without a pool. *ssh.Session
// satisfies it directly -- no wrapper is needed -- but note what is
// deliberately absent: its Stdin/Stdout/Stderr FIELDS, which an
// interface cannot express. Callers wire I/O through the pipes.
type JobSession interface {
	RequestPty(term string, h, w int, modes ssh.TerminalModes) error
	WindowChange(h, w int) error
	Shell() error
	Start(cmd string) error
	// RequestSubsystem starts a named subsystem, such as sftp. The
	// job's sshd serves its own Subsystem directive, so this reaches a
	// real sftp-server rather than the forced command.
	RequestSubsystem(subsystem string) error
	Signal(sig ssh.Signal) error
	Wait() error
	StdinPipe() (io.WriteCloser, error)
	StdoutPipe() (io.Reader, error)
	StderrPipe() (io.Reader, error)
	Close() error
}

// socketPathResult is a memoized socket-address lookup, failure
// included: a job that publishes nothing now will publish nothing on
// the next request either.
type socketPathResult struct {
	path string
	err  error
}

// MaxSessionsPerTransport caps live sessions on one transport.
//
// The sshd HTCondor generates sets no MaxSessions, so OpenSSH's
// default of 10 applies -- and that budget is per CONNECTION. Before
// this cache each client had its own connection and so its own 10;
// sharing a transport per (caller, job) makes it one budget shared by
// every terminal and command for that job. Hitting it at the far end
// produces an opaque channel-open rejection partway through a session,
// so the limit is enforced here, where the error can say what it is.
//
// Port forwards do not count: direct-tcpip channels are not sessions,
// so the reverse proxy contributes nothing to this.
const MaxSessionsPerTransport = 10

// ErrTooManySessions is returned when a transport already holds
// MaxSessionsPerTransport live sessions.
var ErrTooManySessions = errors.New("jobssh: too many concurrent sessions for this job")

// Dialer opens a transport for key. The context carries the caller's
// credentials, so it must be one authenticated as key.Owner.
type Dialer func(ctx context.Context, key Key) (Conn, error)

// Options configures a Cache. Only Dial is required.
type Options struct {
	Dial        Dialer
	IdleTimeout time.Duration
	Logger      *logging.Logger

	// now is injectable so the reaper can be tested without sleeping.
	now func() time.Time
}

// Cache holds the live transports.
type Cache struct {
	dial Dialer
	idle time.Duration
	log  *logging.Logger
	now  func() time.Time

	// mu guards entries and every bookkeeping field on an entry
	// (conn, refs, lastUse, evicted). It is NOT held across a dial --
	// see entry.dialMu.
	mu      sync.Mutex
	entries map[Key]*entry
	closed  bool

	stop chan struct{}
	// wg tracks the reaper only; see watch for why not the watchers.
	wg sync.WaitGroup
}

type entry struct {
	key Key

	// dialMu serializes the first dial for this key so two concurrent
	// callers do not each pay for a handshake. It is per entry rather
	// than the cache lock, so a slow dial for one job does not block
	// every other job's lookups.
	dialMu sync.Mutex

	conn Conn

	// refs counts connections handed out and not yet closed; lastUse
	// is when refs last reached zero. A transport is reapable only
	// when both agree: closing one with live connections would break
	// a session mid-use, and "nothing dialled recently" is not the
	// same as "nothing is using it" when one connection can stay open
	// for hours.
	refs    int
	lastUse time.Time

	// evicted marks an entry removed from the map, so a release that
	// arrives afterwards closes the transport instead of resurrecting
	// bookkeeping nobody will read.
	evicted bool

	// sessions counts live session channels, which is what the sshd's
	// MaxSessions budget applies to. Tracked apart from refs because
	// refs also covers forwarded connections, and those do not consume
	// the budget.
	sessions int

	// socketPaths caches the address for each socket name the job
	// publishes, resolved once per transport like scratch.
	socketPaths map[string]socketPathResult

	// scratch caches the sandbox's scratch directory, resolved once
	// per transport. scratchErr is cached too: if the sandbox will not
	// tell us, it will not tell the next request either, and retrying
	// costs a round trip per request to learn the same thing.
	scratchOnce sync.Once
	scratch     string
	scratchErr  error

	// closeOnce makes shutting the transport idempotent. Three things
	// can decide a transport is finished -- the reaper, the watcher
	// noticing the job ended, and the last release of an evicted
	// entry -- and more than one of them can be right at the same
	// time.
	closeOnce sync.Once
}

// shut closes a transport exactly once, whoever gets there first.
func shut(e *entry, conn Conn) {
	if conn == nil {
		return
	}
	e.closeOnce.Do(func() { _ = conn.Close() })
}

// NewCache returns a Cache and starts its reaper. Close it when done.
func NewCache(opts Options) (*Cache, error) {
	if opts.Dial == nil {
		return nil, errors.New("jobssh: a Dialer is required")
	}
	idle := opts.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	now := opts.now
	if now == nil {
		now = time.Now
	}
	c := &Cache{
		dial:    opts.Dial,
		idle:    idle,
		log:     opts.Logger,
		now:     now,
		entries: make(map[Key]*entry),
		stop:    make(chan struct{}),
	}
	c.wg.Add(1)
	go c.reap()
	return c, nil
}

// DialJob opens a connection to addr inside key's job, reusing the
// cached transport or establishing one.
//
// The returned net.Conn holds the transport open: it is released when
// the caller Closes it, and not before. Callers must Close it.
func (c *Cache) DialJob(ctx context.Context, key Key, network, addr string) (net.Conn, error) {
	e, err := c.acquire(ctx, key)
	if err != nil {
		return nil, err
	}
	raw, err := e.conn.DialContext(ctx, network, addr)
	if err != nil {
		c.release(e)
		// Deliberately NOT evicting here. A dial can fail because
		// nothing is listening on that port yet -- the server in the
		// job is still starting -- which says nothing about the
		// transport. A transport that has actually died is noticed by
		// watch() instead, which is the only thing that can tell the
		// difference.
		return nil, fmt.Errorf("dialling %s inside job %s: %w", addr, key, err)
	}
	return &trackedConn{Conn: raw, release: func() { c.release(e) }}, nil
}

// acquire returns an entry with a reference already taken.
func (c *Cache) acquire(ctx context.Context, key Key) (*entry, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("jobssh: cache is closed")
	}
	e, ok := c.entries[key]
	if !ok {
		e = &entry{key: key}
		c.entries[key] = e
	}
	e.refs++
	c.mu.Unlock()

	// Fast path: somebody already dialled.
	c.mu.Lock()
	conn := e.conn
	c.mu.Unlock()
	if conn != nil {
		return e, nil
	}

	e.dialMu.Lock()
	defer e.dialMu.Unlock()

	// Re-check: another caller may have dialled while we waited.
	c.mu.Lock()
	conn = e.conn
	c.mu.Unlock()
	if conn != nil {
		return e, nil
	}

	conn, err := c.dial(ctx, key)
	if err != nil {
		c.release(e)
		return nil, fmt.Errorf("opening a transport to job %s: %w", key, err)
	}

	// The entry can have been evicted while the dial was in flight --
	// the cache was closed, or the reaper ran. The caller still gets
	// the transport, because they asked for one and it works; it is
	// the entry's own bookkeeping that decides whether anyone else
	// can find it. Either way conn is published under the lock, since
	// release reads it there to decide whether to close it.
	c.mu.Lock()
	e.conn = conn
	c.mu.Unlock()

	go c.watch(e, conn)
	if c.log != nil {
		c.log.Debug(logging.DestinationSchedd, "opened a job transport", "job", key.String())
	}
	return e, nil
}

// release drops one reference, starting the idle clock when the last
// one goes.
func (c *Cache) release(e *entry) {
	c.mu.Lock()
	e.refs--
	if e.refs < 0 {
		// A double release is a bug in this package, not a condition
		// to recover from silently: it would let the reaper close a
		// transport somebody is still using.
		e.refs = 0
	}
	last := e.refs == 0
	if last {
		e.lastUse = c.now()
	}
	// An entry whose dial failed holds no transport, and the reaper
	// only considers entries that have one -- so nothing else would
	// ever remove this, and a job that cannot be reached would
	// accumulate an entry per attempt. Drop it here, at the only
	// moment we know it is finished with.
	if last && e.conn == nil && !e.evicted {
		if cur, ok := c.entries[e.key]; ok && cur == e {
			delete(c.entries, e.key)
		}
		e.evicted = true
	}
	evicted, conn := e.evicted, e.conn
	c.mu.Unlock()

	// An evicted entry's transport is nobody's to reuse, so the last
	// reference out turns off the lights.
	if last && evicted {
		shut(e, conn)
	}
}

// watch closes out an entry when its transport ends, which is how the
// cache learns a job finished or was removed. Without it a dead
// transport would sit in the map until the idle timer got round to it,
// and every request in between would fail on a corpse.
//
// Deliberately not tracked by c.wg. A watcher blocks until its
// transport ends, and the transport of an entry still in use is closed
// by its last release -- which can be long after Close was called.
// Making Close wait for watchers deadlocks it against exactly the
// in-flight request it is trying not to cut off. Watchers hold nothing
// but the transport they are watching, and end when it closes.
func (c *Cache) watch(e *entry, conn Conn) {
	_ = conn.Wait()

	c.mu.Lock()
	if cur, ok := c.entries[e.key]; ok && cur == e {
		delete(c.entries, e.key)
	}
	e.evicted = true
	idle := e.refs == 0
	c.mu.Unlock()

	if idle {
		shut(e, conn)
	}
	if c.log != nil {
		c.log.Debug(logging.DestinationSchedd, "job transport ended", "job", e.key.String())
	}
}

// reap closes transports that nothing has used for IdleTimeout.
func (c *Cache) reap() {
	defer c.wg.Done()
	// Half the idle timeout: an entry is then closed somewhere between
	// idle and 1.5*idle after last use, which is close enough for a
	// resource this cheap to hold and avoids a tick per second.
	ticker := time.NewTicker(c.idle / 2)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.reapOnce()
		}
	}
}

func (c *Cache) reapOnce() {
	now := c.now()
	type victim struct {
		e    *entry
		conn Conn
	}
	var dead []victim

	c.mu.Lock()
	for key, e := range c.entries {
		// refs > 0 means somebody is mid-dial or holding a
		// connection. One connection can stay open for hours, so
		// "nothing dialled recently" on its own is the wrong test.
		if e.refs > 0 {
			continue
		}
		if now.Sub(e.lastUse) < c.idle {
			continue
		}
		delete(c.entries, key)
		e.evicted = true
		// conn is nil for an entry whose dial failed; release should
		// already have dropped it, and sweeping it here costs nothing
		// and closes the gap if it did not.
		dead = append(dead, victim{e, e.conn})
	}
	c.mu.Unlock()

	for _, v := range dead {
		shut(v.e, v.conn)
	}
	if len(dead) > 0 && c.log != nil {
		c.log.Debug(logging.DestinationSchedd, "reaped idle job transports", "count", len(dead))
	}
}

// Len reports how many transports are cached. For tests and metrics.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Close shuts the cache down, closing every transport whose
// connections have all been released. One still in use is closed by
// its last release.
func (c *Cache) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	close(c.stop)
	type victim struct {
		e    *entry
		conn Conn
	}
	var dead []victim
	for key, e := range c.entries {
		delete(c.entries, key)
		e.evicted = true
		if e.refs == 0 {
			dead = append(dead, victim{e, e.conn})
		}
	}
	c.mu.Unlock()

	for _, v := range dead {
		shut(v.e, v.conn)
	}
	c.wg.Wait()
}

// trackedConn releases the cache reference when the caller is done
// with the connection, exactly once however many times Close is
// called -- net/http closes a connection from more than one place.
type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (t *trackedConn) Close() error {
	err := t.Conn.Close()
	t.once.Do(t.release)
	return err
}

// maxUnixPath is the practical ceiling on a Unix socket address.
// sun_path is 108 bytes on Linux and 104 on macOS, and both ends of a
// forward are bound by it. An HTCondor scratch directory can fill most
// of that on its own, and the kernel's complaint arrives as nothing
// more informative than "open failed" -- so the check is here, where
// the path can be named in the error.
const maxUnixPath = 100

// ScratchDir returns the job's scratch directory, asking the sandbox
// once per transport.
//
// It has to be asked. A relative socket path does not resolve over a
// forward -- sshd's working directory is not the sandbox -- so an
// absolute path is the only way to reach a socket, and only the job
// knows what its own is.
func (c *Cache) ScratchDir(ctx context.Context, key Key) (string, error) {
	e, err := c.acquire(ctx, key)
	if err != nil {
		return "", err
	}
	defer c.release(e)

	e.scratchOnce.Do(func() {
		out, rerr := e.conn.Run(ctx, `echo "$_CONDOR_SCRATCH_DIR"`)
		if rerr != nil {
			e.scratchErr = fmt.Errorf("asking job %s for its scratch directory: %w", key, rerr)
			return
		}
		dir := strings.TrimSpace(out)
		if dir == "" {
			e.scratchErr = fmt.Errorf("job %s reported no scratch directory", key)
			return
		}
		e.scratch = dir
	})
	return e.scratch, e.scratchErr
}

// DialJobUnix opens a connection to a Unix socket the job is serving
// on. name is a bare filename, not a path.
//
// This is how a server in the job should be reached. A TCP port bound
// to 127.0.0.1 in a sandbox is reachable by any local user on the
// execute node unless the job has its own network namespace, which no
// pool can be assumed to configure; a socket is protected by file
// permissions instead.
//
// The address comes from the job, not from joining the scratch
// directory to name. Both ends of a Unix socket are capped at ~100
// bytes of sun_path, and an HTCondor scratch directory routinely
// exceeds that on its own -- a glidein, an EP running inside a SLURM
// job, nests its execute/dir_N under the host batch system's, and the
// path runs past the limit before anything of ours is added. So a job
// binds its socket by bare name, against its own working directory,
// and publishes an address short enough to connect to in
// "<name>.path". Falling back to the joined path keeps a job that
// publishes nothing working wherever the path does fit.
func (c *Cache) DialJobUnix(ctx context.Context, key Key, name string) (net.Conn, error) {
	if err := ValidateSocketName(name); err != nil {
		return nil, err
	}
	path, err := c.SocketPath(ctx, key, name)
	if err != nil {
		return nil, err
	}
	conn, err := c.DialJob(ctx, key, "unix", path)
	if err != nil {
		return nil, err
	}
	// A guess that works is as good as a published address, and worth
	// not re-deriving on every connection. One that does not work is
	// never cached, so a server still starting up is re-asked.
	e, aerr := c.acquire(ctx, key)
	if aerr == nil {
		c.rememberSocketPath(e, name, path)
		c.release(e)
	}
	return conn, nil
}

// SocketPath returns the address to connect to for the job's socket
// name, asking the job once per transport.
//
// The lookup runs in the sandbox, where the working directory is the
// job's, so reading "<name>.path" needs no long path of its own --
// which is the whole point, since a long path is what this exists to
// get around.
func (c *Cache) SocketPath(ctx context.Context, key Key, name string) (string, error) {
	if err := ValidateSocketName(name); err != nil {
		return "", err
	}
	e, err := c.acquire(ctx, key)
	if err != nil {
		return "", err
	}
	defer c.release(e)

	c.mu.Lock()
	cached, ok := e.socketPaths[name]
	c.mu.Unlock()
	if ok {
		return cached.path, cached.err
	}

	path, published, perr := c.resolveSocketPath(ctx, e, key, name)
	// Only an address the job actually published is worth remembering.
	//
	// Caching whatever the first lookup produced is what made a session
	// sit at "starting" forever: the first probe lands in the seconds
	// before the server has written its address, the lookup falls back
	// to joining the scratch path, and that guess is then answered to
	// every later request -- including after the server has published a
	// real address somewhere else entirely. The job was running the
	// whole time and ssh-to-job worked, which is exactly how it looked.
	//
	// A guess costs one command in the sandbox to re-ask, and only for
	// as long as nothing has been published, so re-asking is cheap and
	// self-healing. DialJobUnix promotes a guess to the cache once a
	// connection over it actually works.
	if published && perr == nil {
		c.rememberSocketPath(e, name, path)
	}
	return path, perr
}

// rememberSocketPath records an address that is known good.
func (c *Cache) rememberSocketPath(e *entry, name, path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.socketPaths == nil {
		e.socketPaths = map[string]socketPathResult{}
	}
	e.socketPaths[name] = socketPathResult{path: path}
}

// resolveSocketPath asks the job where its socket is. published
// reports whether the answer came from the job rather than from
// guessing, which is what decides whether it may be cached.
func (c *Cache) resolveSocketPath(ctx context.Context, e *entry, key Key, name string) (path string, published bool, err error) {
	// `cat` rather than a shell test: a missing file is an error we
	// recognise by getting nothing usable back, and anything sent
	// through ssh-to-job is word-split and rejoined, so the command
	// stays a single line with no quoting to survive.
	out, err := e.conn.Run(ctx, "cat "+name+".path 2>/dev/null")
	if err == nil {
		if addr := strings.TrimSpace(out); addr != "" {
			if !strings.HasPrefix(addr, "/") {
				return "", true, fmt.Errorf("job %s published a relative socket address %q; sshd resolves it against its own working directory, not the sandbox's", key, addr)
			}
			if len(addr) > maxUnixPath {
				return "", true, fmt.Errorf("job %s published a socket address of %d bytes, over the ~%d a Unix socket allows: %q",
					key, len(addr), maxUnixPath, addr)
			}
			return addr, true, nil
		}
	}

	// Nothing published: a job that predates this, or one somebody set
	// up by hand. The joined path is right whenever it fits.
	dir, derr := c.ScratchDir(ctx, key)
	if derr != nil {
		return "", false, derr
	}
	guess := dir + "/" + name
	if len(guess) > maxUnixPath {
		return "", false, fmt.Errorf(
			"job %s publishes no %s.path and %q is %d bytes, over the ~%d a Unix socket address allows; "+
				"a server in a sandbox this deep must put its socket somewhere shorter and publish where",
			key, name, guess, len(guess), maxUnixPath)
	}
	return guess, false, nil
}

// ValidateSocketName keeps the caller-supplied component to a bare
// filename. Everything about the path but this comes from the sandbox,
// and a name with a separator or a parent reference in it would let a
// request name a socket anywhere on the execute node.
//
// Exported so an HTTP layer can refuse a bad name where it arrives,
// with a 400 that says what is wrong, rather than letting it travel as
// far as a dial and come back as a 502.
func ValidateSocketName(name string) error {
	if name == "" {
		return errors.New("socket name is empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("socket name %q is too long", name)
	}
	if name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("socket name %q must be a bare filename", name)
	}
	for _, r := range name {
		ok := r == '.' || r == '_' || r == '-' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return fmt.Errorf("socket name %q has a character outside [A-Za-z0-9._-]", name)
		}
	}
	return nil
}

// Session opens a session channel inside the job, reusing the cached
// transport or establishing one.
//
// The returned release must be called when the session is done. Until
// it is, the session counts as a live user of the transport exactly as
// a forwarded connection does: an interactive shell can sit silent for
// an hour, and the reaper's idle clock alone would close the transport
// out from under it.
func (c *Cache) Session(ctx context.Context, key Key) (JobSession, func(), error) {
	e, err := c.acquire(ctx, key)
	if err != nil {
		return nil, nil, err
	}

	c.mu.Lock()
	if e.sessions >= MaxSessionsPerTransport {
		live := e.sessions
		c.mu.Unlock()
		c.release(e)
		return nil, nil, fmt.Errorf("%w: job %s already has %d of %d (every terminal and command for one job shares the sshd's session budget)",
			ErrTooManySessions, key, live, MaxSessionsPerTransport)
	}
	e.sessions++
	c.mu.Unlock()

	sess, err := e.conn.OpenSession(ctx)
	if err != nil {
		c.mu.Lock()
		e.sessions--
		c.mu.Unlock()
		c.release(e)
		// Deliberately NOT evicting, for the same reason DialJob does
		// not: opening a session can fail because the sandbox is not
		// ready, which says nothing about the transport. Only watch()
		// can tell a dead transport from one whose far end is busy.
		return nil, nil, fmt.Errorf("opening a session in job %s: %w", key, err)
	}

	var once sync.Once
	release := func() {
		once.Do(func() {
			c.mu.Lock()
			e.sessions--
			c.mu.Unlock()
			c.release(e)
		})
	}
	return sess, release, nil
}

// LiveSessions reports how many sessions are open on key's transport.
// For tests and metrics.
func (c *Cache) LiveSessions(key Key) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		return e.sessions
	}
	return 0
}
