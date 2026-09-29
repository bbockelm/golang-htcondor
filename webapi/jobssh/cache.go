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
	"net"
	"strings"
	"sync"
	"time"

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
	// Run executes cmd in the sandbox and returns its standard output.
	// Used for the one thing only the sandbox knows: where its scratch
	// directory is.
	Run(ctx context.Context, cmd string) (string, error)
	// Wait blocks until the transport is finished, and is how the
	// cache learns the job ended.
	Wait() error
	Close() error
}

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

// DialJobUnix opens a connection to a Unix socket in the job's scratch
// directory. name is a bare filename, not a path.
//
// This is how a server in the job should be reached. A TCP port bound
// to 127.0.0.1 in a sandbox is reachable by any local user on the
// execute node unless the job has its own network namespace, which no
// pool can be assumed to configure; a socket is protected by file
// permissions instead.
func (c *Cache) DialJobUnix(ctx context.Context, key Key, name string) (net.Conn, error) {
	if err := ValidateSocketName(name); err != nil {
		return nil, err
	}
	dir, err := c.ScratchDir(ctx, key)
	if err != nil {
		return nil, err
	}
	path := dir + "/" + name
	if len(path) > maxUnixPath {
		return nil, fmt.Errorf(
			"socket path %q is %d bytes, over the ~%d a Unix socket address allows; "+
				"this pool's EXECUTE directory is too deep to serve a job over a socket",
			path, len(path), maxUnixPath)
	}
	return c.DialJob(ctx, key, "unix", path)
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
