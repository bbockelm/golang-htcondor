package jobssh

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeConn stands in for an *ssh.Client. dialErr, when set, is what
// DialContext returns -- the "nothing is listening on that port yet"
// case, which must not be confused with the transport dying.
type fakeConn struct {
	mu        sync.Mutex
	dialErr   error
	dials     int
	runOut    string
	runErr    error
	runs      int
	openErr   error
	opens     int
	published string // what "cat <name>.path" returns
	pathReads int
	closed    bool
	done      chan struct{} // closed to make Wait return, i.e. the job ended
}

func newFakeConn() *fakeConn {
	return &fakeConn{done: make(chan struct{}), runOut: "/var/lib/condor/execute/dir_42\n"}
}

func (f *fakeConn) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dials++
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	client, server := net.Pipe()
	go func() { _ = server.Close() }()
	return client, nil
}

func (f *fakeConn) Run(_ context.Context, cmd string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs++
	if f.runErr != nil {
		return "", f.runErr
	}
	// The sandbox answers two questions: where its scratch directory
	// is, and what address a socket is reachable at.
	if strings.HasPrefix(cmd, "cat ") {
		f.pathReads++
		return f.published, nil
	}
	return f.runOut, nil
}

// fakeSession is a JobSession that does nothing but exist and close,
// which is all the cache's accounting cares about.
type fakeSession struct {
	mu     sync.Mutex
	closed bool
}

func (f *fakeSession) RequestPty(string, int, int, ssh.TerminalModes) error { return nil }
func (f *fakeSession) WindowChange(int, int) error                          { return nil }
func (f *fakeSession) Shell() error                                         { return nil }
func (f *fakeSession) Start(string) error                                   { return nil }
func (f *fakeSession) RequestSubsystem(string) error                        { return nil }
func (f *fakeSession) Signal(ssh.Signal) error                              { return nil }
func (f *fakeSession) Wait() error                                          { return nil }
func (f *fakeSession) StdinPipe() (io.WriteCloser, error)                   { return nil, nil }
func (f *fakeSession) StdoutPipe() (io.Reader, error)                       { return nil, nil }
func (f *fakeSession) StderrPipe() (io.Reader, error)                       { return nil, nil }
func (f *fakeSession) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeConn) OpenSession(context.Context) (JobSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens++
	if f.openErr != nil {
		return nil, f.openErr
	}
	return &fakeSession{}, nil
}

func (f *fakeConn) Wait() error {
	<-f.done
	return errors.New("transport ended")
}

// Close makes Wait return, as *ssh.Client does. A fake that kept Wait
// blocking after Close would let a watcher leak past a test.
func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.done)
	}
	return nil
}

func (f *fakeConn) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// end makes Wait return without a Close, as it does when the job
// finishes underneath a transport nobody has closed.
func (f *fakeConn) end() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.done)
	}
}

type fakeDialer struct {
	mu            sync.Mutex
	calls         int
	conns         []*fakeConn
	err           error
	delay         time.Duration
	scratch       string
	publishedPath string
}

func (d *fakeDialer) dial(_ context.Context, _ Key) (Conn, error) {
	d.mu.Lock()
	d.calls++
	err, delay, scratch, published := d.err, d.delay, d.scratch, d.publishedPath
	d.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
	if err != nil {
		return nil, err
	}
	c := newFakeConn()
	if scratch != "" {
		c.runOut = scratch
	}
	c.published = published
	d.mu.Lock()
	d.conns = append(d.conns, c)
	d.mu.Unlock()
	return c, nil
}

func (d *fakeDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// newTestCache builds a cache whose idle timeout is long enough never
// to fire on its own: the reap tests drive reapOnce directly against an
// injected clock, so a real timer would only make them flaky.
func newTestCache(t *testing.T, d *fakeDialer, now func() time.Time) *Cache {
	t.Helper()
	c, err := NewCache(Options{Dial: d.dial, IdleTimeout: time.Hour, now: now})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

var testKey = Key{Owner: "alice@example.com", Cluster: 12, Proc: 0}

// TestTransportIsReusedAcrossConnections is the whole point of the
// package: the expensive handshake happens once, not once per
// connection. A browser talking to a server in the job opens
// connections constantly.
func TestTransportIsReusedAcrossConnections(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	for i := 0; i < 5; i++ {
		conn, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:8080")
		if err != nil {
			t.Fatalf("DialJob %d: %v", i, err)
		}
		_ = conn.Close()
	}
	if got := d.count(); got != 1 {
		t.Errorf("dialled the job %d times, want 1", got)
	}
}

// TestTransportIsNotSharedAcrossOwners pins the separation that keeps
// one user's transport from carrying another user's traffic. A
// transport authenticates as somebody; sharing one by job id alone
// would run a request as whoever opened it first.
func TestTransportIsNotSharedAcrossOwners(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	alice := Key{Owner: "alice@example.com", Cluster: 12, Proc: 0}
	bob := Key{Owner: "bob@example.com", Cluster: 12, Proc: 0}

	for _, k := range []Key{alice, bob} {
		conn, err := c.DialJob(context.Background(), k, "tcp", "127.0.0.1:8080")
		if err != nil {
			t.Fatalf("DialJob %s: %v", k, err)
		}
		_ = conn.Close()
	}
	if got := d.count(); got != 2 {
		t.Errorf("dialled %d times for two owners of the same job, want 2", got)
	}
	if c.Len() != 2 {
		t.Errorf("cached %d transports, want 2", c.Len())
	}
}

// TestConcurrentFirstUseDialsOnce covers the thundering herd a page
// load produces: a browser opens several connections at once, and the
// first of them must not turn into several handshakes.
func TestConcurrentFirstUseDialsOnce(t *testing.T) {
	d := &fakeDialer{delay: 50 * time.Millisecond}
	c := newTestCache(t, d, nil)

	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:8080")
			if err != nil {
				failures.Add(1)
				return
			}
			_ = conn.Close()
		}()
	}
	wg.Wait()

	if n := failures.Load(); n != 0 {
		t.Errorf("%d concurrent callers failed", n)
	}
	if got := d.count(); got != 1 {
		t.Errorf("dialled %d times concurrently, want 1", got)
	}
}

// TestPortRefusedDoesNotEvictTransport is the distinction that would
// otherwise cost a handshake on every poll: a server inside the job
// that has not finished starting refuses connections, which says
// nothing about the transport carrying them. Only the transport dying
// should evict.
func TestPortRefusedDoesNotEvictTransport(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	// First call establishes the transport.
	conn, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("DialJob: %v", err)
	}
	_ = conn.Close()

	d.mu.Lock()
	d.conns[0].mu.Lock()
	d.conns[0].dialErr = errors.New("connect failed")
	d.conns[0].mu.Unlock()
	d.mu.Unlock()

	for i := 0; i < 3; i++ {
		if _, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:8080"); err == nil {
			t.Fatal("DialJob succeeded against a refusing port")
		}
	}
	if got := d.count(); got != 1 {
		t.Errorf("a refused port cost %d transport dials, want 1", got)
	}
	if c.Len() != 1 {
		t.Errorf("transport was evicted by a refused port; cached = %d, want 1", c.Len())
	}
}

// TestDeadTransportIsEvictedAndRedialled covers a job ending under a
// live cache entry. Without this the dead transport sits in the map
// until the idle timer notices, and every request in between fails on
// a corpse.
func TestDeadTransportIsEvictedAndRedialled(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	conn, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("DialJob: %v", err)
	}
	_ = conn.Close()

	d.mu.Lock()
	first := d.conns[0]
	d.mu.Unlock()
	first.end()

	// watch() runs in its own goroutine; give it a moment to evict.
	deadline := time.Now().Add(2 * time.Second)
	for c.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c.Len() != 0 {
		t.Fatalf("dead transport still cached; Len = %d", c.Len())
	}
	if !first.isClosed() {
		t.Error("dead transport was not closed")
	}

	conn2, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("DialJob after death: %v", err)
	}
	_ = conn2.Close()
	if got := d.count(); got != 2 {
		t.Errorf("dialled %d times, want 2 (one before the job ended, one after)", got)
	}
}

// TestInUseTransportSurvivesTheReaper pins the half of the reap rule
// that "nothing dialled recently" alone would get wrong: one
// connection can stay open for hours, and closing its transport would
// break a session that is actively in use.
func TestInUseTransportSurvivesTheReaper(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }

	d := &fakeDialer{}
	c := newTestCache(t, d, now)

	held, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("DialJob: %v", err)
	}
	// Long past the idle timeout, but the connection is still open.
	clock.Add(int64(24 * time.Hour))
	c.reapOnce()

	if c.Len() != 1 {
		t.Fatalf("reaper closed a transport with a connection open; Len = %d", c.Len())
	}

	_ = held.Close()
	clock.Add(int64(24 * time.Hour))
	c.reapOnce()
	if c.Len() != 0 {
		t.Errorf("idle transport was not reaped; Len = %d", c.Len())
	}
	d.mu.Lock()
	closed := d.conns[0].isClosed()
	d.mu.Unlock()
	if !closed {
		t.Error("reaped transport was not closed")
	}
}

// TestFailedDialLeavesNothingCached stops a job that cannot be reached
// from accumulating an entry per attempt.
func TestFailedDialLeavesNothingCached(t *testing.T) {
	d := &fakeDialer{err: errors.New("job is not running")}
	c := newTestCache(t, d, nil)

	if _, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:8080"); err == nil {
		t.Fatal("DialJob succeeded with a failing dialer")
	}
	if c.Len() != 0 {
		t.Errorf("a failed dial left %d entries cached, want 0", c.Len())
	}
}

// TestCloseWaitsForTheLastConnection covers shutdown while somebody is
// still streaming: the transport must outlive the cache until its last
// connection is released, or an in-flight response is truncated.
func TestCloseWaitsForTheLastConnection(t *testing.T) {
	d := &fakeDialer{}
	c, err := NewCache(Options{Dial: d.dial, IdleTimeout: time.Hour})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	held, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("DialJob: %v", err)
	}

	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()

	d.mu.Lock()
	conn := d.conns[0]
	d.mu.Unlock()

	time.Sleep(50 * time.Millisecond)
	if conn.isClosed() {
		t.Fatal("transport was closed while a connection was still open")
	}

	_ = held.Close()
	if !conn.isClosed() {
		t.Error("transport was not closed by the last release")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Error("Close did not return")
	}
}

// TestScratchDirIsResolvedOnce pins the memo. A relative socket path
// does not resolve over a forward, so every Unix dial needs the
// sandbox's absolute scratch directory -- asking for it per request
// would put a round trip in front of each one.
func TestScratchDirIsResolvedOnce(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	for i := 0; i < 4; i++ {
		got, err := c.ScratchDir(context.Background(), testKey)
		if err != nil {
			t.Fatalf("ScratchDir %d: %v", i, err)
		}
		if got != "/var/lib/condor/execute/dir_42" {
			t.Fatalf("ScratchDir = %q, want the sandbox's path with the newline trimmed", got)
		}
	}
	d.mu.Lock()
	runs := d.conns[0].runs
	d.mu.Unlock()
	if runs != 1 {
		t.Errorf("asked the sandbox %d times, want 1", runs)
	}
}

// TestScratchDirFailureIsCached: a sandbox that will not answer will
// not answer the next request either, and retrying costs a round trip
// per request to learn the same thing.
func TestScratchDirFailureIsCached(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	// Establish the transport, then make Run fail.
	if _, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:1"); err != nil {
		t.Fatalf("DialJob: %v", err)
	}
	d.mu.Lock()
	d.conns[0].mu.Lock()
	d.conns[0].runErr = errors.New("no shell")
	d.conns[0].mu.Unlock()
	d.mu.Unlock()

	for i := 0; i < 3; i++ {
		if _, err := c.ScratchDir(context.Background(), testKey); err == nil {
			t.Fatal("ScratchDir succeeded with a failing shell")
		}
	}
	d.mu.Lock()
	runs := d.conns[0].runs
	d.mu.Unlock()
	if runs != 1 {
		t.Errorf("retried the failing lookup %d times, want it cached after 1", runs)
	}
}

func TestValidateSocketName(t *testing.T) {
	good := []string{"vscode.sock", "a", "code-server_1.sock", "X.Y-Z_0"}
	for _, n := range good {
		if err := ValidateSocketName(n); err != nil {
			t.Errorf("ValidateSocketName(%q) = %v, want nil", n, err)
		}
	}
	// Everything about the path but this component comes from the
	// sandbox, so a separator or a parent reference here would let a
	// request name a socket anywhere on the execute node.
	bad := []string{"", ".", "..", "a/b", "../etc/x", "a\x00b", "a b", "sock;rm", strings.Repeat("x", 65)}
	for _, n := range bad {
		if err := ValidateSocketName(n); err == nil {
			t.Errorf("ValidateSocketName(%q) = nil, want an error", n)
		}
	}
}

// TestUnixPathLengthIsRefusedWithAReason: sun_path is ~104 bytes and
// both ends of a forward are bound by it, but the kernel's complaint
// arrives as "open failed" and names nothing. A pool whose EXECUTE
// directory is too deep should be told that, not left guessing.
func TestUnixPathLengthIsRefusedWithAReason(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	deep := "/" + strings.Repeat("longdir/", 14) + "scratch"
	d.mu.Lock()
	d.scratch = deep + "\n"
	d.mu.Unlock()

	_, err := c.DialJobUnix(context.Background(), testKey, "vscode.sock")
	if err == nil {
		t.Fatal("DialJobUnix accepted a path over the sun_path limit")
	}
	if !strings.Contains(err.Error(), "Unix socket address allows") {
		t.Errorf("error %q does not explain the sun_path limit", err)
	}
}

// TestSessionHoldsTheTransportOpen is the rule that matters most: an
// interactive shell can sit silent for an hour, so a held session must
// count as a live user of the transport exactly as a forwarded
// connection does, or the reaper closes it out from under the user.
func TestSessionHoldsTheTransportOpen(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }

	d := &fakeDialer{}
	c := newTestCache(t, d, now)

	_, release, err := c.Session(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}

	clock.Add(int64(24 * time.Hour))
	c.reapOnce()
	if c.Len() != 1 {
		t.Fatal("the reaper closed a transport with a session open")
	}

	release()
	clock.Add(int64(24 * time.Hour))
	c.reapOnce()
	if c.Len() != 0 {
		t.Errorf("transport was not reaped after its session was released; Len = %d", c.Len())
	}
}

// TestSessionCapIsRefusedWithAReason: the generated sshd sets no
// MaxSessions, so OpenSSH's default of 10 applies -- per CONNECTION.
// Sharing a transport makes that one budget for every terminal and
// command on a job, and the far end rejects the eleventh channel with
// nothing an operator can act on.
func TestSessionCapIsRefusedWithAReason(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	var releases []func()
	for i := 0; i < MaxSessionsPerTransport; i++ {
		_, rel, err := c.Session(context.Background(), testKey)
		if err != nil {
			t.Fatalf("session %d of %d: %v", i+1, MaxSessionsPerTransport, err)
		}
		releases = append(releases, rel)
	}

	_, _, err := c.Session(context.Background(), testKey)
	if err == nil {
		t.Fatalf("session %d was allowed past the cap", MaxSessionsPerTransport+1)
	}
	if !errors.Is(err, ErrTooManySessions) {
		t.Errorf("error %v is not ErrTooManySessions", err)
	}
	if !strings.Contains(err.Error(), "session budget") {
		t.Errorf("error %q does not explain the shared budget", err)
	}

	// Releasing one makes room again, or the cap would be a one-way
	// door for a long-lived transport.
	releases[0]()
	if _, rel, rerr := c.Session(context.Background(), testKey); rerr != nil {
		t.Errorf("no room after a release: %v", rerr)
	} else {
		rel()
	}
	for _, rel := range releases[1:] {
		rel()
	}
	if got := c.LiveSessions(testKey); got != 0 {
		t.Errorf("LiveSessions = %d after releasing everything, want 0", got)
	}
}

// TestClosingOneSessionLeavesTheJobReachable: two terminals on one job
// share a transport, and the first to close must not take the second
// with it.
func TestClosingOneSessionLeavesTheJobReachable(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	_, releaseA, err := c.Session(context.Background(), testKey)
	if err != nil {
		t.Fatalf("first session: %v", err)
	}
	_, releaseB, err := c.Session(context.Background(), testKey)
	if err != nil {
		t.Fatalf("second session: %v", err)
	}
	if got := d.count(); got != 1 {
		t.Errorf("two sessions opened %d transports, want 1", got)
	}

	releaseA()

	if c.Len() != 1 {
		t.Fatal("releasing one session closed the transport the other is using")
	}
	d.mu.Lock()
	closed := d.conns[0].isClosed()
	d.mu.Unlock()
	if closed {
		t.Fatal("releasing one session closed the shared transport")
	}
	// The job is still reachable for the surviving session's owner.
	conn, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("job unreachable after one session closed: %v", err)
	}
	_ = conn.Close()

	releaseB()
}

// TestFailedSessionOpenDoesNotEvict mirrors the dial rule: a sandbox
// that cannot start a session right now says nothing about whether the
// transport is alive.
func TestFailedSessionOpenDoesNotEvict(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	if _, rel, err := c.Session(context.Background(), testKey); err != nil {
		t.Fatalf("first session: %v", err)
	} else {
		rel()
	}

	d.mu.Lock()
	d.conns[0].mu.Lock()
	d.conns[0].openErr = errors.New("sandbox busy")
	d.conns[0].mu.Unlock()
	d.mu.Unlock()

	for i := 0; i < 3; i++ {
		if _, _, err := c.Session(context.Background(), testKey); err == nil {
			t.Fatal("Session succeeded against a refusing sandbox")
		}
	}
	if got := d.count(); got != 1 {
		t.Errorf("a refused session cost %d transport dials, want 1", got)
	}
	if got := c.LiveSessions(testKey); got != 0 {
		t.Errorf("LiveSessions = %d after failed opens, want 0", got)
	}
}

// TestSocketAddressComesFromTheJob is the glidein case. Both ends of a
// Unix socket are capped at ~100 bytes of sun_path, and an EP running
// inside a SLURM job nests its execute/dir_N under the host batch
// system's -- so the scratch directory alone can exceed the limit
// before anything of ours is added. The job binds by bare name and
// publishes an address short enough to connect to; joining the scratch
// path would refuse to work on exactly the pools this is for.
func TestSocketAddressComesFromTheJob(t *testing.T) {
	deep := "/" + strings.Repeat("glide_dir/", 12) + "execute/dir_9"
	if len(deep) <= maxUnixPath {
		t.Fatalf("the test's own path is only %d bytes; it is not exercising the limit", len(deep))
	}

	d := &fakeDialer{scratch: deep + "\n"}
	c := newTestCache(t, d, nil)
	d.mu.Lock()
	d.publishedPath = "/proc/4242/cwd/vscode.sock"
	d.mu.Unlock()

	got, err := c.SocketPath(context.Background(), testKey, "vscode.sock")
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if got != "/proc/4242/cwd/vscode.sock" {
		t.Errorf("SocketPath = %q, want the address the job published", got)
	}

	// Resolved once per transport: it is a round trip into the sandbox,
	// and a browser opens connections constantly.
	for i := 0; i < 4; i++ {
		if _, err := c.SocketPath(context.Background(), testKey, "vscode.sock"); err != nil {
			t.Fatalf("SocketPath %d: %v", i, err)
		}
	}
	d.mu.Lock()
	reads := d.conns[0].pathReads
	d.mu.Unlock()
	if reads != 1 {
		t.Errorf("asked the job for its socket address %d times, want 1", reads)
	}
}

// TestSocketAddressFallsBackWhenNothingPublished keeps a job that
// predates this, or one set up by hand, working wherever the joined
// path fits.
func TestSocketAddressFallsBackWhenNothingPublished(t *testing.T) {
	d := &fakeDialer{scratch: "/var/lib/condor/execute/dir_42\n"}
	c := newTestCache(t, d, nil)

	got, err := c.SocketPath(context.Background(), testKey, "vscode.sock")
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if got != "/var/lib/condor/execute/dir_42/vscode.sock" {
		t.Errorf("SocketPath = %q, want the joined path", got)
	}
}

// TestSocketAddressRefusesWhatCannotWork: a published address that is
// relative would be resolved by sshd against its own working directory
// rather than the sandbox's, and one over the limit fails in the kernel
// with nothing to go on. Both are worth naming here.
func TestSocketAddressRefusesWhatCannotWork(t *testing.T) {
	deep := "/" + strings.Repeat("glide_dir/", 12) + "execute/dir_9"

	relative := &fakeDialer{scratch: deep + "\n", publishedPath: "vscode.sock"}
	c1 := newTestCache(t, relative, nil)
	if _, err := c1.SocketPath(context.Background(), testKey, "vscode.sock"); err == nil {
		t.Error("a relative published address was accepted")
	} else if !strings.Contains(err.Error(), "relative") {
		t.Errorf("error %q does not say the address is relative", err)
	}

	long := &fakeDialer{scratch: deep + "\n", publishedPath: "/" + strings.Repeat("x", maxUnixPath+10)}
	c2 := newTestCache(t, long, nil)
	if _, err := c2.SocketPath(context.Background(), testKey, "vscode.sock"); err == nil {
		t.Error("an over-long published address was accepted")
	}

	// And with nothing published at all, the refusal says what the job
	// has to do about it.
	none := &fakeDialer{scratch: deep + "\n"}
	c3 := newTestCache(t, none, nil)
	if _, err := c3.SocketPath(context.Background(), testKey, "vscode.sock"); err == nil {
		t.Error("a scratch path over the limit was accepted with nothing published")
	} else if !strings.Contains(err.Error(), "somewhere shorter and publish where") {
		t.Errorf("error %q does not say what the job must do", err)
	}
}

// TestSocketAddressIsNotCachedBeforeItIsPublished reproduces a session
// that sat at "starting" forever while the job was running perfectly
// well and ssh-to-job worked.
//
// The first probe lands in the seconds before the server has written
// its address. The lookup falls back to joining the scratch path, and
// caching that guess meant every later request got it too -- including
// long after the server had published a real address somewhere else.
func TestSocketAddressIsNotCachedBeforeItIsPublished(t *testing.T) {
	d := &fakeDialer{scratch: "/var/lib/condor/execute/dir_42\n"}
	c := newTestCache(t, d, nil)

	// Nothing published yet: the answer is a guess.
	first, err := c.SocketPath(context.Background(), testKey, "vscode.sock")
	if err != nil {
		t.Fatalf("SocketPath: %v", err)
	}
	if first != "/var/lib/condor/execute/dir_42/vscode.sock" {
		t.Fatalf("first answer = %q, want the joined guess", first)
	}

	// The server comes up and publishes where it actually bound.
	d.mu.Lock()
	d.conns[0].mu.Lock()
	d.conns[0].published = "/tmp/.condor-app-4242/s"
	d.conns[0].mu.Unlock()
	d.mu.Unlock()

	second, err := c.SocketPath(context.Background(), testKey, "vscode.sock")
	if err != nil {
		t.Fatalf("SocketPath after publish: %v", err)
	}
	if second != "/tmp/.condor-app-4242/s" {
		t.Errorf("after the server published its address, SocketPath still answers %q; "+
			"a guess was cached and the session can never become reachable", second)
	}

	// Now that it is authoritative, it is cached: no more asking.
	d.mu.Lock()
	before := d.conns[0].pathReads
	d.mu.Unlock()
	for i := 0; i < 3; i++ {
		if _, err := c.SocketPath(context.Background(), testKey, "vscode.sock"); err != nil {
			t.Fatalf("SocketPath %d: %v", i, err)
		}
	}
	d.mu.Lock()
	after := d.conns[0].pathReads
	d.mu.Unlock()
	if after != before {
		t.Errorf("a published address was re-asked %d more times; it should be cached", after-before)
	}
}

// TestAWorkingGuessIsRemembered: a job that publishes nothing still
// works wherever the joined path fits, and must not pay a command in
// the sandbox for every connection a browser opens.
func TestAWorkingGuessIsRemembered(t *testing.T) {
	d := &fakeDialer{scratch: "/var/lib/condor/execute/dir_42\n"}
	c := newTestCache(t, d, nil)

	for i := 0; i < 4; i++ {
		conn, err := c.DialJobUnix(context.Background(), testKey, "vscode.sock")
		if err != nil {
			t.Fatalf("DialJobUnix %d: %v", i, err)
		}
		_ = conn.Close()
	}
	d.mu.Lock()
	reads := d.conns[0].pathReads
	d.mu.Unlock()
	if reads != 1 {
		t.Errorf("asked the sandbox %d times for a guess that works, want 1", reads)
	}
}

// TestWarmOpensTheTransportOnce is what the SSH gateway gets out of
// warming: the handshake is paid for by a request the client chose the
// deadline of, and the connection that follows finds it done.
func TestWarmOpensTheTransportOnce(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	reused, err := c.Warm(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Warm: %v", err)
	}
	if reused {
		t.Error("the first warm cannot have reused anything")
	}
	if d.count() != 1 {
		t.Fatalf("dials = %d, want 1", d.count())
	}

	reused, err = c.Warm(context.Background(), testKey)
	if err != nil {
		t.Fatalf("second Warm: %v", err)
	}
	if !reused {
		t.Error("the second warm should report that there was nothing to do")
	}
	if d.count() != 1 {
		t.Errorf("dials = %d after warming twice, want 1", d.count())
	}
}

// TestConnectingAfterWarmDoesNotDialAgain is the claim the endpoint
// makes to its caller. If this does not hold, warming costs a
// handshake and saves nothing.
func TestConnectingAfterWarmDoesNotDialAgain(t *testing.T) {
	d := &fakeDialer{}
	c := newTestCache(t, d, nil)

	if _, err := c.Warm(context.Background(), testKey); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	conn, err := c.DialJob(context.Background(), testKey, "tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("DialJob: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if d.count() != 1 {
		t.Errorf("dials = %d, want 1: the connection should have found a warm transport", d.count())
	}
}

// TestWarmReportsAFailureRatherThanCachingIt. A job that cannot be
// reached must not leave an entry behind claiming otherwise, or the
// next caller is told it is warm and then fails anyway.
func TestWarmReportsAFailureRatherThanCachingIt(t *testing.T) {
	d := &fakeDialer{err: errors.New("no route to the execute node")}
	c := newTestCache(t, d, nil)

	if _, err := c.Warm(context.Background(), testKey); err == nil {
		t.Fatal("Warm should have failed")
	}
	if n := c.Len(); n != 0 {
		t.Errorf("cache holds %d entries after a failed warm, want 0", n)
	}

	d.mu.Lock()
	d.err = nil
	d.mu.Unlock()
	reused, err := c.Warm(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Warm after recovery: %v", err)
	}
	if reused {
		t.Error("a failed warm must not look like a warm transport to the next caller")
	}
}

// TestWarmDoesNotPinTheTransport: warming takes no reference, so the
// reaper can still retire a transport nobody went on to use.
func TestWarmDoesNotPinTheTransport(t *testing.T) {
	now := time.Now()
	d := &fakeDialer{}
	c := newTestCache(t, d, func() time.Time { return now })

	if _, err := c.Warm(context.Background(), testKey); err != nil {
		t.Fatalf("Warm: %v", err)
	}
	now = now.Add(2 * time.Hour)
	c.reapOnce()

	if n := c.Len(); n != 0 {
		t.Errorf("cache holds %d entries after the idle timeout, want 0", n)
	}
}
