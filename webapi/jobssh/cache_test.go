package jobssh

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeConn stands in for an *ssh.Client. dialErr, when set, is what
// DialContext returns -- the "nothing is listening on that port yet"
// case, which must not be confused with the transport dying.
type fakeConn struct {
	mu      sync.Mutex
	dialErr error
	dials   int
	closed  bool
	done    chan struct{} // closed to make Wait return, i.e. the job ended
}

func newFakeConn() *fakeConn { return &fakeConn{done: make(chan struct{})} }

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
	mu    sync.Mutex
	calls int
	conns []*fakeConn
	err   error
	delay time.Duration
}

func (d *fakeDialer) dial(_ context.Context, _ Key) (Conn, error) {
	d.mu.Lock()
	d.calls++
	err, delay := d.err, d.delay
	d.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
	if err != nil {
		return nil, err
	}
	c := newFakeConn()
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
