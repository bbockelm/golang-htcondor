package droppriv

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestMain lets the test binary double as a droppriv helper. When the pool
// re-execs this binary with the helper sentinel set, RunHelperIfRequested
// detects it, serves the control protocol, and exits without ever running the
// test suite. A real program wires this the same way at the top of main().
func TestMain(m *testing.M) {
	RunHelperIfRequested()
	os.Exit(m.Run())
}

// newTestPool builds an unprivileged forced pool with a manager pinned to the
// current identity so no credential switching is attempted in CI.
func newTestPool(t *testing.T, maxHelpers int) *pool {
	t.Helper()
	id, err := currentIdentity()
	if err != nil {
		t.Fatalf("currentIdentity: %v", err)
	}
	mgr := &Manager{
		enabled:          false,
		defaultIdentity:  id,
		originalIdentity: id,
		cachedIdentities: make(map[string]Identity),
	}
	ps, err := NewPrivsep(PrivsepConfig{
		Mode:                    ModePool,
		ForceHelperUnprivileged: true,
		MaxHelpers:              maxHelpers,
		Manager:                 mgr,
	})
	if err != nil {
		t.Fatalf("NewPrivsep: %v", err)
	}
	p, ok := ps.(*pool)
	if !ok {
		t.Fatalf("expected *pool, got %T", ps)
	}
	return p
}

// TestPoolOpenFileRoundTripsDescriptor is the crux: a real file descriptor is
// opened in the helper, passed back over the control socket via SCM_RIGHTS, and
// used for I/O in the parent.
func TestPoolOpenFileRoundTripsDescriptor(t *testing.T) {
	p := newTestPool(t, 4)
	defer mustClose(t, p)
	ctx := context.Background()

	path := filepath.Join(t.TempDir(), "roundtrip.txt")
	want := "hello via SCM_RIGHTS\n"

	wf, err := p.OpenFile(ctx, "", path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile (write): %v", err)
	}
	if _, err := wf.WriteString(want); err != nil {
		t.Fatalf("write through passed fd: %v", err)
	}
	if err := wf.Close(); err != nil {
		t.Fatalf("close write fd: %v", err)
	}

	rf, err := p.OpenFile(ctx, "", path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile (read): %v", err)
	}
	got, err := io.ReadAll(rf)
	_ = rf.Close()
	if err != nil {
		t.Fatalf("read through passed fd: %v", err)
	}
	if string(got) != want {
		t.Fatalf("round-trip mismatch: got %q want %q", got, want)
	}
}

func TestPoolOpenFileError(t *testing.T) {
	p := newTestPool(t, 2)
	defer mustClose(t, p)
	ctx := context.Background()

	_, err := p.OpenFile(ctx, "", filepath.Join(t.TempDir(), "missing", "x"), os.O_RDONLY, 0)
	if err == nil {
		t.Fatal("expected error opening nonexistent path")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected ErrNotExist, got %v", err)
	}
}

func TestPoolFilesystemOps(t *testing.T) {
	p := newTestPool(t, 4)
	defer mustClose(t, p)
	ctx := context.Background()
	base := t.TempDir()

	dir := filepath.Join(base, "a", "b", "c")
	if err := p.MkdirAll(ctx, "", dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("MkdirAll did not create dir: %v", err)
	}

	// Stat via the pool returns a RemoteStat carrying uid/gid.
	fi, err := p.Stat(ctx, "", dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("Stat says not a dir")
	}
	rs, ok := fi.Sys().(*RemoteStat)
	if !ok {
		t.Fatalf("Stat Sys() = %T, want *RemoteStat", fi.Sys())
	}
	//nolint:gosec // G115 - os.Getuid within uint32 range.
	if rs.UID != uint32(os.Getuid()) {
		t.Fatalf("Stat uid = %d, want %d", rs.UID, os.Getuid())
	}

	// Chown to our own uid/gid is a permitted no-op unprivileged.
	if err := p.Chown(ctx, "", dir, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("Chown (same uid no-op): %v", err)
	}

	// Rename then Remove.
	src := filepath.Join(base, "src.txt")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(base, "dst.txt")
	if err := p.Rename(ctx, "", src, dst); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := os.Stat(src); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source still exists after rename")
	}
	if err := p.Remove(ctx, "", dst); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file still exists after remove")
	}

	// Stat of a missing path yields ErrNotExist through the wire error path.
	if _, err := p.Stat(ctx, "", dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat missing = %v, want ErrNotExist", err)
	}
}

func TestPoolCommandRunsAndCapturesOutput(t *testing.T) {
	p := newTestPool(t, 4)
	defer mustClose(t, p)
	ctx := context.Background()

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	spec := CommandSpec{Path: "/bin/sh", Args: []string{"-c", "echo hi"}, Stdout: pw}
	proc, err := p.Command(ctx, "", spec)
	if err != nil {
		_ = pw.Close()
		_ = pr.Close()
		t.Fatalf("Command: %v", err)
	}
	// Parent no longer needs the write end; the child (via the helper) has it.
	_ = pw.Close()

	out, err := io.ReadAll(pr)
	_ = pr.Close()
	if err != nil {
		t.Fatalf("read child output: %v", err)
	}
	if err := proc.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if string(out) != "hi\n" {
		t.Fatalf("child output = %q, want %q", out, "hi\n")
	}
	if proc.Pid() <= 0 {
		t.Fatalf("expected a positive pid, got %d", proc.Pid())
	}
}

func TestPoolCommandNonZeroExit(t *testing.T) {
	p := newTestPool(t, 2)
	defer mustClose(t, p)
	ctx := context.Background()

	proc, err := p.Command(ctx, "", CommandSpec{Path: "/bin/sh", Args: []string{"-c", "exit 7"}})
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	err = proc.Wait()
	var exitErr *ProcessExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Wait err = %v, want *ProcessExitError", err)
	}
	if exitErr.Code != 7 {
		t.Fatalf("exit code = %d, want 7", exitErr.Code)
	}
}

// TestPoolCapAndLRUEviction drives the acquire/checkin bookkeeping directly with
// an injected spawner (no real processes), proving the live-helper count is
// bounded by MaxHelpers and that the least-recently-used idle helper is evicted.
func TestPoolCapAndLRUEviction(t *testing.T) {
	const maxHelpers = 3
	p := newTestPool(t, maxHelpers)
	defer mustClose(t, p)
	ctx := context.Background()

	var spawnCount int
	p.spawnFn = func(key helperKey, _ *Identity, _ bool) (*helper, error) {
		spawnCount++
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			return nil, err
		}
		// No process on the far end; close the child side immediately.
		_ = syscall.Close(fds[1])
		return &helper{key: key, conn: newMsgConn(fds[0])}, nil
	}

	// Fill the pool with three distinct keys, checking each in with a strictly
	// increasing lastUsed so LRU order is deterministic.
	keys := []helperKey{keyNamed("u0"), keyNamed("u1"), keyNamed("u2")}
	for _, k := range keys {
		h, err := p.acquire(ctx, k, nil, false)
		if err != nil {
			t.Fatalf("acquire %s: %v", k, err)
		}
		p.checkin(h)
		time.Sleep(2 * time.Millisecond)
	}
	if got := p.liveCount(); got != maxHelpers {
		t.Fatalf("live helpers = %d, want %d", got, maxHelpers)
	}

	// A fourth distinct key must evict the LRU idle helper (u0), not exceed cap.
	h, err := p.acquire(ctx, keyNamed("u3"), nil, false)
	if err != nil {
		t.Fatalf("acquire u3: %v", err)
	}
	p.checkin(h)
	if got := p.liveCount(); got != maxHelpers {
		t.Fatalf("after eviction live helpers = %d, want %d", got, maxHelpers)
	}
	if p.hasKey(keyNamed("u0")) {
		t.Fatalf("expected LRU key u0 to be evicted")
	}
	if !p.hasKey(keyNamed("u3")) {
		t.Fatalf("expected new key u3 present")
	}

	// Hammering many distinct keys must never exceed the cap.
	for i := 0; i < 30; i++ {
		hh, err := p.acquire(ctx, keyNamed("k"+itoa(i)), nil, false)
		if err != nil {
			t.Fatalf("acquire k%d: %v", i, err)
		}
		p.checkin(hh)
		if got := p.liveCount(); got > maxHelpers {
			t.Fatalf("live helpers = %d exceeds cap %d", got, maxHelpers)
		}
	}
	// Reusing an existing key must not spawn again.
	before := spawnCount
	reuse, err := p.acquire(ctx, keyNamed("k29"), nil, false)
	if err != nil {
		t.Fatalf("acquire reuse: %v", err)
	}
	p.checkin(reuse)
	if spawnCount != before {
		t.Fatalf("expected reuse of idle helper, but spawned again (%d -> %d)", before, spawnCount)
	}
}

// TestPoolReapsHelpersOnClose proves real helper processes are spawned and then
// fully reaped by Close, leaving no orphans.
func TestPoolReapsHelpersOnClose(t *testing.T) {
	p := newTestPool(t, 8)
	ctx := context.Background()

	// Spawn two real helper processes deterministically via distinct keys.
	h1, err := p.acquire(ctx, keyNamed("real-a"), nil, false)
	if err != nil {
		t.Fatalf("acquire real-a: %v", err)
	}
	p.checkin(h1)
	h2, err := p.acquire(ctx, keyNamed("real-b"), nil, false)
	if err != nil {
		t.Fatalf("acquire real-b: %v", err)
	}
	p.checkin(h2)

	// Also exercise a real op through the self helper.
	path := filepath.Join(t.TempDir(), "f")
	f, err := p.OpenFile(ctx, "", path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	_ = f.Close()

	pids := p.helperPids()
	if len(pids) < 2 {
		t.Fatalf("expected at least 2 helper processes, got %d", len(pids))
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After Close returns, every helper must be reaped (no orphan, no zombie).
	for _, pid := range pids {
		if processAlive(pid) {
			t.Fatalf("helper pid %d still alive after Close (orphan/zombie)", pid)
		}
	}
}

// TestHelperExitsOnControlSocketClose proves a helper exits on its own when the
// control channel drops — the portable backstop for parent-death safety.
func TestHelperExitsOnControlSocketClose(t *testing.T) {
	p := newTestPool(t, 4)
	defer mustClose(t, p)
	ctx := context.Background()

	h, err := p.acquire(ctx, keyNamed("death"), nil, false)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if h.cmd == nil || h.cmd.Process == nil {
		t.Fatal("expected a real helper process")
	}
	pid := h.cmd.Process.Pid

	// Detach so pool.Close won't also try to reap it.
	p.mu.Lock()
	p.removeLocked(h)
	p.mu.Unlock()

	// Dropping the parent's control-socket end makes the helper see EOF.
	_ = h.conn.close()

	done := make(chan error, 1)
	go func() { done <- h.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = h.cmd.Process.Kill()
		t.Fatalf("helper pid %d did not exit after control socket close", pid)
	}
	if processAlive(pid) {
		t.Fatalf("helper pid %d still alive after control socket close", pid)
	}
}

// TestNativeBackendInProcess verifies the native backend works unprivileged for
// the no-switch paths (user "").
func TestNativeBackendInProcess(t *testing.T) {
	id, err := currentIdentity()
	if err != nil {
		t.Fatalf("currentIdentity: %v", err)
	}
	mgr := &Manager{
		enabled:          false,
		defaultIdentity:  id,
		originalIdentity: id,
		cachedIdentities: make(map[string]Identity),
	}
	ps, err := NewPrivsep(PrivsepConfig{Mode: ModeNative, Manager: mgr})
	if err != nil {
		t.Fatalf("NewPrivsep native: %v", err)
	}
	defer mustClose(t, ps)
	ctx := context.Background()

	dir := filepath.Join(t.TempDir(), "n")
	if err := ps.MkdirAll(ctx, "", dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir, "f.txt")
	f, err := ps.OpenFile(ctx, "", path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.WriteString("native"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	fi, err := ps.Stat(ctx, "", path)
	if err != nil || fi.Size() != int64(len("native")) {
		t.Fatalf("Stat: %v size=%v", err, fi)
	}

	pr, pw, _ := os.Pipe()
	proc, err := ps.Command(ctx, "", CommandSpec{Path: "/bin/sh", Args: []string{"-c", "echo native-hi"}, Stdout: pw})
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	_ = pw.Close()
	out, _ := io.ReadAll(pr)
	_ = pr.Close()
	if err := proc.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if string(out) != "native-hi\n" {
		t.Fatalf("output = %q", out)
	}
}

// ---- test helpers ----------------------------------------------------------

func mustClose(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// liveCount returns the number of live helpers (test-only accessor).
func (p *pool) liveCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.helpers)
}

func (p *pool) hasKey(key helperKey) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, h := range p.helpers {
		if h.key == key {
			return true
		}
	}
	return false
}

func (p *pool) helperPids() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	var pids []int
	for _, h := range p.helpers {
		if h.cmd != nil && h.cmd.Process != nil {
			pids = append(pids, h.cmd.Process.Pid)
		}
	}
	return pids
}

// processAlive reports whether pid names a live process (signal 0 probe).
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
