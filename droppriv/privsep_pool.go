package droppriv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Environment variables that mark and configure a re-exec'd helper. They are
// intentionally obscure so a normal process never mistakes itself for a helper.
const (
	helperEnvSentinel = "__DROPPRIV_HELPER"
	helperEnvSwitch   = "__DROPPRIV_HELPER_SWITCH"
	helperEnvUID      = "__DROPPRIV_HELPER_UID"
	helperEnvGID      = "__DROPPRIV_HELPER_GID"
	// helperControlFD is the descriptor number the control socket lands on in
	// the child: exec dup's ExtraFiles starting at fd 3.
	helperControlFD = 3
)

// Tunables for pool lifecycle behavior.
const (
	acquireWaitBudget   = 5 * time.Second
	helperShutdownGrace = 3 * time.Second
)

// helperKey identifies the credential class a helper serves. Helpers are reused
// only for the same key.
type helperKey string

const keySelf helperKey = "self"

func keyPrivileged(id Identity) helperKey {
	return helperKey(fmt.Sprintf("id:%d:%d", id.UID, id.GID))
}

func keyNamed(name string) helperKey {
	return helperKey("name:" + name)
}

// helper is one live (or test-injected) helper process.
type helper struct {
	key      helperKey
	conn     *msgConn
	cmd      *exec.Cmd // nil for test-injected helpers
	switched bool
	busy     bool
	broken   bool
	lastUsed time.Time
}

// pool is the pooled-helper Privsep backend.
type pool struct {
	mgr         *Manager
	maxHelpers  int
	idleTimeout time.Duration
	forceUnpriv bool

	mu      sync.Mutex
	cond    *sync.Cond
	helpers []*helper
	closed  bool

	// spawnFn is injectable so tests can drive the cap/eviction bookkeeping
	// without launching real processes. Nil uses spawnHelper.
	spawnFn func(key helperKey, target *Identity, switchCreds bool) (*helper, error)

	reaperStop chan struct{}
	reaperDone chan struct{}
}

var _ Privsep = (*pool)(nil)

func newPool(cfg PrivsepConfig, mgr *Manager) *pool {
	maxHelpers := cfg.MaxHelpers
	if maxHelpers <= 0 {
		maxHelpers = defaultMaxHelpers
	}
	idle := cfg.HelperIdleTimeout
	if idle <= 0 {
		idle = defaultHelperIdleTimeout
	}
	p := &pool{
		mgr:         mgr,
		maxHelpers:  maxHelpers,
		idleTimeout: idle,
		forceUnpriv: cfg.ForceHelperUnprivileged,
		reaperStop:  make(chan struct{}),
		reaperDone:  make(chan struct{}),
	}
	p.cond = sync.NewCond(&p.mu)
	p.spawnFn = p.spawnHelper
	go p.reapLoop()
	return p
}

// canSwitchCredentials reports whether this process can permanently switch a
// helper's credentials: privileged Linux.
func canSwitchCredentials() bool {
	return runtime.GOOS == "linux" && os.Geteuid() == 0
}

// resolveTarget maps a user to a helper key, a target identity, and whether the
// helper should switch credentials.
func (p *pool) resolveTarget(user string) (helperKey, *Identity, bool, error) {
	if strings.TrimSpace(user) == "" {
		return keySelf, nil, false, nil
	}
	if err := validateUsername(user); err != nil {
		return "", nil, false, err
	}
	id, err := p.mgr.resolveUser(user)
	if err != nil {
		return "", nil, false, err
	}
	if !p.forceUnpriv && canSwitchCredentials() {
		return keyPrivileged(id), &id, true, nil
	}
	// Unprivileged / forced-test mode: key by requested name so distinct users
	// map to distinct helpers even when they share a uid, and never switch.
	return keyNamed(user), &id, false, nil
}

// ---- pool acquire / checkin / eviction -------------------------------------

// acquire returns a busy-marked helper for key, spawning or evicting as needed.
func (p *pool) acquire(ctx context.Context, key helperKey, target *Identity, switchCreds bool) (*helper, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	deadline := time.Now().Add(acquireWaitBudget)
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		if p.closed {
			return nil, ErrPoolClosed
		}

		// Reuse an idle helper with a matching key.
		if h := p.findIdle(key); h != nil {
			h.busy = true
			return h, nil
		}

		// Room to spawn another helper?
		if len(p.helpers) < p.maxHelpers {
			return p.spawnLocked(key, target, switchCreds)
		}

		// At capacity: evict the least-recently-used idle helper, then spawn.
		if victim := p.lruIdle(); victim != nil {
			p.removeLocked(victim)
			p.shutdownAsync(victim)
			return p.spawnLocked(key, target, switchCreds)
		}

		// Everything is busy. Wait for a checkin, bounded by the budget.
		if time.Now().After(deadline) {
			return nil, ErrPoolExhausted
		}
		if timer == nil {
			timer = time.AfterFunc(time.Until(deadline), func() {
				p.mu.Lock()
				p.cond.Broadcast()
				p.mu.Unlock()
			})
		}
		p.cond.Wait()
	}
}

func (p *pool) findIdle(key helperKey) *helper {
	for _, h := range p.helpers {
		if !h.busy && !h.broken && h.key == key {
			return h
		}
	}
	return nil
}

func (p *pool) lruIdle() *helper {
	var victim *helper
	for _, h := range p.helpers {
		if h.busy || h.broken {
			continue
		}
		if victim == nil || h.lastUsed.Before(victim.lastUsed) {
			victim = h
		}
	}
	return victim
}

// spawnLocked spawns a new helper and registers it as busy. Called with p.mu
// held; spawning execs a process but is brief.
func (p *pool) spawnLocked(key helperKey, target *Identity, switchCreds bool) (*helper, error) {
	h, err := p.spawnFn(key, target, switchCreds)
	if err != nil {
		return nil, err
	}
	h.busy = true
	h.lastUsed = time.Now()
	p.helpers = append(p.helpers, h)
	return h, nil
}

func (p *pool) removeLocked(h *helper) {
	for i, existing := range p.helpers {
		if existing == h {
			p.helpers = append(p.helpers[:i], p.helpers[i+1:]...)
			return
		}
	}
}

// checkin returns a helper to the idle set (or discards it if broken).
func (p *pool) checkin(h *helper) {
	p.mu.Lock()
	if h.broken {
		p.removeLocked(h)
		p.mu.Unlock()
		p.shutdownAsync(h)
		p.mu.Lock()
	} else {
		h.busy = false
		h.lastUsed = time.Now()
	}
	p.cond.Broadcast()
	p.mu.Unlock()
}

// discard removes a helper permanently (used after an RPC failure).
func (p *pool) discard(h *helper) {
	p.mu.Lock()
	p.removeLocked(h)
	p.mu.Unlock()
	p.shutdownAsync(h)
	p.mu.Lock()
	p.cond.Broadcast()
	p.mu.Unlock()
}

// shutdownAsync closes a helper's socket and reaps its process in the
// background so a lock holder never blocks on process teardown.
func (p *pool) shutdownAsync(h *helper) {
	go shutdownHelper(h)
}

// shutdownHelper closes the control socket (which makes the helper exit on EOF)
// and waits for the process, killing it if it overstays the grace period, so no
// helper is ever orphaned or left as a zombie.
func shutdownHelper(h *helper) {
	if h.conn != nil {
		_ = h.conn.close()
	}
	if h.cmd == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_ = h.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(helperShutdownGrace):
		if h.cmd.Process != nil {
			_ = h.cmd.Process.Kill()
		}
		<-done
	}
}

// reapLoop periodically closes helpers idle longer than idleTimeout.
func (p *pool) reapLoop() {
	defer close(p.reaperDone)
	interval := p.idleTimeout / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.reaperStop:
			return
		case <-ticker.C:
			p.reapIdle()
		}
	}
}

func (p *pool) reapIdle() {
	now := time.Now()
	var victims []*helper
	p.mu.Lock()
	kept := p.helpers[:0]
	for _, h := range p.helpers {
		if !h.busy && !h.broken && now.Sub(h.lastUsed) > p.idleTimeout {
			victims = append(victims, h)
			continue
		}
		kept = append(kept, h)
	}
	p.helpers = kept
	p.mu.Unlock()
	for _, h := range victims {
		shutdownHelper(h)
	}
}

// Close shuts the pool down, reaping every helper.
func (p *pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	victims := p.helpers
	p.helpers = nil
	p.cond.Broadcast()
	p.mu.Unlock()

	close(p.reaperStop)
	<-p.reaperDone

	var wg sync.WaitGroup
	for _, h := range victims {
		wg.Add(1)
		go func(h *helper) {
			defer wg.Done()
			shutdownHelper(h)
		}(h)
	}
	wg.Wait()
	return nil
}

// ---- client-side RPC -------------------------------------------------------

func (p *pool) rpc(h *helper, req *wireRequest, passFDs []int) (*wireResponse, []int, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	if err := h.conn.send(payload, passFDs); err != nil {
		h.broken = true
		return nil, nil, err
	}
	respPayload, fds, err := h.conn.recv()
	if err != nil {
		h.broken = true
		closeFDs(fds)
		return nil, nil, err
	}
	var resp wireResponse
	if err := json.Unmarshal(respPayload, &resp); err != nil {
		h.broken = true
		closeFDs(fds)
		return nil, nil, err
	}
	return &resp, fds, nil
}

// simpleOp runs a request that returns no descriptors and reports only an error.
func (p *pool) simpleOp(ctx context.Context, user string, build func(target *Identity) *wireRequest) error {
	key, target, sw, err := p.resolveTarget(user)
	if err != nil {
		return err
	}
	h, err := p.acquire(ctx, key, target, sw)
	if err != nil {
		return err
	}
	resp, fds, rpcErr := p.rpc(h, build(target), nil)
	closeFDs(fds)
	if rpcErr != nil {
		p.discard(h)
		return rpcErr
	}
	p.checkin(h)
	return wireToError(resp)
}

func (p *pool) OpenFile(ctx context.Context, user, path string, flag int, perm os.FileMode) (*os.File, error) {
	key, target, sw, err := p.resolveTarget(user)
	if err != nil {
		return nil, err
	}
	h, err := p.acquire(ctx, key, target, sw)
	if err != nil {
		return nil, err
	}
	req := &wireRequest{Op: opOpenFile, Path: path, Flag: flag, Perm: uint32(perm)}
	resp, fds, rpcErr := p.rpc(h, req, nil)
	if rpcErr != nil {
		p.discard(h)
		return nil, rpcErr
	}
	p.checkin(h)
	if opErr := wireToError(resp); opErr != nil {
		closeFDs(fds)
		return nil, opErr
	}
	if len(fds) != 1 {
		closeFDs(fds)
		return nil, fmt.Errorf("droppriv: OpenFile expected one descriptor, got %d", len(fds))
	}
	//nolint:gosec // G115 - fds[0] is a kernel file descriptor from recvmsg, always a small non-negative int.
	return os.NewFile(uintptr(fds[0]), path), nil
}

func (p *pool) MkdirAll(ctx context.Context, user, path string, perm os.FileMode) error {
	return p.simpleOp(ctx, user, func(_ *Identity) *wireRequest {
		return &wireRequest{Op: opMkdirAll, Path: path, Perm: uint32(perm)}
	})
}

func (p *pool) Chown(ctx context.Context, user, path string, uid, gid int) error {
	return p.simpleOp(ctx, user, func(_ *Identity) *wireRequest {
		return &wireRequest{Op: opChown, Path: path, UID: uid, GID: gid}
	})
}

func (p *pool) Remove(ctx context.Context, user, path string) error {
	return p.simpleOp(ctx, user, func(_ *Identity) *wireRequest {
		return &wireRequest{Op: opRemove, Path: path}
	})
}

func (p *pool) Rename(ctx context.Context, user, oldpath, newpath string) error {
	return p.simpleOp(ctx, user, func(_ *Identity) *wireRequest {
		return &wireRequest{Op: opRename, Path: oldpath, NewPath: newpath}
	})
}

func (p *pool) Stat(ctx context.Context, user, path string) (os.FileInfo, error) {
	key, target, sw, err := p.resolveTarget(user)
	if err != nil {
		return nil, err
	}
	h, err := p.acquire(ctx, key, target, sw)
	if err != nil {
		return nil, err
	}
	resp, fds, rpcErr := p.rpc(h, &wireRequest{Op: opStat, Path: path}, nil)
	closeFDs(fds)
	if rpcErr != nil {
		p.discard(h)
		return nil, rpcErr
	}
	p.checkin(h)
	if opErr := wireToError(resp); opErr != nil {
		return nil, opErr
	}
	if resp.Stat == nil {
		return nil, fmt.Errorf("droppriv: Stat returned no info")
	}
	return &remoteFileInfo{w: *resp.Stat}, nil
}

func (p *pool) Command(ctx context.Context, user string, spec CommandSpec) (Process, error) {
	key, target, sw, err := p.resolveTarget(user)
	if err != nil {
		return nil, err
	}
	h, err := p.acquire(ctx, key, target, sw)
	if err != nil {
		return nil, err
	}

	req := &wireRequest{
		Op:        opCommand,
		CmdPath:   spec.Path,
		Args:      spec.Args,
		Dir:       spec.Dir,
		Env:       spec.Env,
		HasStdin:  spec.Stdin != nil,
		HasStdout: spec.Stdout != nil,
		HasStderr: spec.Stderr != nil,
	}
	var passFDs []int
	for _, f := range []*os.File{spec.Stdin, spec.Stdout, spec.Stderr} {
		if f != nil {
			//nolint:gosec // G115 - Fd() returns a kernel descriptor, a small non-negative int.
			passFDs = append(passFDs, int(f.Fd()))
		}
	}

	resp, fds, rpcErr := p.rpc(h, req, passFDs)
	closeFDs(fds)
	if rpcErr != nil {
		p.discard(h)
		return nil, rpcErr
	}
	if opErr := wireToError(resp); opErr != nil {
		p.checkin(h)
		return nil, opErr
	}
	// The helper holds the child; keep the helper leased until Wait releases it.
	return &poolProcess{pool: p, h: h, pid: resp.Pid}, nil
}

// poolProcess is the Process handle for a pool-launched child.
type poolProcess struct {
	pool     *pool
	h        *helper
	pid      int
	waitOnce sync.Once
	waitErr  error
}

func (p *poolProcess) Pid() int { return p.pid }

func (p *poolProcess) Wait() error {
	p.waitOnce.Do(func() {
		resp, fds, rpcErr := p.pool.rpc(p.h, &wireRequest{Op: opWait}, nil)
		closeFDs(fds)
		if rpcErr != nil {
			p.pool.discard(p.h)
			p.waitErr = rpcErr
			return
		}
		p.pool.checkin(p.h)
		if opErr := wireToError(resp); opErr != nil {
			p.waitErr = opErr
			return
		}
		if resp.Signaled {
			p.waitErr = &ProcessExitError{Signaled: true, Signal: resp.Signal}
			return
		}
		if resp.ExitCode != 0 {
			p.waitErr = &ProcessExitError{Code: resp.ExitCode}
		}
	})
	return p.waitErr
}

func (p *poolProcess) Signal(sig os.Signal) error {
	s, ok := sig.(syscall.Signal)
	if !ok {
		return fmt.Errorf("droppriv: unsupported signal type %T", sig)
	}
	return syscall.Kill(p.pid, s)
}

// ---- helper spawning (parent side) -----------------------------------------

// spawnHelper re-execs the current binary as a helper, wiring an inherited
// AF_UNIX socketpair as the control channel.
func (p *pool) spawnHelper(key helperKey, target *Identity, switchCreds bool) (*helper, error) {
	// Create the control socketpair with both ends close-on-exec, under
	// ForkLock so no concurrent fork inherits them. The child end is handed to
	// the helper via ExtraFiles, which re-dups it (clearing cloexec) onto fd 3;
	// the parent end must NOT leak into the helper, otherwise the helper would
	// hold its own copy of the parent end and never see EOF when the parent
	// closes the socket. Marking both cloexec also stops one helper from
	// inheriting another helper's control descriptors.
	syscall.ForkLock.Lock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.Unlock()
	if err != nil {
		return nil, fmt.Errorf("droppriv: socketpair: %w", err)
	}
	parentFD, childFD := fds[0], fds[1]

	//nolint:gosec // G115 - childFD is a kernel descriptor from socketpair, a small non-negative int.
	childFile := os.NewFile(uintptr(childFD), "droppriv-helper-ctl")

	exe, err := os.Executable()
	if err != nil {
		_ = syscall.Close(parentFD)
		_ = childFile.Close()
		return nil, fmt.Errorf("droppriv: os.Executable: %w", err)
	}

	//nolint:gosec // G204 - re-executing our own binary (os.Executable) as a helper; no external command is run.
	cmd := exec.CommandContext(context.Background(), exe)
	cmd.Env = append(os.Environ(), helperEnvSentinel+"=1")
	if switchCreds && target != nil {
		cmd.Env = append(cmd.Env,
			helperEnvSwitch+"=1",
			fmt.Sprintf("%s=%d", helperEnvUID, target.UID),
			fmt.Sprintf("%s=%d", helperEnvGID, target.GID),
		)
	}
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	setChildPdeathsig(cmd.SysProcAttr)

	if err := cmd.Start(); err != nil {
		_ = syscall.Close(parentFD)
		_ = childFile.Close()
		return nil, fmt.Errorf("droppriv: starting helper: %w", err)
	}
	// The child owns its dup of the socket; the parent keeps only its end.
	_ = childFile.Close()

	return &helper{
		key:      key,
		conn:     newMsgConn(parentFD),
		cmd:      cmd,
		switched: switchCreds,
	}, nil
}

// ---- helper serve loop (child side) ----------------------------------------

// RunHelperIfRequested must be called at the very top of a consuming program's
// main(). If the current process is a droppriv helper (detected via a private
// environment sentinel set during re-exec), it switches credentials if
// requested, serves the control protocol on the inherited socket, and exits
// when the parent closes the channel or dies — it never returns to the caller.
// In a normal (non-helper) process it returns immediately so main() proceeds.
func RunHelperIfRequested() {
	if os.Getenv(helperEnvSentinel) != "1" {
		return
	}
	os.Exit(runHelper())
}

func runHelper() int {
	if os.Getenv(helperEnvSwitch) == "1" {
		uid, err1 := strconv.Atoi(os.Getenv(helperEnvUID))
		gid, err2 := strconv.Atoi(os.Getenv(helperEnvGID))
		if err1 != nil || err2 != nil {
			fmt.Fprintln(os.Stderr, "droppriv helper: bad uid/gid env")
			return 2
		}
		//nolint:gosec // G115 - uid/gid come from our own parent, within uint32 range.
		if err := switchHelperCredentials(Identity{UID: uint32(uid), GID: uint32(gid)}); err != nil {
			fmt.Fprintf(os.Stderr, "droppriv helper: credential switch failed: %v\n", err)
			return 3
		}
	}

	// After any credential switch so the dumpable-flag reset does not clear it.
	helperSetParentDeathSignal()

	conn := newMsgConn(helperControlFD)
	serveHelper(conn)
	return 0
}

// serveHelper runs the request/reply loop until the control socket reports EOF
// (parent closed or died) or an unrecoverable protocol error.
func serveHelper(conn *msgConn) {
	var cmd *exec.Cmd // the currently launched child, awaiting opWait
	for {
		payload, inFDs, err := conn.recv()
		if err != nil {
			// Any recv error (clean EOF or broken pipe) means the parent is
			// gone or the channel is unusable; exit so the helper never lingers.
			closeFDs(inFDs)
			return
		}
		var req wireRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			closeFDs(inFDs)
			resp := &wireResponse{Err: "droppriv helper: bad request: " + err.Error()}
			if sendErr := replyHelper(conn, resp, nil); sendErr != nil {
				return
			}
			continue
		}

		resp, passFD, newCmd := handleRequest(&req, inFDs, cmd)
		if newCmd != nil {
			cmd = newCmd
		}
		if req.Op == opWait {
			cmd = nil
		}
		var passFDs []int
		if passFD != nil {
			//nolint:gosec // G115 - Fd() returns a kernel descriptor, a small non-negative int.
			passFDs = []int{int(passFD.Fd())}
		}
		if err := replyHelper(conn, resp, passFDs); err != nil {
			if passFD != nil {
				_ = passFD.Close()
			}
			return
		}
		if passFD != nil {
			_ = passFD.Close()
		}
	}
}

func replyHelper(conn *msgConn, resp *wireResponse, passFDs []int) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		payload = []byte(`{"err":"droppriv helper: marshal failed"}`)
	}
	return conn.send(payload, passFDs)
}

// handleRequest executes one request in the helper. It returns the response, an
// optional *os.File whose descriptor must be passed back (OpenFile), and an
// optional newly launched child to remember for a subsequent opWait.
func handleRequest(req *wireRequest, inFDs []int, current *exec.Cmd) (*wireResponse, *os.File, *exec.Cmd) {
	resp := &wireResponse{}
	switch req.Op {
	case opPing:
		return resp, nil, nil
	case opOpenFile:
		//nolint:gosec // G304 - the path originates from the trusted schedd/shadow caller; access is enforced by the helper's dropped credentials.
		f, err := os.OpenFile(req.Path, req.Flag, os.FileMode(req.Perm))
		if err != nil {
			errorToWire(resp, err)
			return resp, nil, nil
		}
		return resp, f, nil
	case opMkdirAll:
		errorToWire(resp, os.MkdirAll(req.Path, os.FileMode(req.Perm)))
		return resp, nil, nil
	case opChown:
		errorToWire(resp, os.Chown(req.Path, req.UID, req.GID))
		return resp, nil, nil
	case opRemove:
		errorToWire(resp, os.Remove(req.Path))
		return resp, nil, nil
	case opRename:
		errorToWire(resp, os.Rename(req.Path, req.NewPath))
		return resp, nil, nil
	case opStat:
		fi, err := os.Stat(req.Path)
		if err != nil {
			errorToWire(resp, err)
			return resp, nil, nil
		}
		resp.Stat = statToWire(fi)
		return resp, nil, nil
	case opCommand:
		cmd, err := startHelperChild(req, inFDs)
		if err != nil {
			errorToWire(resp, err)
			return resp, nil, nil
		}
		resp.Pid = cmd.Process.Pid
		return resp, nil, cmd
	case opWait:
		fillWaitResponse(resp, current)
		return resp, nil, nil
	default:
		resp.Err = "droppriv helper: unknown op " + req.Op
		return resp, nil, nil
	}
}

// startHelperChild forks/execs the requested command as the helper (which is
// already the target user). Received stdio descriptors become the child's
// streams; the helper closes its own copies after Start.
func startHelperChild(req *wireRequest, inFDs []int) (*exec.Cmd, error) {
	//nolint:gosec // G204 - argv originates from the trusted schedd/shadow caller.
	cmd := exec.CommandContext(context.Background(), req.CmdPath, req.Args...)
	cmd.Dir = req.Dir
	cmd.Env = req.Env

	var toClose []*os.File
	idx := 0
	next := func(present bool, name string) *os.File {
		if !present || idx >= len(inFDs) {
			return nil
		}
		//nolint:gosec // G115 - inFDs entries are kernel descriptors from recvmsg, small non-negative ints.
		f := os.NewFile(uintptr(inFDs[idx]), name)
		idx++
		toClose = append(toClose, f)
		return f
	}
	cmd.Stdin = fileReader(next(req.HasStdin, "stdin"))
	cmd.Stdout = fileWriter(next(req.HasStdout, "stdout"))
	cmd.Stderr = fileWriter(next(req.HasStderr, "stderr"))

	cmd.SysProcAttr = &syscall.SysProcAttr{}
	setChildPdeathsig(cmd.SysProcAttr)

	err := cmd.Start()
	// The child inherited its own dups; close the helper's copies regardless.
	for _, f := range toClose {
		_ = f.Close()
	}
	// Close any stray descriptors we did not consume.
	for ; idx < len(inFDs); idx++ {
		_ = syscall.Close(inFDs[idx])
	}
	if err != nil {
		return nil, err
	}
	return cmd, nil
}

// fileReader / fileWriter convert a possibly-nil *os.File into a truly nil
// io.Reader/io.Writer interface, so exec.Cmd connects the stream to /dev/null
// rather than dereferencing a typed-nil *os.File.
func fileReader(f *os.File) io.Reader {
	if f == nil {
		return nil
	}
	return f
}

func fileWriter(f *os.File) io.Writer {
	if f == nil {
		return nil
	}
	return f
}

func fillWaitResponse(resp *wireResponse, cmd *exec.Cmd) {
	if cmd == nil {
		resp.Err = "droppriv helper: no command to wait for"
		return
	}
	err := cmd.Wait()
	if err == nil {
		return
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				resp.Signaled = true
				resp.Signal = int(ws.Signal())
				return
			}
			resp.ExitCode = ws.ExitStatus()
			return
		}
	}
	errorToWire(resp, err)
}
