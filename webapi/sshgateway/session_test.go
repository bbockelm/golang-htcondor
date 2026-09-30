// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sshgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-htcondor/webapi/jobssh"
)

// fakeSession stands in for a session channel inside a sandbox. It
// records what the gateway asked for and lets a test drive the
// remote end's output and exit.
type fakeSession struct {
	mu sync.Mutex

	ptyTerm  string
	ptyRows  int
	ptyCols  int
	ptyModes ssh.TerminalModes
	winRows  int
	winCols  int
	started  string // "shell", or "exec: <cmd>"
	signals  []string

	stdinR  *io.PipeReader
	stdinW  *io.PipeWriter
	stdoutR *io.PipeReader
	stdoutW *io.PipeWriter
	stderrR *io.PipeReader
	stderrW *io.PipeWriter

	exit    chan struct{}
	waitErr error
	closed  bool
}

func newFakeSession() *fakeSession {
	f := &fakeSession{exit: make(chan struct{})}
	f.stdinR, f.stdinW = io.Pipe()
	f.stdoutR, f.stdoutW = io.Pipe()
	f.stderrR, f.stderrW = io.Pipe()
	return f
}

func (f *fakeSession) RequestPty(term string, h, w int, modes ssh.TerminalModes) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ptyTerm, f.ptyRows, f.ptyCols, f.ptyModes = term, h, w, modes
	return nil
}

func (f *fakeSession) WindowChange(h, w int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.winRows, f.winCols = h, w
	return nil
}

func (f *fakeSession) Shell() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = "shell"
	return nil
}

func (f *fakeSession) Start(cmd string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = "exec: " + cmd
	return nil
}

func (f *fakeSession) Signal(sig ssh.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signals = append(f.signals, string(sig))
	return nil
}

func (f *fakeSession) Wait() error {
	<-f.exit
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.waitErr
}

func (f *fakeSession) StdinPipe() (io.WriteCloser, error) { return f.stdinW, nil }
func (f *fakeSession) StdoutPipe() (io.Reader, error)     { return f.stdoutR, nil }
func (f *fakeSession) StderrPipe() (io.Reader, error)     { return f.stderrR, nil }

func (f *fakeSession) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.exit)
	}
	return nil
}

// finish makes the remote command exit with err.
func (f *fakeSession) finish(err error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.waitErr = err
	f.closed = true
	f.mu.Unlock()
	_ = f.stdoutW.Close()
	_ = f.stderrW.Close()
	close(f.exit)
}

func (f *fakeSession) snapshot() fakeSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeSession{
		ptyTerm: f.ptyTerm, ptyRows: f.ptyRows, ptyCols: f.ptyCols, ptyModes: f.ptyModes,
		winRows: f.winRows, winCols: f.winCols, started: f.started,
		signals: append([]string(nil), f.signals...),
	}
}

// fakeTransport hands out fakeSessions and pipes for forwarded ports.
type fakeTransport struct {
	mu sync.Mutex

	sessions   []*fakeSession
	sessionErr error
	released   int

	dialed  []string
	dialErr error
	// forwarded is the far end of the last DialJob, for the test to
	// read and write.
	forwarded net.Conn
}

func (f *fakeTransport) Session(context.Context, jobssh.Key) (jobssh.JobSession, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sessionErr != nil {
		return nil, nil, f.sessionErr
	}
	s := newFakeSession()
	f.sessions = append(f.sessions, s)
	return s, func() {
		f.mu.Lock()
		f.released++
		f.mu.Unlock()
	}, nil
}

func (f *fakeTransport) DialJob(_ context.Context, _ jobssh.Key, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	f.dialed = append(f.dialed, network+" "+addr)
	near, far := net.Pipe()
	f.forwarded = far
	return near, nil
}

func (f *fakeTransport) lastSession(t *testing.T) *fakeSession {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.sessions)
		var s *fakeSession
		if n > 0 {
			s = f.sessions[n-1]
		}
		f.mu.Unlock()
		if s != nil {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no session was ever opened")
	return nil
}

func (f *fakeTransport) releaseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.released
}

// gateway starts an authenticating SSH server whose channels are
// served by a Server over tr.
func gateway(t *testing.T, tr *fakeTransport) string {
	t.Helper()

	a := grantingAuthenticator(t, "bbockelm", Options{Prompt: "ap.example.edu"})
	srv := &Server{
		Transport: tr,
		Resolve: func(_ context.Context, account string, target Target, _ func(string)) (jobssh.Key, error) {
			if account != "bbockelm" {
				return jobssh.Key{}, fmt.Errorf("unexpected account %q", account)
			}
			if !target.IsJob() {
				return jobssh.Key{}, fmt.Errorf("no session called %q", target.Name)
			}
			return jobssh.Key{Owner: account, Cluster: target.Cluster, Proc: target.Proc}, nil
		},
	}

	cfg := &ssh.ServerConfig{KeyboardInteractiveCallback: a.KeyboardInteractive(context.Background())}
	cfg.AddHostKey(testSigner(t))

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					_ = nc.Close()
					return
				}
				defer func() { _ = conn.Close() }()
				srv.Serve(context.Background(), conn, chans, reqs)
			}()
		}
	}()
	return ln.Addr().String()
}

func gatewayClient(t *testing.T, addr, user string) *ssh.Client {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test server, key generated per run
		Timeout:         10 * time.Second,
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				return make([]string, len(questions)), nil
			}),
		},
	}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// The wire carries columns first and RequestPty takes rows first.
// Swapping them yields a terminal that looks correct until something
// wraps, so the two orders are pinned with deliberately unequal
// numbers.
func TestPtyRowsAndColumnsAreNotSwapped(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400}
	if err := sess.RequestPty("xterm-256color", 24, 120, modes); err != nil {
		t.Fatalf("request pty: %v", err)
	}

	got := tr.lastSession(t).snapshot()
	if got.ptyRows != 24 || got.ptyCols != 120 {
		t.Errorf("pty rows/cols = %d/%d, want 24/120", got.ptyRows, got.ptyCols)
	}
	if got.ptyTerm != "xterm-256color" {
		t.Errorf("term = %q", got.ptyTerm)
	}
	// ECHO lives in the modes blob. A shell that comes up with echo
	// off looks like a hung terminal.
	if got.ptyModes[ssh.ECHO] != 1 {
		t.Errorf("ECHO = %v, want it preserved through the modes blob", got.ptyModes[ssh.ECHO])
	}
	if got.ptyModes[ssh.TTY_OP_ISPEED] != 38400 {
		t.Errorf("ISPEED = %v, want 38400", got.ptyModes[ssh.TTY_OP_ISPEED])
	}
}

func TestWindowChangeRowsAndColumnsAreNotSwapped(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	if err := sess.WindowChange(40, 132); err != nil {
		t.Fatalf("window change: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := tr.lastSession(t).snapshot(); got.winRows != 0 {
			if got.winRows != 40 || got.winCols != 132 {
				t.Fatalf("window rows/cols = %d/%d, want 40/132", got.winRows, got.winCols)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the window change never arrived")
}

// A command that exits 7 must look like a command that exited 7, not
// like a broken connection. Without an exit-status request the client
// reports 255, which is what it also says when the transport dies.
func TestExitStatusIsPropagated(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	out := make(chan error, 1)
	go func() { out <- sess.Run("false") }()

	remote := tr.lastSession(t)
	// Wait until the exec actually reached the far end, so finishing
	// does not race the start.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && remote.snapshot().started == "" {
		time.Sleep(5 * time.Millisecond)
	}
	if got := remote.snapshot().started; got != "exec: false" {
		t.Fatalf("started = %q, want the exec", got)
	}
	remote.finish(&exitError{status: 7})

	select {
	case err := <-out:
		var ee *ssh.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("err = %v, want an ExitError", err)
		}
		if ee.ExitStatus() != 7 {
			t.Errorf("exit status = %d, want 7", ee.ExitStatus())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the command never returned")
	}
}

// exitError carries an exit status the way *ssh.ExitError does.
//
// It cannot BE an *ssh.ExitError: that type's Waitmsg fields are
// unexported, so no test outside x/crypto can build one with a chosen
// status. That is what pushed sendExitStatus to match on the
// ExitStatus method rather than the concrete type -- which is also the
// right thing for an interface-typed Wait.
type exitError struct{ status int }

func (e *exitError) Error() string   { return fmt.Sprintf("Process exited with status %d", e.status) }
func (e *exitError) ExitStatus() int { return e.status }

func TestCleanExitIsZero(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	out := make(chan error, 1)
	go func() { out <- sess.Run("true") }()

	remote := tr.lastSession(t)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && remote.snapshot().started == "" {
		time.Sleep(5 * time.Millisecond)
	}
	remote.finish(nil)

	select {
	case err := <-out:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the command never returned")
	}
	if tr.releaseCount() == 0 {
		t.Error("the session was never released back to the transport")
	}
}

func TestStdoutAndStderrReachTheClient(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	var stdout, stderr strings.Builder
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	out := make(chan error, 1)
	go func() { out <- sess.Run("say") }()

	remote := tr.lastSession(t)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && remote.snapshot().started == "" {
		time.Sleep(5 * time.Millisecond)
	}
	_, _ = remote.stdoutW.Write([]byte("on stdout"))
	_, _ = remote.stderrW.Write([]byte("on stderr"))
	remote.finish(nil)

	select {
	case <-out:
	case <-time.After(5 * time.Second):
		t.Fatal("the command never returned")
	}
	if stdout.String() != "on stdout" {
		t.Errorf("stdout = %q", stdout.String())
	}
	if stderr.String() != "on stderr" {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// The session budget is shared per job, so hitting it is an ordinary
// thing a user will do. It has to arrive as words.
//
// It reaches them on stderr rather than as a channel rejection,
// because the channel is now accepted before the job is resolved --
// that is what makes a queue wait visible. The user sees the same
// sentence either way; what changes is that ssh exits 1 rather than
// reporting a refused channel.
func TestTooManySessionsIsExplained(t *testing.T) {
	tr := &fakeTransport{sessionErr: fmt.Errorf("%w: job bbockelm/12345.0 already has 10 of 10", jobssh.ErrTooManySessions)}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	// Through the pipe, not sess.Stderr: x/crypto wires the latter
	// when a command starts, and here no command ever does.
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	if runErr := sess.Start("true"); runErr == nil {
		t.Error("the exec was accepted despite the session cap")
	}
	msg := readAvailable(t, stderrPipe)
	if !strings.Contains(msg, "sessions open") || !strings.Contains(msg, "Close a terminal") {
		t.Errorf("the failure does not explain itself: %q", msg)
	}
}

// sftp cannot work through condor_ssh_to_job: the forced command turns
// the subsystem request into `eval sftp`. "subsystem request failed"
// sends people looking in the wrong place, so the reason is written to
// the channel first.
func TestSubsystemIsRefusedWithAReason(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	subsystemErr := sess.RequestSubsystem("sftp")
	if subsystemErr == nil {
		t.Fatal("the sftp subsystem was accepted")
	}

	buf := make([]byte, 256)
	n, _ := stderrPipe.Read(buf)
	if !strings.Contains(string(buf[:n]), "sftp") {
		t.Errorf("the refusal did not name the subsystem: %q", string(buf[:n]))
	}
}

// Neither kind of forward is a session, so neither draws on the
// sshd's session budget -- which is what keeps a reverse proxy working
// when every terminal for that job is in use.
//
// The socket form matters more than the port form: a TCP port bound to
// 127.0.0.1 in a sandbox is open to every local user on the execute
// node unless the job has its own network namespace, which no pool can
// be assumed to configure. A socket is protected by file permissions.
func TestForwardingReachesTheJobWithoutASession(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		addr    string
		want    string
	}{
		{"tcp port", "tcp", "127.0.0.1:8888", "tcp 127.0.0.1:8888"},
		{"unix socket", "unix", "/scratch/dir_123/vscode.sock", "unix /scratch/dir_123/vscode.sock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &fakeTransport{}
			client := gatewayClient(t, gateway(t, tr), "12345.0")

			conn, err := client.Dial(tc.network, tc.addr)
			if err != nil {
				t.Fatalf("dial through the job: %v", err)
			}
			defer func() { _ = conn.Close() }()

			tr.mu.Lock()
			far := tr.forwarded
			dialed := append([]string(nil), tr.dialed...)
			sessions := len(tr.sessions)
			tr.mu.Unlock()

			if len(dialed) != 1 || dialed[0] != tc.want {
				t.Fatalf("dialed = %v, want [%q]", dialed, tc.want)
			}
			if sessions != 0 {
				t.Errorf("a forward opened %d sessions; it must open none", sessions)
			}

			go func() {
				b := make([]byte, 4)
				_, _ = io.ReadFull(far, b)
				_, _ = far.Write([]byte("pong"))
			}()

			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			reply := make([]byte, 4)
			if _, err := io.ReadFull(conn, reply); err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(reply) != "pong" {
				t.Errorf("reply = %q", reply)
			}
		})
	}
}

func TestUnknownChannelTypeIsRefused(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	_, _, err := client.OpenChannel("x11", nil)
	if err == nil {
		t.Fatal("an unknown channel type was accepted")
	}
	if !strings.Contains(err.Error(), "x11") {
		t.Errorf("the rejection does not name the channel type: %v", err)
	}
}

func TestUnresolvableTargetIsExplained(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "+nosuchsession")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	if runErr := sess.Start("true"); runErr == nil {
		t.Error("an exec was accepted against an unresolvable target")
	}
	msg := readAvailable(t, stderrPipe)
	if !strings.Contains(msg, "nosuchsession") {
		t.Errorf("the failure does not name the target: %q", msg)
	}
}

// The pre-Accept rejection path still exists, and an empty username is
// now the only thing that reaches it.
//
// Every other username produces a session name, because a bare `ssh
// gateway` sends whatever the local login happens to be. An empty one
// is not a login and no ssh client sends it, but the protocol permits
// it and refusing before Accept is the clearer answer: there is no
// wait to make visible, so a rejection reason beats a message on a
// channel.
func TestEmptyUsernameIsRejectedOutright(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "")

	if _, err := client.NewSession(); err == nil {
		t.Fatal("a channel was accepted for an empty username")
	}
	tr.mu.Lock()
	sessions := len(tr.sessions)
	tr.mu.Unlock()
	if sessions != 0 {
		t.Errorf("a job session was opened for an empty username")
	}
}

// A username that is not a job id reaches a session, whatever it looks
// like -- the channel is accepted and the resolver is asked. Awkward
// logins land on the default session rather than being refused.
func TestAwkwardUsernamesStillReachASession(t *testing.T) {
	for _, user := range []string{"has space", "_appstore", "bob@wisc.edu", "-leading", "+work"} {
		t.Run(user, func(t *testing.T) {
			tr := &fakeTransport{}
			client := gatewayClient(t, gateway(t, tr), user)

			sess, err := client.NewSession()
			if err != nil {
				t.Fatalf("new session: %v", err)
			}
			defer func() { _ = sess.Close() }()

			// gateway()'s resolver only answers for job ids, so this
			// reaching a refusal ON THE CHANNEL rather than a rejected
			// channel is the point: the name resolved, and only the
			// lookup failed.
			stderrPipe, err := sess.StderrPipe()
			if err != nil {
				t.Fatalf("stderr pipe: %v", err)
			}
			_ = sess.Start("true")
			if msg := readAvailable(t, stderrPipe); !strings.Contains(msg, "session") {
				t.Errorf("the failure does not mention a session: %q", msg)
			}
		})
	}
}

// blockingResolve is a ResolveFunc that reports progress and waits.
type blockingResolve struct {
	statuses []string
	release  chan struct{}
	entered  chan struct{}
	ctxErr   chan error
	once     sync.Once
}

func newBlockingResolve(statuses ...string) *blockingResolve {
	return &blockingResolve{
		statuses: statuses,
		release:  make(chan struct{}),
		entered:  make(chan struct{}),
		ctxErr:   make(chan error, 1),
	}
}

func (b *blockingResolve) fn(ctx context.Context, account string, _ Target, report func(string)) (jobssh.Key, error) {
	b.once.Do(func() { close(b.entered) })
	for _, st := range b.statuses {
		report(st)
		time.Sleep(60 * time.Millisecond)
	}
	select {
	case <-b.release:
	case <-ctx.Done():
		b.ctxErr <- ctx.Err()
		return jobssh.Key{}, ctx.Err()
	case <-time.After(3 * time.Second):
	}
	b.ctxErr <- nil
	return jobssh.Key{Owner: account, Cluster: 1, Proc: 0}, nil
}

// gatewayWithResolve is gateway() with a caller-supplied resolver.
func gatewayWithResolve(t *testing.T, tr *fakeTransport, resolve ResolveFunc) string {
	t.Helper()
	a := grantingAuthenticator(t, "bbockelm", Options{Prompt: "ap.example.edu"})
	srv := &Server{Transport: tr, Resolve: resolve}

	cfg := &ssh.ServerConfig{KeyboardInteractiveCallback: a.KeyboardInteractive(context.Background())}
	cfg.AddHostKey(testSigner(t))

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					_ = nc.Close()
					return
				}
				defer func() { _ = conn.Close() }()
				srv.Serve(context.Background(), conn, chans, reqs)
			}()
		}
	}()
	return ln.Addr().String()
}

// A caller waiting on a queued job must see WHY. A spinner with no
// reason is indistinguishable from a hang, which is the complaint this
// whole display exists to answer.
func TestWaitShowsTheReasonOnATerminal(t *testing.T) {
	br := newBlockingResolve("Session \"work\" (job 5.0) is idle")
	tr := &fakeTransport{}
	client := gatewayClient(t, gatewayWithResolve(t, tr, br.fn), "work")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	// Asynchronously: the reply is held until the job exists, which is
	// the other side of the wait being measured here.
	go func() { _ = sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}) }()

	// Read whatever the wait paints, then let the resolve finish.
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := stdout.Read(buf)
		got <- string(buf[:n])
	}()

	select {
	case painted := <-got:
		if !strings.Contains(painted, "is idle") {
			t.Errorf("the wait did not say why: %q", painted)
		}
		if !strings.Contains(painted, "\r") {
			t.Errorf("a terminal wait should redraw in place: %q", painted)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was painted during the wait")
	}
	close(br.release)
}

// Without a terminal, progress goes to stderr and stdout stays the
// command's alone.
//
// Both halves matter. A pipe has no cursor to move, so escape
// sequences in it corrupt whatever is reading; and stdout belongs to
// the command, so status lines there end up inside
// `ssh -T gateway cat file > out`.
func TestWaitWithoutATerminalKeepsStdoutClean(t *testing.T) {
	br := newBlockingResolve("Session \"work\" (job 5.0) is idle")
	tr := &fakeTransport{}
	client := gatewayClient(t, gatewayWithResolve(t, tr, br.fn), "work")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	// No RequestPty: start the command straight away, as a script does.
	go func() { _ = sess.Start("true") }()

	// Anything arriving on stdout during the wait is a bug, so watch
	// it while reading the status off stderr.
	stdoutSaw := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := stdout.Read(buf)
		stdoutSaw <- string(buf[:n])
	}()

	painted := readAvailable(t, stderrPipe)
	if !strings.Contains(painted, "is idle") {
		t.Errorf("the wait did not say why: %q", painted)
	}
	if strings.Contains(painted, "\x1b[") {
		t.Errorf("escape sequences reached a pipe: %q", painted)
	}

	select {
	case leaked := <-stdoutSaw:
		t.Errorf("progress leaked into the command's stdout: %q", leaked)
	case <-time.After(300 * time.Millisecond):
	}

	close(br.release)
}

// Ctrl-C during the wait has to end it. Otherwise the only way out of
// a queue is to kill the terminal, which leaves the job behind.
func TestInterruptDuringTheWaitCancels(t *testing.T) {
	br := newBlockingResolve()
	tr := &fakeTransport{}
	client := gatewayClient(t, gatewayWithResolve(t, tr, br.fn), "work")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	go func() { _ = sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}) }()

	<-br.entered
	if _, err := stdin.Write([]byte{0x03}); err != nil {
		t.Fatalf("write ctrl-c: %v", err)
	}

	select {
	case err := <-br.ctxErr:
		if err == nil {
			t.Fatal("the resolve finished normally; Ctrl-C did not cancel it")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ctrl-C did not reach the wait")
	}
}

// Input sent before the job exists must still reach it.
//
// `echo hi | ssh gateway cat` writes immediately, long before a queued
// job is running. Nothing reads the channel during the wait for a
// session with no terminal, precisely so those bytes stay in the SSH
// window rather than being consumed looking for a Ctrl-C that a pipe
// will never send.
func TestStdinSentDuringTheWaitSurvives(t *testing.T) {
	br := newBlockingResolve()
	tr := &fakeTransport{}
	client := gatewayClient(t, gatewayWithResolve(t, tr, br.fn), "work")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	go func() { _ = sess.Start("cat") }()

	<-br.entered
	if _, err := stdin.Write([]byte("hello-from-before\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	close(br.release)

	remote := tr.lastSession(t)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && remote.snapshot().started == "" {
		time.Sleep(5 * time.Millisecond)
	}

	buf := make([]byte, 64)
	done := make(chan int, 1)
	go func() {
		n, _ := remote.stdinR.Read(buf)
		done <- n
	}()
	select {
	case n := <-done:
		if !strings.Contains(string(buf[:n]), "hello-from-before") {
			t.Errorf("the job received %q", string(buf[:n]))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("input written during the wait never reached the job")
	}
}

// readAvailable returns what is already waiting on r, giving the writer
// a moment to get there. A deadline rather than io.ReadAll because the
// stream stays open and ReadAll would wait for a close that the
// failure path does not always perform.
func readAvailable(t *testing.T, r io.Reader) string {
	t.Helper()
	out := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		out <- string(buf[:n])
	}()
	select {
	case s := <-out:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was written where the failure should have been explained")
		return ""
	}
}

// autoFinishSessions answers whatever the gateway opens: writes a line
// and exits cleanly, so a real client has something to see and a reason
// to exit 0.
func autoFinishSessions(t *testing.T, tr *fakeTransport, output string) {
	t.Helper()
	go func() {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			tr.mu.Lock()
			n := len(tr.sessions)
			var s *fakeSession
			if n > 0 {
				s = tr.sessions[n-1]
			}
			tr.mu.Unlock()
			if s != nil {
				for time.Now().Before(deadline) && s.snapshot().started == "" {
					time.Sleep(5 * time.Millisecond)
				}
				_, _ = s.stdoutW.Write([]byte(output))
				s.finish(nil)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
}

// The whole point of the wait display is what a person sees. x/crypto
// proves the bytes were sent; only a real client proves they are shown.
func TestRealClientSeesTheWaitAndItsReason(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh binary to test against")
	}

	br := newBlockingResolve("Session \"work\" (job 5.0) is idle, waiting for a slot")
	tr := &fakeTransport{}
	addr := gatewayWithResolve(t, tr, br.fn)

	// Let the wait run visibly, then let it succeed.
	go func() {
		<-br.entered
		time.Sleep(700 * time.Millisecond)
		close(br.release)
	}()
	autoFinishSessions(t, tr, "shell-ran\r\n")

	out, sshErr := realSSH(t, sshBin, addr, []string{"-tt"}, "work@HOST", "true")
	t.Logf("ssh exit=%v output:\n%q", sshErr, out)

	if !strings.Contains(string(out), "waiting for a slot") {
		t.Errorf("a real client never saw why it was waiting:\n%q", out)
	}
	if !strings.Contains(string(out), "shell-ran") {
		t.Errorf("the session did not run after the wait:\n%q", out)
	}
	// The spinner line is erased before the session starts, so the
	// job's own first line is not appended to a progress line.
	if idx := strings.Index(string(out), "shell-ran"); idx > 0 {
		if strings.Contains(string(out[:idx]), "waiting for a slot\rshell") {
			t.Errorf("the progress line was not cleared before output:\n%q", out)
		}
	}
}

// A failure after the channel is accepted reaches the terminal, and the
// client exits non-zero rather than reporting a dropped connection.
func TestRealClientSeesAFailureReason(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh binary to test against")
	}

	tr := &fakeTransport{}
	addr := gatewayWithResolve(t, tr, func(context.Context, string, Target, func(string)) (jobssh.Key, error) {
		return jobssh.Key{}, fmt.Errorf("session %q is held: no matching machines", "work")
	})

	out, sshErr := realSSH(t, sshBin, addr, nil, "work@HOST", "echo should-not-run")
	t.Logf("ssh exit=%v output:\n%q", sshErr, out)

	if sshErr == nil {
		t.Error("ssh reported success for a session that could not be opened")
	}
	if !strings.Contains(string(out), "no matching machines") {
		t.Errorf("the reason never reached the terminal:\n%q", out)
	}
	if strings.Contains(string(out), "should-not-run") {
		t.Errorf("the command ran anyway:\n%q", out)
	}
}

// Keystrokes typed after the shell starts must all reach the job.
//
// The interrupt scanner and the stdin copier are the same goroutine
// for exactly this reason. When they were separate they raced for
// every Read, and whichever won took the bytes -- so roughly half of
// what the user typed vanished. Nothing caught it, because a test that
// types nothing after the shell starts cannot.
//
// Several separate writes rather than one: with two readers each write
// is its own coin flip, so the old shape fails this almost always,
// while the fixed shape passes deterministically.
func TestTypingAfterTheSessionStartsIsNotEaten(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}

	remote := tr.lastSession(t)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && remote.snapshot().started == "" {
		time.Sleep(5 * time.Millisecond)
	}

	got := make(chan string, 1)
	go func() {
		var seen []byte
		buf := make([]byte, 64)
		for len(seen) < 10 {
			n, err := remote.stdinR.Read(buf)
			seen = append(seen, buf[:n]...)
			if err != nil {
				break
			}
		}
		got <- string(seen)
	}()

	for _, chunk := range []string{"ab", "cd", "ef", "gh", "ij"} {
		if _, err := stdin.Write([]byte(chunk)); err != nil {
			t.Fatalf("write %q: %v", chunk, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case seen := <-got:
		if seen != "abcdefghij" {
			t.Errorf("the job received %q, want everything that was typed", seen)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("what was typed never reached the job")
	}
}

// An empty socket path is refused rather than passed down to become an
// opaque dial error.
func TestEmptySocketPathIsRefused(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	payload := ssh.Marshal(struct {
		SocketPath string
		Reserved   string
		ReservedN  uint32
	}{})
	_, _, err := client.OpenChannel(streamLocalChannelType, payload)
	if err == nil {
		t.Fatal("an empty socket path was accepted")
	}
	tr.mu.Lock()
	dialed := len(tr.dialed)
	tr.mu.Unlock()
	if dialed != 0 {
		t.Errorf("the job was dialled %d times for an empty path", dialed)
	}
}
