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
		Resolve: func(_ context.Context, account string, target Target) (jobssh.Key, error) {
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
// thing a user will do. It has to arrive as words rather than as an
// unexplained channel rejection.
func TestTooManySessionsIsExplained(t *testing.T) {
	tr := &fakeTransport{sessionErr: fmt.Errorf("%w: job bbockelm/12345.0 already has 10 of 10", jobssh.ErrTooManySessions)}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	_, err := client.NewSession()
	if err == nil {
		t.Fatal("a session was opened past the cap")
	}
	msg := err.Error()
	if !strings.Contains(msg, "sessions open") || !strings.Contains(msg, "Close a terminal") {
		t.Errorf("the rejection does not explain itself: %q", msg)
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

// A forwarded port is not a session and must not draw on the session
// budget -- that is what keeps the reverse proxy working when every
// terminal is in use.
func TestPortForwardDoesNotConsumeASession(t *testing.T) {
	tr := &fakeTransport{}
	client := gatewayClient(t, gateway(t, tr), "12345.0")

	conn, err := client.Dial("tcp", "127.0.0.1:8888")
	if err != nil {
		t.Fatalf("dial through the job: %v", err)
	}
	defer func() { _ = conn.Close() }()

	tr.mu.Lock()
	far := tr.forwarded
	dialed := append([]string(nil), tr.dialed...)
	sessions := len(tr.sessions)
	tr.mu.Unlock()

	if len(dialed) != 1 || dialed[0] != "tcp 127.0.0.1:8888" {
		t.Fatalf("dialed = %v", dialed)
	}
	if sessions != 0 {
		t.Errorf("a port forward opened %d sessions; it must open none", sessions)
	}

	go func() {
		b := make([]byte, 5)
		_, _ = io.ReadFull(far, b)
		_, _ = far.Write([]byte("pong"))
	}()

	if _, err := conn.Write([]byte("ping!")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(reply) != "pong" {
		t.Errorf("reply = %q", reply)
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
	client := gatewayClient(t, gateway(t, tr), "nosuchsession")

	_, err := client.NewSession()
	if err == nil {
		t.Fatal("a session opened against an unresolvable target")
	}
	if !strings.Contains(err.Error(), "nosuchsession") {
		t.Errorf("the rejection does not name the target: %v", err)
	}
}
