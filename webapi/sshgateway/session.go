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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/jobssh"
)

// JobTransport is the slice of *jobssh.Cache the gateway needs.
//
// An interface so the channel plumbing can be tested without a pool,
// and so the two ways into a sandbox stay visibly separate: sessions
// draw on the sshd's session budget, forwarded connections do not.
type JobTransport interface {
	Session(ctx context.Context, key jobssh.Key) (jobssh.JobSession, func(), error)
	DialJob(ctx context.Context, key jobssh.Key, network, addr string) (net.Conn, error)
}

// ResolveFunc turns an authenticated caller's target into a job.
//
// It is where "create the session if it does not exist yet" belongs,
// and why it takes a context: it may submit a job and wait for it to
// start.
//
// report is how that wait becomes visible. Call it with a short phrase
// -- "Idle, waiting for a slot" -- whenever the answer changes; the
// gateway decides how to show it, and a caller with no terminal gets
// lines instead of a spinner. Calling it often is fine and calling it
// never is allowed, but a wait with no reason on the screen is
// indistinguishable from a hang.
type ResolveFunc func(ctx context.Context, account string, t Target, report func(status string)) (jobssh.Key, error)

// Server proxies an authenticated SSH connection into a job.
type Server struct {
	// Transport and Resolve are required.
	Transport JobTransport
	Resolve   ResolveFunc

	Logger *logging.Logger
}

// Serve handles one authenticated connection until it ends.
//
// conn.Permissions must be the ones an Authenticator produced: the
// account comes from there and never from conn.User().
func (s *Server) Serve(ctx context.Context, conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	go ssh.DiscardRequests(reqs)

	account := ""
	if conn.Permissions != nil {
		account = conn.Permissions.Extensions[ExtAccount]
	}
	if account == "" {
		// Defence in depth. The Authenticator refuses an unnamed
		// caller, so reaching here means something else admitted the
		// connection, and running it as nobody is the one outcome
		// worth preventing twice.
		s.logf("Refusing an authenticated connection that carries no account", "remote", conn.RemoteAddr().String())
		_ = conn.Close()
		return
	}

	var wg sync.WaitGroup
	for nch := range chans {
		switch nch.ChannelType() {
		case "session":
			wg.Add(1)
			go func(nch ssh.NewChannel) {
				defer wg.Done()
				s.handleSession(ctx, account, conn.User(), nch)
			}(nch)
		case "direct-tcpip":
			wg.Add(1)
			go func(nch ssh.NewChannel) {
				defer wg.Done()
				s.handleDirectTCPIP(ctx, account, conn.User(), nch)
			}(nch)
		case streamLocalChannelType:
			wg.Add(1)
			go func(nch ssh.NewChannel) {
				defer wg.Done()
				s.handleStreamLocal(ctx, account, conn.User(), nch)
			}(nch)
		default:
			_ = nch.Reject(ssh.UnknownChannelType,
				fmt.Sprintf("this gateway serves sessions and port forwards, not %q", nch.ChannelType()))
		}
	}
	wg.Wait()
}

// resolve parses the username and finds the job behind it.
func (s *Server) resolve(ctx context.Context, account, user string, report func(string)) (jobssh.Key, Target, error) {
	target, err := ParseTarget(user)
	if err != nil {
		return jobssh.Key{}, Target{}, err
	}
	if report == nil {
		report = func(string) {}
	}
	key, err := s.Resolve(ctx, account, target, report)
	if err != nil {
		return jobssh.Key{}, target, err
	}
	return key, target, nil
}

// handleSession proxies one session channel: a shell, a command, or a
// PTY, whichever the client asks for once the channel is open.
//
// The channel is accepted BEFORE the job is resolved, which is the
// opposite of the obvious order and is deliberate. Resolving can mean
// submitting a job and waiting minutes for the queue, and until the
// channel exists there is nowhere to tell the caller that. The cost is
// that a failure after this point cannot use nch.Reject and has to be
// written to the channel instead -- which reaches the user either way.
//
// Only what can be decided instantly stays in front of Accept.
func (s *Server) handleSession(ctx context.Context, account, user string, nch ssh.NewChannel) {
	if _, err := ParseTarget(user); err != nil {
		// A username that names nothing is knowable without asking the
		// pool anything, so it still gets a proper rejection.
		_ = nch.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pump := newRequestPump(reqs)
	go pump.collect()

	prog := newProgress(ch, ch.Stderr(), pump.ptySeen)
	go prog.run(ctx)
	input := newChannelInput(ch, cancel)
	go input.run(ctx, pump.ptySeen)

	key, target, err := s.resolve(ctx, account, user, prog.report)
	prog.stop()
	if err != nil {
		s.failSession(ch, fmt.Sprintf("%v", err), ctx.Err() != nil)
		s.logf("Could not resolve a session target", "account", account, "target", user, "error", err)
		return
	}

	sess, release, err := s.Transport.Session(ctx, key)
	if err != nil {
		msg := fmt.Sprintf("could not open a session in %s: %v", target, err)
		if errors.Is(err, jobssh.ErrTooManySessions) {
			msg = fmt.Sprintf("%s already has %d sessions open, which is all the job's sshd allows. "+
				"Close a terminal and try again.", target, jobssh.MaxSessionsPerTransport)
		}
		s.failSession(ch, msg, ctx.Err() != nil)
		s.logf("Could not open a job session", "account", account, "job", key.String(), "error", err)
		return
	}
	defer release()
	defer func() { _ = sess.Close() }()

	// Pipes must be taken before the remote command starts.
	stdin, err := sess.StdinPipe()
	if err != nil {
		return
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return
	}

	started := make(chan struct{})
	var startOnce sync.Once
	start := func(run func() error) bool {
		ok := true
		startOnce.Do(func() {
			if err := run(); err != nil {
				ok = false
				return
			}
			close(started)
		})
		return ok
	}

	// Everything the client asked for while it was waiting now reaches
	// the job, in the order it was asked.
	pump.release(s, sess, ch, start)

	select {
	case <-started:
	case <-pump.finished:
		// The channel closed without a shell or an exec.
		return
	case <-ctx.Done():
		return
	}

	var ioWG sync.WaitGroup
	ioWG.Add(2)
	go func() { defer ioWG.Done(); _, _ = copyStream(ch, stdout) }()
	go func() { defer ioWG.Done(); _, _ = copyStream(ch.Stderr(), stderr) }()
	// The one reader that has owned this channel all along now carries
	// stdin, so no keystroke is read twice or dropped at the handover.
	input.attach(stdin)

	waitErr := sess.Wait()
	ioWG.Wait()
	sendExitStatus(ch, waitErr)
}

// failSession reports a failure on an already-accepted channel.
//
// The message goes to stderr rather than stdout so it does not land in
// the output of `ssh host cmd`, and an exit status follows so the
// client reports a failure rather than a clean run that printed
// nothing.
//
// Requests the client is still waiting on are deliberately left
// unanswered. Closing the channel resolves them, and measuring it --
// against x/crypto and against OpenSSH -- showed the same exit status
// and the same message either way. Replying "no" to each one first was
// code with no observable effect, which is worse than absent: nothing
// would notice if it broke.
func (s *Server) failSession(ch ssh.Channel, msg string, cancelled bool) {
	// "cancelled" only when there is nothing better to say. A resolver
	// that was interrupted mid-wait knows what it left behind -- a job
	// that is still starting, and worth reconnecting to -- and that is
	// more use than the word.
	if cancelled && isBareCancellation(msg) {
		msg = "cancelled"
	}
	_, _ = fmt.Fprintf(ch.Stderr(), "%s\r\n", msg)
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
	_ = ch.CloseWrite()
}

// isBareCancellation reports whether a message is just Go's own words
// for a cancelled context, which mean nothing to somebody at a
// terminal.
func isBareCancellation(msg string) bool {
	m := strings.TrimSpace(msg)
	return m == context.Canceled.Error() || m == context.DeadlineExceeded.Error()
}

// requestPump holds the client's session requests until there is a job
// to send them to, then hands over and stays out of the way.
//
// A client opens a channel and immediately sends pty-req, env and then
// shell, each waiting for a reply. None can be answered before the job
// exists, and leaving them unread would eventually stall the
// connection's mux loop -- so they are read and held.
//
// Holding stops when the session arrives, NOT when a start request
// comes in. An earlier version waited for shell/exec before releasing,
// which hung any client that sent pty-req and then waited for its
// reply before sending anything else -- which is what a client does.
//
// It also reports the first pty-req, which is how the rest of the
// gateway learns there is a terminal on the other end.
type requestPump struct {
	reqs <-chan *ssh.Request

	// ptySeen closes on the first pty-req.
	ptySeen chan struct{}
	// finished closes when the client's request stream ends.
	finished chan struct{}

	// mu guards everything below, and is held across handling a
	// request so that replayed and live ones cannot interleave: a
	// client that sent pty-req then shell must have them applied in
	// that order, whichever side of the handover they arrived on.
	mu    sync.Mutex
	ready bool
	held  []*ssh.Request
	srv   *Server
	sess  jobssh.JobSession
	ch    ssh.Channel
	start func(func() error) bool

	ptyOnce  sync.Once
	doneOnce sync.Once
}

func newRequestPump(reqs <-chan *ssh.Request) *requestPump {
	return &requestPump{
		reqs:     reqs,
		ptySeen:  make(chan struct{}),
		finished: make(chan struct{}),
	}
}

// release hands the pump a session and replays what the client sent
// while it was waiting.
func (p *requestPump) release(srv *Server, sess jobssh.JobSession, ch ssh.Channel, start func(func() error) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.srv, p.sess, p.ch, p.start = srv, sess, ch, start
	p.ready = true
	held := p.held
	p.held = nil
	for _, req := range held {
		p.srv.handleSessionRequest(req, p.sess, p.ch, p.start)
	}
}

// collect reads the client's requests for the life of the channel,
// buffering them until release and handling them directly after.
func (p *requestPump) collect() {
	defer p.doneOnce.Do(func() { close(p.finished) })

	for req := range p.reqs {
		if req.Type == "pty-req" {
			p.ptyOnce.Do(func() { close(p.ptySeen) })
		}
		p.mu.Lock()
		if !p.ready {
			p.held = append(p.held, req)
			p.mu.Unlock()
			continue
		}
		p.srv.handleSessionRequest(req, p.sess, p.ch, p.start)
		p.mu.Unlock()
	}
}

// channelInput owns reading the client's half of a session channel for
// its whole life: first to notice a Ctrl-C during the wait, then to
// carry stdin to the job.
//
// One goroutine, because two cannot share a Read. An earlier version
// ran an interrupt watcher alongside the stdin copier and they raced
// for every keystroke -- invisible in a test that types nothing after
// the shell starts, and immediately obvious to a person.
type channelInput struct {
	ch     ssh.Channel
	cancel context.CancelFunc

	attached chan struct{}
	writer   chan io.WriteCloser
	once     sync.Once
}

func newChannelInput(ch ssh.Channel, cancel context.CancelFunc) *channelInput {
	return &channelInput{
		ch:       ch,
		cancel:   cancel,
		attached: make(chan struct{}),
		writer:   make(chan io.WriteCloser, 1),
	}
}

// attach hands over the job's stdin. Everything read from here on goes
// to it.
func (in *channelInput) attach(w io.WriteCloser) {
	in.once.Do(func() {
		in.writer <- w
		close(in.attached)
	})
}

// run reads the channel until it ends.
//
// Nothing is read before either a pty is requested or stdin is
// attached, and that is the whole point. Reading consumes bytes meant
// for the job: harmless for somebody typing at a shell that does not
// exist yet, and data loss for `echo hi | ssh gateway cat`. Waiting
// means the unread bytes stay in the SSH window, and the client blocks
// rather than losing them.
func (in *channelInput) run(ctx context.Context, ptySeen <-chan struct{}) {
	select {
	case <-ptySeen:
	case <-in.attached:
	case <-ctx.Done():
		return
	}

	var w io.WriteCloser
	buf := make([]byte, 32*1024)
	for {
		n, err := in.ch.Read(buf)
		if n > 0 {
			if w == nil {
				select {
				case w = <-in.writer:
				default:
				}
			}
			switch {
			case w != nil:
				_, _ = w.Write(buf[:n])
			case bytes.IndexByte(buf[:n], 0x03) >= 0:
				// Ctrl-C while still waiting for the job.
				in.cancel()
			}
		}
		if err != nil {
			if w == nil {
				select {
				case w = <-in.writer:
				default:
				}
			}
			if w != nil {
				// The client closing its half must reach the job as
				// EOF, or a command reading stdin never finishes.
				_ = w.Close()
			}
			return
		}
	}
}

// handleSessionRequest translates one of the client's session requests
// onto the job's own session.
func (s *Server) handleSessionRequest(req *ssh.Request, sess jobssh.JobSession, ch ssh.Channel, start func(func() error) bool) {
	switch req.Type {
	case "pty-req":
		var p struct {
			Term                       string
			Columns, Rows, Width, High uint32
			Modes                      string
		}
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			replyTo(req, false)
			return
		}
		// RequestPty takes (height, width) -- rows first. The wire
		// order is columns first. Swapping them produces a terminal
		// that looks right until something wraps.
		err := sess.RequestPty(p.Term, int(p.Rows), int(p.Columns), parseTerminalModes(p.Modes))
		replyTo(req, err == nil)

	case "window-change":
		var p struct {
			Columns, Rows, Width, High uint32
		}
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			replyTo(req, false)
			return
		}
		replyTo(req, sess.WindowChange(int(p.Rows), int(p.Columns)) == nil)

	case "shell":
		replyTo(req, start(sess.Shell))

	case "exec":
		var p struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			replyTo(req, false)
			return
		}
		cmd := p.Command
		replyTo(req, start(func() error { return sess.Start(cmd) }))

	case "signal":
		var p struct{ Signal string }
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			replyTo(req, false)
			return
		}
		replyTo(req, sess.Signal(ssh.Signal(p.Signal)) == nil)

	case "env":
		// Accepted and dropped. The job's sshd takes AcceptEnv *, but
		// x/crypto has no way to set an environment on a session other
		// than Setenv, and refusing makes noisy clients print a warning
		// for something harmless.
		replyTo(req, true)

	case "subsystem":
		var p struct{ Name string }
		_ = ssh.Unmarshal(req.Payload, &p)
		// sftp cannot work through condor_ssh_to_job: the forced
		// command in condor_ssh_to_job_shell_setup turns the subsystem
		// request into `eval sftp`. Say so, because "subsystem request
		// failed" sends people looking in the wrong place.
		_, _ = fmt.Fprintf(ch.Stderr(),
			"This gateway cannot run the %q subsystem: HTCondor's ssh-to-job wrapper does not support it.\r\n",
			p.Name)
		replyTo(req, false)

	default:
		replyTo(req, false)
	}
}

// handleDirectTCPIP forwards a port inside the job.
//
// Forwarded connections are not sessions, so they do not draw on the
// sshd's session budget.
func (s *Server) handleDirectTCPIP(ctx context.Context, account, user string, nch ssh.NewChannel) {
	var p struct {
		Host           string
		Port           uint32
		OriginatorIP   string
		OriginatorPort uint32
	}
	if err := ssh.Unmarshal(nch.ExtraData(), &p); err != nil {
		_ = nch.Reject(ssh.ConnectionFailed, "could not read the forwarding request")
		return
	}

	// No progress reporting: a forwarded connection has no channel to
	// draw on until it is accepted, and by then it is carrying bytes.
	key, target, err := s.resolve(ctx, account, user, nil)
	if err != nil {
		_ = nch.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	addr := net.JoinHostPort(p.Host, fmt.Sprint(p.Port))
	conn, err := s.Transport.DialJob(ctx, key, "tcp", addr)
	if err != nil {
		_ = nch.Reject(ssh.ConnectionFailed, fmt.Sprintf("could not reach %s inside %s: %v", addr, target, err))
		return
	}
	defer func() { _ = conn.Close() }()

	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()
	go ssh.DiscardRequests(reqs)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = copyStream(conn, ch); closeWrite(conn) }()
	go func() { defer wg.Done(); _, _ = copyStream(ch, conn); _ = ch.CloseWrite() }()
	wg.Wait()
}

// streamLocalChannelType is OpenSSH's extension for forwarding to a
// Unix socket rather than a port.
const streamLocalChannelType = "direct-streamlocal@openssh.com"

// handleStreamLocal forwards to a Unix socket inside the job.
//
// Worth having rather than telling people to use a port: a TCP port
// bound to 127.0.0.1 in a sandbox is reachable by every local user on
// the execute node unless the job has its own network namespace, which
// no pool can be assumed to configure. A socket in the scratch
// directory is protected by file permissions instead.
//
// Like a port forward and unlike a session, this opens no session
// channel in the job and so does not draw on the sshd's session
// budget.
func (s *Server) handleStreamLocal(ctx context.Context, account, user string, nch ssh.NewChannel) {
	// RFC-less but stable: socket path, then two reserved fields that
	// OpenSSH sends empty.
	var p struct {
		SocketPath string
		Reserved   string
		ReservedN  uint32
	}
	if err := ssh.Unmarshal(nch.ExtraData(), &p); err != nil {
		_ = nch.Reject(ssh.ConnectionFailed, "could not read the socket-forwarding request")
		return
	}
	if p.SocketPath == "" {
		_ = nch.Reject(ssh.ConnectionFailed, "no socket path in the forwarding request")
		return
	}

	key, target, err := s.resolve(ctx, account, user, nil)
	if err != nil {
		_ = nch.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	conn, err := s.Transport.DialJob(ctx, key, "unix", p.SocketPath)
	if err != nil {
		// sun_path is capped near 104 bytes and an HTCondor scratch
		// directory can fill most of it, so a path that is simply too
		// long is a realistic cause and the failure names nothing.
		_ = nch.Reject(ssh.ConnectionFailed,
			fmt.Sprintf("could not reach the socket %s inside %s: %v", p.SocketPath, target, err))
		return
	}
	defer func() { _ = conn.Close() }()

	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()
	go ssh.DiscardRequests(reqs)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = copyStream(conn, ch); closeWrite(conn) }()
	go func() { defer wg.Done(); _, _ = copyStream(ch, conn); _ = ch.CloseWrite() }()
	wg.Wait()
}

// sendExitStatus reports how the remote command ended.
//
// An ssh client that gets no exit-status reports 255 and "connection
// closed", which is indistinguishable from the transport breaking. A
// command that legitimately exits 1 must not look like that.
func sendExitStatus(ch ssh.Channel, waitErr error) {
	status := uint32(0)
	// Matched structurally, not as *ssh.ExitError. JobSession is an
	// interface, so what its Wait returns is up to the implementation;
	// requiring one concrete type would silently report 255 for any
	// other, which is exactly the "the connection broke" reading this
	// function exists to avoid.
	var exitErr interface{ ExitStatus() int }
	switch {
	case waitErr == nil:
	case errors.As(waitErr, &exitErr):
		if st := exitErr.ExitStatus(); st >= 0 && st <= 255 {
			status = uint32(st) //nolint:gosec // bounded just above
		} else {
			status = 255
		}
	default:
		// Killed by a signal, or the session ended without a status.
		// 255 is what ssh itself reports for "something went wrong".
		status = 255
	}
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	_ = ch.CloseWrite()
}

// parseTerminalModes decodes the encoded terminal modes from a
// pty-req: opcode/value pairs, ending at opcode 0.
//
// Dropping them is not harmless -- ECHO lives here, and a shell that
// comes up with echo off looks like a hung terminal.
func parseTerminalModes(s string) ssh.TerminalModes {
	modes := ssh.TerminalModes{}
	b := []byte(s)
	for len(b) >= 5 {
		op := b[0]
		if op == 0 {
			break
		}
		modes[op] = uint32(b[1])<<24 | uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4])
		b = b[5:]
	}
	return modes
}

func replyTo(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

// copyStream is io.Copy with a modest fixed buffer, so a busy gateway
// does not size one buffer per stream off whatever the source suggests.
func copyStream(dst io.Writer, src io.Reader) (int64, error) {
	return io.CopyBuffer(dst, src, make([]byte, 32*1024))
}

// closeWrite half-closes a connection when it supports it, so the far
// end sees EOF rather than waiting.
func closeWrite(c net.Conn) {
	type halfCloser interface{ CloseWrite() error }
	if hc, ok := c.(halfCloser); ok {
		_ = hc.CloseWrite()
	}
}

func (s *Server) logf(msg string, args ...any) {
	if s.Logger == nil {
		return
	}
	s.Logger.Info(logging.DestinationHTTP, msg, args...)
}
