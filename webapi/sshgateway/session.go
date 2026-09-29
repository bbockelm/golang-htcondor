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
type ResolveFunc func(ctx context.Context, account string, t Target) (jobssh.Key, error)

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
		default:
			_ = nch.Reject(ssh.UnknownChannelType,
				fmt.Sprintf("this gateway serves sessions and port forwards, not %q", nch.ChannelType()))
		}
	}
	wg.Wait()
}

// resolve parses the username and finds the job behind it.
func (s *Server) resolve(ctx context.Context, account, user string) (jobssh.Key, Target, error) {
	target, err := ParseTarget(user)
	if err != nil {
		return jobssh.Key{}, Target{}, err
	}
	key, err := s.Resolve(ctx, account, target)
	if err != nil {
		return jobssh.Key{}, target, err
	}
	return key, target, nil
}

// handleSession proxies one session channel: a shell, a command, or a
// PTY, whichever the client asks for once the channel is open.
//
// The job session is opened BEFORE the channel is accepted, so that a
// refusal carries a reason the client will print. Once a channel is
// accepted the only way to explain anything is to write to it, which
// an ssh client running a command shows in a much less obvious place.
func (s *Server) handleSession(ctx context.Context, account, user string, nch ssh.NewChannel) {
	key, target, err := s.resolve(ctx, account, user)
	if err != nil {
		_ = nch.Reject(ssh.ConnectionFailed, err.Error())
		s.logf("Could not resolve a session target", "account", account, "target", user, "error", err)
		return
	}

	sess, release, err := s.Transport.Session(ctx, key)
	if err != nil {
		reason := ssh.ConnectionFailed
		msg := fmt.Sprintf("could not open a session in %s: %v", target, err)
		if errors.Is(err, jobssh.ErrTooManySessions) {
			// Its own rejection code, because this one is worth
			// retrying in a minute and the others are not.
			reason = ssh.ResourceShortage
			msg = fmt.Sprintf("%s already has %d sessions open, which is all the job's sshd allows. "+
				"Close a terminal and try again.", target, jobssh.MaxSessionsPerTransport)
		}
		_ = nch.Reject(reason, msg)
		s.logf("Could not open a job session", "account", account, "job", key.String(), "error", err)
		return
	}
	defer release()
	defer func() { _ = sess.Close() }()

	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()

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

	// The client may never ask for anything. Watching the request
	// stream end is how that connection gets cleaned up instead of
	// blocking on a command that is never going to start.
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

	reqsDone := make(chan struct{})
	go func() {
		defer close(reqsDone)
		s.serveSessionRequests(reqs, sess, ch, start)
	}()

	select {
	case <-started:
	case <-reqsDone:
		// The channel closed without a shell or an exec.
		return
	case <-ctx.Done():
		return
	}

	// Only now is there a remote command to carry bytes for. The pipes
	// were taken earlier because x/crypto requires it before the
	// command starts, not because they were usable before this point.
	var ioWG sync.WaitGroup
	ioWG.Add(2)
	go func() { defer ioWG.Done(); _, _ = copyStream(ch, stdout) }()
	go func() { defer ioWG.Done(); _, _ = copyStream(ch.Stderr(), stderr) }()
	go func() {
		// The client closing its half must reach the job as EOF, or a
		// command reading stdin never finishes.
		_, _ = copyStream(stdin, ch)
		_ = stdin.Close()
	}()

	waitErr := sess.Wait()
	ioWG.Wait()
	sendExitStatus(ch, waitErr)
}

// serveSessionRequests translates the client's session requests.
func (s *Server) serveSessionRequests(reqs <-chan *ssh.Request, sess jobssh.JobSession, ch ssh.Channel, start func(func() error) bool) {
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var p struct {
				Term                       string
				Columns, Rows, Width, High uint32
				Modes                      string
			}
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				replyTo(req, false)
				continue
			}
			// RequestPty takes (height, width) -- rows first. The wire
			// order is columns first. Swapping them produces a
			// terminal that looks right until something wraps.
			err := sess.RequestPty(p.Term, int(p.Rows), int(p.Columns), parseTerminalModes(p.Modes))
			replyTo(req, err == nil)

		case "window-change":
			var p struct {
				Columns, Rows, Width, High uint32
			}
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				replyTo(req, false)
				continue
			}
			replyTo(req, sess.WindowChange(int(p.Rows), int(p.Columns)) == nil)

		case "shell":
			replyTo(req, start(sess.Shell))

		case "exec":
			var p struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				replyTo(req, false)
				continue
			}
			cmd := p.Command
			replyTo(req, start(func() error { return sess.Start(cmd) }))

		case "signal":
			var p struct{ Signal string }
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				replyTo(req, false)
				continue
			}
			replyTo(req, sess.Signal(ssh.Signal(p.Signal)) == nil)

		case "env":
			// Accepted and dropped. The job's sshd takes AcceptEnv *,
			// but x/crypto has no way to set an environment on a
			// session other than Setenv, and refusing makes noisy
			// clients print a warning for something harmless.
			replyTo(req, true)

		case "subsystem":
			var p struct{ Name string }
			_ = ssh.Unmarshal(req.Payload, &p)
			// sftp cannot work through condor_ssh_to_job: the forced
			// command in condor_ssh_to_job_shell_setup turns the
			// subsystem request into `eval sftp`. Say so, because
			// "subsystem request failed" sends people looking in the
			// wrong place.
			_, _ = fmt.Fprintf(ch.Stderr(),
				"This gateway cannot run the %q subsystem: HTCondor's ssh-to-job wrapper does not support it.\r\n",
				p.Name)
			replyTo(req, false)

		default:
			replyTo(req, false)
		}
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

	key, target, err := s.resolve(ctx, account, user)
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
