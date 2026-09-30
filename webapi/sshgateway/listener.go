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
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-htcondor/logging"
)

// HandshakeTimeout bounds the SSH handshake, which includes the
// device-flow login. It is generous because a human is reading a code
// off their terminal and typing it into a browser.
const HandshakeTimeout = 6 * time.Minute

// Listener accepts SSH connections, authenticates them and hands them
// to a Server.
type Listener struct {
	// Addr is where to listen, e.g. ":2222". Required.
	Addr string
	// HostKey is what clients pin in known_hosts. Required, and
	// stable across restarts and replicas -- a new one presents as a
	// man-in-the-middle to everybody who has connected before.
	HostKey ssh.Signer
	// Auth and Server are required.
	Auth   *Authenticator
	Server *Server

	// Certs, when set, lets a client authenticate with a certificate
	// this deployment's CA signed instead of going through the
	// browser. Optional; without it the device flow is the only way
	// in.
	Certs *CertAuth

	// ConnContext derives the context each connection's work runs
	// under, from the identity the Authenticator resolved. This is
	// where the caller's HTCondor credential is attached: everything
	// the connection does afterwards runs as that person, so it must
	// not be built from the SSH username.
	//
	// Optional, and a caller that serves real jobs must supply it.
	// Without it the connection runs under the context passed to
	// Listen, which carries no caller credential -- and a context with
	// none does not fail closed downstream: HTCondor falls back to this
	// daemon's own configuration, so the session would run as the
	// daemon. An earlier version of this comment claimed the schedd
	// would refuse such a connection. It does not.
	ConnContext func(ctx context.Context, conn *ssh.ServerConn) (context.Context, error)

	Logger *logging.Logger

	mu       sync.Mutex
	ln       net.Listener
	cfg      *ssh.ServerConfig
	closed   bool
	conns    sync.WaitGroup
	shutdown chan struct{}
}

// Listen binds the port and prepares the server configuration.
//
// Separate from Serve so a caller can fail startup on a bind error.
// When this ran inside the serving goroutine, "address already in use"
// only reached a log line while the daemon carried on without the
// gateway -- which is the same class of failure as a missing host key,
// and that one is fatal.
func (l *Listener) Listen(ctx context.Context) error {
	if l.HostKey == nil {
		return errors.New("sshgateway: a host key is required")
	}
	if l.Auth == nil || l.Server == nil {
		return errors.New("sshgateway: an Authenticator and a Server are required")
	}

	cfg := &ssh.ServerConfig{
		// The device flow is the only method advertised unless
		// certificates are configured below. A client therefore does
		// not attempt publickey, and a user with a loaded agent
		// reaches the prompt without configuring anything.
		KeyboardInteractiveCallback: l.Auth.KeyboardInteractive(ctx),
		ServerVersion:               "SSH-2.0-HTCondorGateway",
	}
	if l.Certs != nil {
		cfg.PublicKeyCallback = l.Certs.Callback
		// A client offers every key it has before it gets to the
		// certificate, and each offer costs an attempt. The default of
		// six is spent by a developer with a populated agent, who then
		// never reaches the prompt. Raising it does not weaken
		// anything meaningful: guessing a key is not a thing, and the
		// device flow has its own concurrency cap.
		cfg.MaxAuthTries = 32
	}
	cfg.AddHostKey(l.HostKey)

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", l.Addr)
	if err != nil {
		return fmt.Errorf("sshgateway: listening on %s: %w", l.Addr, err)
	}

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return ln.Close()
	}
	l.ln = ln
	l.cfg = cfg
	l.shutdown = make(chan struct{})
	l.mu.Unlock()

	l.logf("SSH gateway listening", "address", ln.Addr().String(),
		"host_key", ssh.FingerprintSHA256(l.HostKey.PublicKey()),
		"certificates", l.Certs != nil)
	return nil
}

// Serve accepts until the listener is closed or ctx is done.
//
// Returns nil on a deliberate Close, so a caller can run it in a
// goroutine and treat any non-nil error as worth reporting.
func (l *Listener) Serve(ctx context.Context) error {
	l.mu.Lock()
	ln, cfg, shutdown := l.ln, l.cfg, l.shutdown
	l.mu.Unlock()
	if ln == nil || cfg == nil {
		return errors.New("sshgateway: Serve called before Listen")
	}

	// Closing on ctx cancellation, so a shutdown does not wait for the
	// next connection to arrive before noticing.
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-shutdown:
		}
	}()

	for {
		nc, err := ln.Accept()
		if err != nil {
			l.mu.Lock()
			deliberate := l.closed
			l.mu.Unlock()
			if deliberate {
				l.conns.Wait()
				return nil
			}
			return fmt.Errorf("sshgateway: accept: %w", err)
		}
		l.conns.Add(1)
		go func() {
			defer l.conns.Done()
			l.serveConn(ctx, nc, cfg)
		}()
	}
}

// ListenAndServe is Listen followed by Serve.
func (l *Listener) ListenAndServe(ctx context.Context) error {
	if err := l.Listen(ctx); err != nil {
		return err
	}
	return l.Serve(ctx)
}

// BoundAddr reports the address actually bound, which differs from the
// configured one when the port was 0.
func (l *Listener) BoundAddr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln == nil {
		return ""
	}
	return l.ln.Addr().String()
}

// Close stops accepting and waits for connections in flight.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	ln := l.ln
	if l.shutdown != nil {
		close(l.shutdown)
		l.shutdown = nil
	}
	l.mu.Unlock()

	if ln == nil {
		return nil
	}
	return ln.Close()
}

func (l *Listener) serveConn(ctx context.Context, nc net.Conn, cfg *ssh.ServerConfig) {
	// The handshake carries the whole login, so the deadline has to
	// outlast a human. Cleared once the connection is up, or a long
	// terminal session would die on it.
	_ = nc.SetDeadline(time.Now().Add(HandshakeTimeout))

	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		// Includes every refused login, which is ordinary traffic on a
		// public port and not worth an error-level line each.
		l.debugf("SSH gateway handshake did not complete",
			"remote", nc.RemoteAddr().String(), "error", err)
		_ = nc.Close()
		return
	}
	defer func() { _ = conn.Close() }()
	_ = nc.SetDeadline(time.Time{})

	connCtx := ctx
	if l.ConnContext != nil {
		connCtx, err = l.ConnContext(ctx, conn)
		if err != nil {
			l.logf("Could not prepare a connection's credentials",
				"remote", conn.RemoteAddr().String(), "error", err)
			return
		}
	}

	l.Server.Serve(connCtx, conn, chans, reqs)
}

func (l *Listener) logf(msg string, args ...any) {
	if l.Logger != nil {
		l.Logger.Info(logging.DestinationHTTP, msg, args...)
	}
}

func (l *Listener) debugf(msg string, args ...any) {
	if l.Logger != nil {
		l.Logger.Debug(logging.DestinationHTTP, msg, args...)
	}
}
