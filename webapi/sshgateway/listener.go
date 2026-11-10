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
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-htcondor/logging"
)

// DefaultMaxConnections caps sockets served at once.
const DefaultMaxConnections = 256

// HandshakeTimeout bounds the SSH handshake, which includes the
// device-flow login. It is generous because a human is reading a code
// off their terminal and typing it into a browser.
const HandshakeTimeout = 6 * time.Minute

// Bounds on connections that have not yet begun authenticating: the
// version exchange, the key exchange and the first authentication
// request, none of which waits for a human.
const (
	// DefaultPreAuthTimeout is how long a connection has to ask to
	// authenticate. Only once it has does HandshakeTimeout apply.
	DefaultPreAuthTimeout = 20 * time.Second
	// DefaultMaxPreAuthPerHost caps such connections from one host (an
	// IPv4 address, an IPv6 /64), as sshd's MaxStartups does.
	DefaultMaxPreAuthPerHost = 4
	// DefaultMaxPreAuthPerNetwork caps them from one network (an IPv4
	// /24, an IPv6 /48), the same two granularities the Banlist counts.
	DefaultMaxPreAuthPerNetwork = DefaultNetThresholdRatio * DefaultMaxPreAuthPerHost
)

// Listener accepts SSH connections, authenticates them and hands them
// to a Server.
type Listener struct {
	// Addr is where to listen, e.g. ":2222". Required.
	Addr string
	// HostKey is what clients pin in known_hosts. Required, and
	// stable across restarts and replicas -- a new one presents as a
	// man-in-the-middle to everybody who has connected before.
	HostKey ssh.Signer
	// HostCert, when set, is HostKey wrapped in a certificate signed
	// by this deployment's CA, letting a client verify the gateway
	// from the CA alone.
	//
	// Both are offered, and that is the point rather than an
	// oversight. A client picks the host key algorithm it already
	// knows something about: one holding the CA line negotiates the
	// certificate, while one that pinned the bare key years ago
	// negotiates that and notices nothing. Offering only the
	// certificate would present every existing client with what looks
	// like a brand new host.
	HostCert ssh.Signer
	// Auth and Server are required.
	Auth   *Authenticator
	Server *Server

	// Certs, when set, lets a client authenticate with a certificate
	// this deployment's CA signed instead of going through the
	// browser. Optional; without it the device flow is the only way
	// in.
	Certs *CertAuth

	// Bans locks out a source that keeps failing to authenticate.
	// Optional; nil means no lockout, and every method on a nil
	// *Banlist works, so nothing here is conditional.
	Bans *Banlist

	// MaxConnections caps sockets being served at once. Zero means
	// DefaultMaxConnections.
	//
	// Without one, a slowloris of sockets that never finish the
	// handshake holds a goroutine and an fd each for HandshakeTimeout
	// -- and this listener shares its process with the HTTP API, so
	// running out of descriptors takes the REST and MCP surfaces down
	// with it.
	MaxConnections int

	// PreAuthTimeout bounds how long a connection may take to send its
	// first authentication request. Zero means DefaultPreAuthTimeout.
	//
	// Separate from HandshakeTimeout because only authentication waits
	// for a human. Without it, a socket that never speaks held its
	// connection slot for the whole six minutes.
	PreAuthTimeout time.Duration

	// MaxPreAuthPerHost and MaxPreAuthPerNetwork cap connections from
	// one source that have not yet begun authenticating; past them a
	// new connection is closed at accept. Zero means the defaults.
	//
	// MaxConnections alone let one address hold every slot with idle
	// sockets. Authentication in flight has its own per-source cap in
	// the Authenticator.
	MaxPreAuthPerHost    int
	MaxPreAuthPerNetwork int

	Logger *logging.Logger

	connSlots chan struct{}
	preAuth   *preAuthCounter

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
		// Every refused authentication is reported here, which is
		// where the lockout counts them. Nil when Bans is nil.
		AuthLogCallback: l.Bans.AuthLogCallback(),
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
	// The certificate goes first: where a client is happy with either,
	// x/crypto/ssh offers them in the order they were added, and the
	// certificate is the one that needs no prior knowledge of this
	// host.
	if l.HostCert != nil {
		cfg.AddHostKey(l.HostCert)
	}
	cfg.AddHostKey(l.HostKey)

	if l.MaxConnections <= 0 {
		l.MaxConnections = DefaultMaxConnections
	}
	l.connSlots = make(chan struct{}, l.MaxConnections)
	if l.PreAuthTimeout <= 0 {
		l.PreAuthTimeout = DefaultPreAuthTimeout
	}
	if l.MaxPreAuthPerHost <= 0 {
		l.MaxPreAuthPerHost = DefaultMaxPreAuthPerHost
	}
	if l.MaxPreAuthPerNetwork <= 0 {
		l.MaxPreAuthPerNetwork = DefaultMaxPreAuthPerNetwork
	}
	l.preAuth = newPreAuthCounter(l.MaxPreAuthPerHost, l.MaxPreAuthPerNetwork)

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
				// Close owns the wait now.
				return nil
			}
			return fmt.Errorf("sshgateway: accept: %w", err)
		}
		// Checked before a connection slot is taken, so a locked-out
		// source cannot spend the concurrency budget it was locked
		// out for spending.
		if ok, until := l.Bans.Allow(nc.RemoteAddr()); !ok {
			l.debugf("SSH gateway refused a connection: source is locked out",
				"remote", nc.RemoteAddr().String(), "until", until.Format(time.RFC3339))
			_ = nc.Close()
			continue
		}

		// Also before a connection slot: the per-source cap is what
		// keeps one source from holding all of them.
		releasePreAuth, ok := l.preAuth.take(nc.RemoteAddr())
		if !ok {
			l.debugf("SSH gateway refused a connection: too many unauthenticated connections from its source",
				"remote", nc.RemoteAddr().String())
			_ = nc.Close()
			continue
		}

		select {
		case l.connSlots <- struct{}{}:
		default:
			// Over the cap. Closing immediately is the honest answer:
			// accepting and then stalling would look like the gateway
			// is broken rather than busy.
			l.debugf("SSH gateway refused a connection: at the concurrency limit",
				"remote", nc.RemoteAddr().String(), "limit", l.MaxConnections)
			releasePreAuth()
			_ = nc.Close()
			continue
		}
		l.conns.Add(1)
		go func() {
			defer func() {
				<-l.connSlots
				l.conns.Done()
			}()
			l.serveConn(ctx, nc, cfg, releasePreAuth)
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
	err := ln.Close()

	// Wait for connections in flight, with a bound.
	//
	// The accept loop used to own this wait, in a goroutine nobody
	// joined -- so Close returned immediately and a caller that
	// shut the transports down next cut live sessions off
	// mid-keystroke, which is exactly what its own comment said it
	// was avoiding.
	done := make(chan struct{})
	go func() {
		l.conns.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(ShutdownGrace):
		l.logf("SSH gateway shut down with sessions still open", "grace", ShutdownGrace)
	}
	return err
}

// ShutdownGrace bounds how long Close waits for live sessions. Long
// enough that a reload does not cut somebody off mid-command, short
// enough that a shell somebody walked away from cannot block a
// restart.
const ShutdownGrace = 10 * time.Second

func (l *Listener) serveConn(ctx context.Context, nc net.Conn, cfg *ssh.ServerConfig, releasePreAuth func()) {
	// Until the client asks to authenticate, nothing waits for a human:
	// the short deadline. The first authentication request -- where
	// x/crypto calls BannerCallback -- moves the connection out of the
	// source's pre-auth count and onto HandshakeTimeout, which carries
	// the whole login and so has to outlast a human. Cleared once the
	// connection is up, or a long terminal session would die on it.
	_ = nc.SetDeadline(time.Now().Add(l.PreAuthTimeout))
	var authStarted atomic.Bool
	connCfg := *cfg
	banner := cfg.BannerCallback
	connCfg.BannerCallback = func(md ssh.ConnMetadata) string {
		if !authStarted.Swap(true) {
			_ = nc.SetDeadline(time.Now().Add(HandshakeTimeout))
			releasePreAuth()
		}
		if banner != nil {
			return banner(md)
		}
		return ""
	}

	conn, chans, reqs, err := ssh.NewServerConn(nc, &connCfg)
	releasePreAuth()
	if err != nil {
		// A source whose connections sit silent until the short
		// deadline is charged for it: that is how the slots were
		// held, and nothing legitimate does it. A client that hangs up
		// -- one refusing the host key, say -- is not.
		if !authStarted.Load() && isTimeout(err) {
			l.Bans.Fail(nc.RemoteAddr(), WeightStalled, "did not begin authenticating")
		}
		// Includes every refused login, which is ordinary traffic on a
		// public port and not worth an error-level line each.
		l.debugf("SSH gateway handshake did not complete",
			"remote", nc.RemoteAddr().String(), "error", err)
		_ = nc.Close()
		return
	}
	defer func() { _ = conn.Close() }()
	_ = nc.SetDeadline(time.Time{})

	// Logged HERE rather than in an auth callback. x/crypto calls
	// PublicKeyCallback on the public-key query, before the client has
	// proved possession -- so logging a "login" there lets anyone
	// holding a copy of somebody's certificate, which is public data,
	// write that person's name into the audit log. By this point the
	// handshake has completed.
	account := ""
	if conn.Permissions != nil {
		account = conn.Permissions.Extensions[ExtAccount]
	}
	l.logf("SSH gateway connection authenticated",
		"account", account,
		"remote", conn.RemoteAddr().String(),
		"requested_target", conn.User(),
		"client", string(conn.ClientVersion()))

	// No per-connection credential: Server mints one per channel,
	// because the credential is short-lived and this connection is
	// not.
	l.Server.Serve(ctx, conn, chans, reqs)
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

// isTimeout reports whether err is a deadline expiring.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// preAuthCounter counts connections that have not yet begun
// authenticating, per host and per network (see banKeys).
type preAuthCounter struct {
	maxHost, maxNet int

	mu    sync.Mutex
	hosts map[netip.Prefix]int
	nets  map[netip.Prefix]int
}

func newPreAuthCounter(maxHost, maxNet int) *preAuthCounter {
	return &preAuthCounter{
		maxHost: maxHost,
		maxNet:  maxNet,
		hosts:   map[netip.Prefix]int{},
		nets:    map[netip.Prefix]int{},
	}
}

// take claims a slot for addr and returns its release, which may be
// called more than once; or reports false when addr's host or network is
// at its cap. An address that is not an IP is not counted.
func (c *preAuthCounter) take(addr net.Addr) (func(), bool) {
	host, network, ok := banKeys(addr)
	if !ok {
		return func() {}, true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hosts[host] >= c.maxHost || c.nets[network] >= c.maxNet {
		return nil, false
	}
	c.hosts[host]++
	c.nets[network]++
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			decrement(c.hosts, host)
			decrement(c.nets, network)
		})
	}, true
}

func decrement(m map[netip.Prefix]int, k netip.Prefix) {
	if m[k] <= 1 {
		delete(m, k)
		return
	}
	m[k]--
}
