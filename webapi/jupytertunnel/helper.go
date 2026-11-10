package jupytertunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

// HelperConfig configures RunHelperTunnel.
type HelperConfig struct {
	// UpstreamURL is the wss:// or ws:// endpoint the helper should dial,
	// typically /api/v1/jupyter/instances/{id}/tunnel.
	UpstreamURL string

	// Token is the bearer token the web app minted for this instance.
	// Sent as Authorization: Bearer <Token>.
	Token string

	// SocketPath is the local Unix domain socket where the upstream service
	// (Jupyter) is listening. The helper dials this for every yamux stream.
	SocketPath string

	// Logger receives non-fatal status messages. nil silences output.
	Logger func(format string, args ...any)

	// HandshakeTimeout caps the websocket dial. Default 30 s.
	HandshakeTimeout time.Duration

	// TLSInsecureSkipVerify, when true, accepts any server cert. Useful
	// only for development.
	TLSInsecureSkipVerify bool

	// TLSRootCAs supplies an additional set of certificate authorities
	// to trust when verifying the upstream server. The helper inside a
	// HTCondor sandbox typically has none of the host's system CAs
	// available, so handing it the API server's own CA (or the public
	// CA chain, in production) is the simplest path to a verified TLS
	// connection. Nil = use the system pool.
	TLSRootCAs *x509.CertPool

	// IdleTimeout, when > 0, closes the tunnel and exits if no yamux
	// stream has been accepted from the upstream peer within this
	// window. Used as an auto-shutdown for stuck JupyterLab sessions
	// — if the user never opens the iframe (or jupyter-lab failed at
	// startup and stopped responding), the slot frees automatically
	// instead of being held forever.
	//
	// Each successful Accept resets the deadline. Zero = no timeout.
	IdleTimeout time.Duration

	// TokenPath is where the helper writes a token the server hands it
	// over the control channel. Empty means a received token is kept in
	// memory only, which still survives a reconnect but not a restart of
	// the helper itself.
	TokenPath string

	// OnNextToken, when set, is called with each token the server issues,
	// after it has been persisted. A seam for tests, which have no
	// business reading the helper's token file.
	OnNextToken func(token string)

	// IdleClock, when set, carries the idle measurement across calls, so a
	// caller that reconnects keeps one clock for the whole session. Nil
	// gives each call a fresh one.
	IdleClock *IdleClock

	// OnConnected, when set, is called once the server has accepted this
	// helper: when the first stream arrives over the tunnel, on the
	// goroutine that called RunHelperTunnel.
	//
	// Not when the websocket and yamux are up. The server upgrades the
	// connection before it checks the token, so a dial it then refuses --
	// a busy session, a database it could not write -- gets that far too,
	// and a caller resetting its backoff on it redials a refusing server
	// at the floor rate for as long as the refusals last. An accepted
	// helper is sent its next token on a control stream at once (with a
	// session store), or a proxied request when the browser next asks.
	OnConnected func()
}

// IdleClock measures how long a session has gone without a proxied request,
// counting only time the tunnel was up.
//
// Both halves matter once the helper reconnects. A disconnect is not
// idleness -- nobody could reach the session to use it -- so time spent
// down is not counted, and a server outage does not end a session the moment
// it comes back. Nor is a reconnect activity: restarting the clock on every
// dial would let a flapping tunnel keep an abandoned session alive forever.
// So the clock pauses while the tunnel is down and resumes where it was.
type IdleClock struct {
	mu        sync.Mutex
	last      time.Time // last activity, shifted forward by time spent down
	downSince time.Time // zero while the tunnel is up
}

// Touch records activity.
func (c *IdleClock) Touch() { c.touch(time.Now()) }

func (c *IdleClock) touch(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = now
}

// Up records that the tunnel is (re)established.
func (c *IdleClock) Up() { c.up(time.Now()) }

func (c *IdleClock) up(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.last.IsZero():
		c.last = now
	case !c.downSince.IsZero():
		c.last = c.last.Add(now.Sub(c.downSince))
	}
	c.downSince = time.Time{}
}

// Down records that the tunnel has dropped.
func (c *IdleClock) Down() { c.down(time.Now()) }

func (c *IdleClock) down(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.downSince.IsZero() {
		c.downSince = now
	}
}

// IdleFor is how long the session has been idle while connected.
func (c *IdleClock) IdleFor() time.Duration { return c.idleFor(time.Now()) }

func (c *IdleClock) idleFor(now time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last.IsZero() {
		return 0
	}
	end := now
	if !c.downSince.IsZero() {
		end = c.downSince
	}
	return end.Sub(c.last)
}

// RunHelperTunnel dials the upstream websocket, wraps it with yamux as the
// server side, and accepts streams. Each stream is dialed to the local UDS
// and bytes are copied bidirectionally. RunHelperTunnel returns when the
// session ends (peer hangup, ctx cancellation, hard error). It does not
// daemonize — that is the caller's responsibility.
func RunHelperTunnel(ctx context.Context, cfg HelperConfig) error {
	if cfg.UpstreamURL == "" {
		return errors.New("helper: UpstreamURL required")
	}
	if cfg.Token == "" {
		return errors.New("helper: Token required")
	}
	if cfg.SocketPath == "" {
		return errors.New("helper: SocketPath required")
	}
	logf := cfg.Logger
	if logf == nil {
		logf = func(string, ...any) {}
	}
	timeout := cfg.HandshakeTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	if _, err := url.Parse(cfg.UpstreamURL); err != nil {
		return fmt.Errorf("helper: parse upstream: %w", err)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: timeout,
		ReadBufferSize:   32 * 1024,
		WriteBufferSize:  32 * 1024,
	}
	// Build a TLS config when either toggle is set. Without one,
	// gorilla/websocket falls back to the host's system roots — which
	// inside a HTCondor sandbox is often empty / minimal, hence the
	// "x509: certificate not trusted" we used to hit on demos.
	if cfg.TLSInsecureSkipVerify || cfg.TLSRootCAs != nil {
		dialer.TLSClientConfig = &tls.Config{
			//nolint:gosec // explicit opt-in via HelperConfig; demo / dev only
			InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
			RootCAs:            cfg.TLSRootCAs,
			MinVersion:         tls.VersionTLS12,
		}
	}

	header := http.Header{}
	header.Set("Authorization", "Bearer "+cfg.Token)

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ws, resp, err := dialer.DialContext(dialCtx, cfg.UpstreamURL, header)
	if err != nil {
		if resp != nil {
			status := resp.Status
			_ = resp.Body.Close()
			return fmt.Errorf("helper: dial upstream: %w (status %s)", err, status)
		}
		return fmt.Errorf("helper: dial upstream: %w", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	logf("helper: connected to %s", cfg.UpstreamURL)

	// Match the registry side: web app is yamux *client* (opens streams);
	// the helper is the yamux *server* (accepts them).
	session, err := yamux.Server(newWSConn(ws), defaultYamuxConfig())
	if err != nil {
		_ = ws.Close()
		return fmt.Errorf("helper: yamux server: %w", err)
	}
	defer func() { _ = session.Close() }()

	// On context cancel, slam the session shut so Accept returns.
	go func() {
		<-ctx.Done()
		_ = session.Close()
	}()

	// Idle-shutdown watcher: if no proxied stream arrives within
	// cfg.IdleTimeout of connected time, close the session. Each proxied
	// stream touches the clock (handleOrControl) so a busy session is never
	// reaped; the control stream the server opens on every connect does
	// not, or a reconnect would count as use. We tick at IdleTimeout/4 so
	// the worst-case overshoot is 25% — small enough that "30 minutes"
	// really means 30–37 minutes, not 60.
	clock := cfg.IdleClock
	if clock == nil {
		clock = &IdleClock{}
		cfg.IdleClock = clock
	}
	clock.Up()
	defer clock.Down()
	// Set when the watcher below gave up, so the caller can tell an idle
	// session from a lost one. They look identical at the accept loop --
	// both are a closed session -- and a reconnect loop that cannot tell
	// them apart dials straight back in and defeats the timeout.
	var idledOut atomic.Bool
	if cfg.IdleTimeout > 0 {
		go func() {
			tickEvery := cfg.IdleTimeout / 4
			if tickEvery < time.Second {
				tickEvery = time.Second
			}
			t := time.NewTicker(tickEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-session.CloseChan():
					// This tunnel is gone; the next one runs its own
					// watcher over the same clock.
					return
				case <-t.C:
					if clock.IdleFor() > cfg.IdleTimeout {
						logf("helper: idle timeout (%s with no streams); closing session",
							cfg.IdleTimeout)
						idledOut.Store(true)
						_ = session.Close()
						return
					}
				}
			}
		}()
	}

	accepted := false
	for {
		stream, err := session.Accept()
		if err != nil {
			if idledOut.Load() {
				return ErrIdleTimeout
			}
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				logf("helper: session closed")
				return nil
			}
			return fmt.Errorf("helper: accept stream: %w", err)
		}
		if !accepted {
			accepted = true
			if cfg.OnConnected != nil {
				cfg.OnConnected()
			}
		}
		// Pass the request-scoped context so the UDS dial inherits the
		// helper's lifetime (gosec G118): cancelling ctx — which
		// happens when the parent stops the tunnel — must also abort
		// in-flight stream-handler dials.
		go handleOrControl(ctx, stream, cfg, logf)
	}
}

// handleOrControl splits the control channel off from the proxy path.
//
// A control stream must never reach JupyterLab: it carries the token for the
// next dial, and forwarding it would hand a live credential to the notebook
// server (and, through it, to anything the notebook can reach).
func handleOrControl(ctx context.Context, stream net.Conn, cfg HelperConfig, logf func(string, ...any)) {
	br, isControl := peekControl(stream)
	if !isControl {
		if cfg.IdleClock != nil {
			cfg.IdleClock.Touch()
		}
		handleBufferedStream(ctx, stream, br, cfg.SocketPath, logf)
		return
	}
	defer func() { _ = stream.Close() }()
	verb, arg, err := readControl(br)
	if err != nil {
		logf("helper: control stream unreadable: %v", err)
		return
	}
	if verb != "next-token" || arg == "" {
		logf("helper: ignoring unknown control verb %q", verb)
		return
	}
	if err := persistToken(cfg.TokenPath, arg); err != nil {
		// Not fatal to this session, which is already up. It costs the
		// NEXT dial, so say so plainly rather than failing silently and
		// leaving a session that cannot come back.
		logf("helper: could not persist the next token; a reconnect will not authenticate: %v", err)
	}
	if cfg.OnNextToken != nil {
		cfg.OnNextToken(arg)
	}
}

// persistToken replaces the token file atomically.
//
// Atomically because the helper may be killed at any moment: a partially
// written token is not merely stale, it is unusable, and the session it
// belonged to could never reconnect.
func persistToken(path, token string) error {
	if path == "" {
		return nil
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(token), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func handleBufferedStream(ctx context.Context, stream net.Conn, br *bufio.Reader, socketPath string, logf func(string, ...any)) {
	defer func() { _ = stream.Close() }()
	// Local UDS dial — no useful context lifetime to enforce, but the
	// linter prefers DialContext. We thread the parent's ctx through
	// so a tunnel shutdown cancels in-flight dials, even though
	// localhost UDS dials usually return instantly.
	d := &net.Dialer{}
	upstream, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		logf("helper: dial UDS %s: %v", socketPath, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	// Copy bytes both ways. The first goroutine to finish (one side closes
	// the connection) propagates a half-close to the other and we return.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// From br, not stream. Deciding whether this was a control
		// stream meant peeking at its first bytes, and those now sit in
		// br's buffer -- reading the raw stream here would skip them and
		// hand JupyterLab a request with its method line chewed off.
		_, _ = io.Copy(upstream, br)
		// Stream EOF means the web-app peer closed the request body; we
		// can shut down the write half of the UDS to let the upstream
		// finish responding before we close.
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, upstream)
		if cw, ok := stream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}
