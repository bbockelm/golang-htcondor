package jupytertunnel

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

// defaultYamuxConfig returns a yamux config with logging silenced. yamux
// requires that either Logger or LogOutput be set; the default config sets
// LogOutput=os.Stderr which would spew protocol-level chatter into our
// process. We send it to io.Discard instead.
func defaultYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.Logger = nil
	return cfg
}

// Registry tracks pending and live Jupyter tunnel instances.
//
// Lifecycle of an instance:
//
//  1. Caller (typically a JupyterLab submit handler) calls CreateInstance().
//     The registry mints a fresh instance id and a single-use bearer token,
//     and returns both. The caller is responsible for shipping the token to
//     the worker (e.g. via transfer_input_files).
//
//  2. The helper inside the job dials POST .../instances/{id}/tunnel with the
//     token in Authorization. The HTTP handler calls AcceptTunnel() with the
//     upgraded websocket; the registry verifies the token, burns the nonce,
//     wraps the connection with yamux, and stores it as the live tunnel.
//
//  3. Browser HTTP requests reach the proxy handler which calls Proxy().
//     Proxy() opens a new yamux stream and runs httputil.ReverseProxy on it.
//
//  4. CloseInstance() (or the helper hanging up) tears the tunnel down. New
//     proxy calls return a stale-instance error.
//
// All Registry methods are safe to call from multiple goroutines.
type Registry struct {
	secret []byte

	// tokenTTL bounds how long a minted token stays usable. After expiry
	// the helper must request a new instance. Default 30 minutes.
	tokenTTL time.Duration

	// idleTTL bounds how long an instance can sit in "pending" (created but
	// helper hasn't connected back) before garbage collection. Default
	// 15 minutes.
	idleTTL time.Duration

	mu        sync.Mutex
	instances map[string]*Instance // keyed by hex(id)
	burned    map[[tokenNonceLen]byte]struct{}
}

// Instance is the registry's view of a single Jupyter session.
type Instance struct {
	ID      string // hex(id)
	Created time.Time

	// Owner is the authenticated username that created this instance.
	// Used by the proxy handler for ACL checks.
	Owner string

	// Free-form metadata the submitter wants to remember (e.g. cluster id,
	// docker image). The registry never reads this.
	Meta map[string]string

	mu      sync.Mutex
	tunnel  *yamux.Session // nil until helper connects back
	pending *signedToken   // bookkeeping copy for token expiry
	closed  bool

	// Event subscribers receive lifecycle events as they happen. Each
	// subscriber gets a buffered channel; if it falls behind we drop
	// events for that subscriber rather than block the publisher.
	subscribersMu sync.Mutex
	subscribers   map[chan Event]struct{}
	// lastEvents holds the most recent event of each kind so a new
	// subscriber attaching after the helper has already connected gets
	// the current state immediately, not just future deltas.
	lastEvents map[EventKind]Event
}

// EventKind enumerates the lifecycle events emitted on an Instance.
type EventKind string

const (
	// EventCreated fires the moment CreateInstance returns. Useful as a
	// sanity-check first frame for SSE clients.
	EventCreated EventKind = "created"
	// EventTunnelConnected fires when the helper has dialed back and
	// AcceptTunnel has registered the yamux session. The browser should
	// switch from "submitting…" to "ready".
	EventTunnelConnected EventKind = "tunnel-connected"
	// EventClosed fires when the instance is torn down for any reason
	// (helper hung up, CloseInstance called, etc).
	EventClosed EventKind = "closed"
)

// Event is one lifecycle notification.
type Event struct {
	Kind EventKind         `json:"kind"`
	At   time.Time         `json:"at"`
	Meta map[string]string `json:"meta,omitempty"`
}

// Subscribe returns a channel that receives all *future* events on this
// instance, plus any "sticky" events (created, tunnel-connected) that have
// already fired. Cap is the per-subscriber channel buffer; events past the
// buffer are silently dropped for that subscriber. The caller must call the
// returned cancel function to unsubscribe; otherwise the channel leaks.
func (i *Instance) Subscribe(bufSize int) (<-chan Event, func()) {
	if bufSize <= 0 {
		bufSize = 16
	}
	ch := make(chan Event, bufSize)

	i.subscribersMu.Lock()
	if i.subscribers == nil {
		i.subscribers = make(map[chan Event]struct{})
	}
	i.subscribers[ch] = struct{}{}
	// Replay sticky events. We hold the mutex so a concurrent publish
	// either sees us in the set (and delivers) or fires before us
	// (and we get it from lastEvents) — never both.
	for _, ev := range i.lastEvents {
		select {
		case ch <- ev:
		default:
		}
	}
	i.subscribersMu.Unlock()

	cancel := func() {
		i.subscribersMu.Lock()
		if _, ok := i.subscribers[ch]; ok {
			delete(i.subscribers, ch)
			close(ch)
		}
		i.subscribersMu.Unlock()
	}
	return ch, cancel
}

func (i *Instance) publish(kind EventKind) {
	ev := Event{Kind: kind, At: time.Now()}
	if kind == EventTunnelConnected {
		ev.Meta = copyMeta(i.Meta) // snapshot at moment of connect
	}
	i.subscribersMu.Lock()
	if i.lastEvents == nil {
		i.lastEvents = make(map[EventKind]Event)
	}
	i.lastEvents[kind] = ev
	for ch := range i.subscribers {
		select {
		case ch <- ev:
		default:
			// Slow subscriber; drop this event for them. Better than
			// blocking the helper's connect-back path.
		}
	}
	if kind == EventClosed {
		// On terminal event, close all remaining subscribers so SSE
		// handlers wake up and finish the response cleanly.
		for ch := range i.subscribers {
			delete(i.subscribers, ch)
			close(ch)
		}
	}
	i.subscribersMu.Unlock()
}

// NewRegistry creates a registry with a random 32-byte signing secret and
// default TTLs. The secret lives in process memory only — restarts kill all
// pending tokens.
func NewRegistry() (*Registry, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("jupytertunnel: gen secret: %w", err)
	}
	return &Registry{
		secret:    secret,
		tokenTTL:  30 * time.Minute,
		idleTTL:   15 * time.Minute,
		instances: make(map[string]*Instance),
		burned:    make(map[[tokenNonceLen]byte]struct{}),
	}, nil
}

// CreateInstanceOptions configures a new instance.
type CreateInstanceOptions struct {
	Owner string            // authenticated username; required
	Meta  map[string]string // copied; optional
}

// CreateInstance mints a fresh instance and its single-use bearer token.
// Returns the instance ID and the encoded token string. The caller must ship
// the token to the helper out-of-band (transfer_input_files file) and never
// log it.
func (r *Registry) CreateInstance(opts CreateInstanceOptions) (id string, token string, err error) {
	if opts.Owner == "" {
		return "", "", errors.New("jupytertunnel: owner required")
	}

	rawID, err := generateInstanceID()
	if err != nil {
		return "", "", err
	}
	tokenStr, parsed, err := mintToken(r.secret, rawID, r.tokenTTL)
	if err != nil {
		return "", "", err
	}

	inst := &Instance{
		ID:      formatInstanceID(rawID),
		Created: time.Now(),
		Owner:   opts.Owner,
		Meta:    copyMeta(opts.Meta),
		pending: &parsed,
	}

	r.mu.Lock()
	r.instances[inst.ID] = inst
	r.mu.Unlock()

	inst.publish(EventCreated)
	return inst.ID, tokenStr, nil
}

// Lookup returns the instance for this id, or false.
func (r *Registry) Lookup(id string) (*Instance, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i, ok := r.instances[id]
	if !ok || i.isClosed() {
		return nil, false
	}
	return i, true
}

// ListByOwner returns every live instance whose Owner matches. Result is
// sorted oldest-first so callers can render a stable list. Closed
// instances are filtered out.
//
// Note: instances live in process memory; restarting the API server
// drops the list. Callers showing a "your sessions" UI should make
// that clear to users.
func (r *Registry) ListByOwner(owner string) []*Instance {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Instance, 0, len(r.instances))
	for _, inst := range r.instances {
		if inst.Owner != owner || inst.isClosed() {
			continue
		}
		out = append(out, inst)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Created.Before(out[j].Created)
	})
	return out
}

// HasTunnel reports whether the helper has connected back. The browser
// uses this on a list to decide whether the iframe is ready to mount
// without waiting on a fresh SSE round-trip.
func (i *Instance) HasTunnel() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.tunnel != nil
}

// AcceptTunnel hands a websocket-upgraded connection to the registry. The
// registry verifies the bearer token, ensures the instance is still pending,
// wraps the websocket with yamux as a *client* (it will be opening streams
// later), and registers it as the live tunnel for this instance.
//
// The handler that called this function should then block until the yamux
// session reports "closed" so it can clean up the upgraded HTTP request.
// AcceptTunnel returns once the tunnel is registered; the caller waits via
// inst.Wait() for teardown.
func (r *Registry) AcceptTunnel(instanceID, bearer string, ws *websocket.Conn) (*Instance, error) {
	parsed, err := parseAndVerify(r.secret, bearer, time.Now())
	if err != nil {
		return nil, err
	}
	if formatInstanceID(parsed.ID) != instanceID {
		return nil, ErrTokenInvalid
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, burned := r.burned[parsed.Nonce]; burned {
		return nil, ErrTokenInvalid
	}
	inst, ok := r.instances[instanceID]
	if !ok || inst.isClosed() {
		return nil, ErrTokenInvalid
	}
	if inst.tunnel != nil {
		// Already connected once. Refuse a second connection so a
		// helper-restart inside the job doesn't blow up an active session.
		return nil, errors.New("jupytertunnel: instance already has an active tunnel")
	}

	// Wrap the websocket and start yamux as the *client* side: the web app
	// is the side that opens streams (one per browser request). The helper
	// is the yamux server.
	session, err := yamux.Client(newWSConn(ws), defaultYamuxConfig())
	if err != nil {
		return nil, fmt.Errorf("yamux client: %w", err)
	}

	inst.mu.Lock()
	inst.tunnel = session
	inst.pending = nil
	inst.mu.Unlock()

	r.burned[parsed.Nonce] = struct{}{}
	inst.publish(EventTunnelConnected)

	// Reap when the underlying yamux session closes (helper hung up, etc).
	go func() {
		<-session.CloseChan()
		r.CloseInstance(instanceID)
	}()
	return inst, nil
}

// CloseInstance forcibly tears down an instance. Subsequent Lookup returns
// false. Idempotent.
func (r *Registry) CloseInstance(id string) {
	r.mu.Lock()
	inst, ok := r.instances[id]
	if !ok {
		r.mu.Unlock()
		return
	}
	delete(r.instances, id)
	r.mu.Unlock()

	inst.mu.Lock()
	if inst.closed {
		inst.mu.Unlock()
		return
	}
	inst.closed = true
	tun := inst.tunnel
	inst.mu.Unlock()
	if tun != nil {
		_ = tun.Close()
	}
	inst.publish(EventClosed)
}

// Proxy serves an HTTP request through the tunnel. The path passed in
// `upstreamPath` (with leading slash) is sent verbatim to Jupyter — the
// caller is responsible for any rewriting. In our usage we forward the
// full browser-facing path (/api/v1/jupyter/.../proxy/lab) so it lines
// up with Jupyter's --ServerApp.base_url; stripping the prefix here
// would make Jupyter 404 on its own self-generated URLs. Headers and
// method are forwarded as-is. WebSocket upgrades are handled by Go's
// httputil.ReverseProxy automatically (since Go 1.20+).
func (r *Registry) Proxy(inst *Instance, upstreamPath string, w http.ResponseWriter, req *http.Request) {
	inst.mu.Lock()
	tun := inst.tunnel
	inst.mu.Unlock()
	if tun == nil || tun.IsClosed() {
		http.Error(w, "tunnel not connected", http.StatusBadGateway)
		return
	}

	// Preserve the browser-facing Host header. Our Transport.Dial
	// ignores Host and goes straight to a yamux stream, so the value
	// is "cosmetic" from a routing perspective — but JupyterLab's
	// cross-origin check compares the request's Host against the
	// Origin header, and an HTTPS browser request has Origin =
	// "https://<host>". If we rewrote Host to a sentinel like
	// "jupytertunnel.local", the LabApp logged
	//   "Blocking Cross Origin API request ... Origin: https://h, Host: jupytertunnel.local"
	// and 404'd half of JupyterLab's own internal API calls. Passing
	// the browser's Host through makes Origin == Host and Jupyter is
	// happy.
	browserHost := req.Host
	if browserHost == "" {
		browserHost = "jupytertunnel.local" // shouldn't happen; defensive
	}
	target := *req.URL
	target.Scheme = "http"
	target.Host = browserHost
	target.Path = upstreamPath
	if upstreamPath == "" {
		target.Path = "/"
	}

	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL = &target
			r.Host = target.Host
			// Do NOT strip Connection here. httputil.ReverseProxy
			// (Go ≥1.13) already removes hop-by-hop headers per
			// RFC 7230 in its own outbound code path. More importantly,
			// for WebSocket upgrades it inspects the request's
			// Connection header *after* the Director runs to decide
			// whether to take the upgrade-handling path — see
			// upgradeType() in net/http/httputil/reverseproxy.go.
			// Deleting Connection here turned every kernel + terminal
			// WebSocket attempt into a plain GET that Jupyter rejected
			// with 400.
		},
		Transport: &yamuxRoundTripper{session: tun},
		// Allow long-lived websocket / SSE connections (Jupyter kernels).
		FlushInterval: 100 * time.Millisecond,
	}
	proxy.ServeHTTP(w, req)
}

// yamuxRoundTripper is the http.RoundTripper that dials each request via a
// fresh yamux stream instead of a TCP socket. The fake "addr" passed to
// session.Open() is unused; yamux multiplexes everything onto the single
// underlying websocket.
type yamuxRoundTripper struct {
	session *yamux.Session
	tr      http.Transport
	once    sync.Once
}

func (t *yamuxRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.once.Do(func() {
		t.tr = http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return t.session.Open()
			},
			Dial: func(_, _ string) (net.Conn, error) {
				return t.session.Open()
			},
			DisableKeepAlives: true, // Each yamux stream is single-use.
		}
	})
	return t.tr.RoundTrip(req)
}

func (i *Instance) isClosed() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.closed
}

// Wait blocks until the instance's tunnel is closed (helper hung up,
// CloseInstance called, etc). Returns immediately if already closed or never
// connected.
func (i *Instance) Wait() {
	i.mu.Lock()
	tun := i.tunnel
	i.mu.Unlock()
	if tun != nil {
		<-tun.CloseChan()
	}
}

func copyMeta(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
