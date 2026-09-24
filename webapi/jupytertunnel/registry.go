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
	// roller, when set, is where spent nonces are recorded so single-use
	// survives a restart. Nil keeps the in-memory burned set alone, which
	// is right for a registry whose secret is per-process anyway.
	roller NonceRoller

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
	// nextToken is the token this session will accept on its next dial,
	// minted when the current one was spent. Handed to the helper over the
	// tunnel it just opened, so a helper that has connected once always
	// holds exactly one unspent token and can come back after a restart.
	nextToken string
	// connecting marks a dial in flight, so two helpers arriving together
	// do not both get as far as spending a token.
	connecting bool
	closed     bool

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

// NonceRoller persists which token a session will accept next.
//
// Single-use tokens were enforced by an in-memory set of spent nonces, which
// a restart emptied: every token ever issued became live again, at the same
// moment the server lost the ability to tell which sessions were its own. A
// roller moves that record somewhere that survives, and makes the swap
// conditional so two helpers racing a redial cannot both win.
//
// RollNonce reports false when the from-nonce is not the one the session is
// waiting for, which is a replay or a loser of that race, and the caller
// refuses the connection.
type NonceRoller interface {
	RollNonce(ctx context.Context, instanceID string, from, to []byte) (bool, error)
}

// NewRegistry creates a registry with a random 32-byte signing secret and
// default TTLs. The secret lives in process memory only, so tokens minted by
// this registry stop verifying when the process ends. Callers that want
// sessions to outlive a restart pass a durable secret to NewRegistryWithSecret.
func NewRegistry() (*Registry, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("jupytertunnel: gen secret: %w", err)
	}
	return newRegistry(secret), nil
}

// NewRegistryWithSecret creates a registry over a caller-supplied signing
// secret and nonce store.
//
// Both are needed for a session to survive a restart, and for opposite
// reasons: without the secret the helper's token no longer verifies, and
// without the store the token verifies too well -- every spent one is live
// again, because the record of what was spent went with the process.
func NewRegistryWithSecret(secret []byte, roller NonceRoller) (*Registry, error) {
	if len(secret) < 32 {
		return nil, errors.New("jupytertunnel: signing secret must be at least 32 bytes")
	}
	r := newRegistry(secret)
	r.roller = roller
	return r, nil
}

func newRegistry(secret []byte) *Registry {
	return &Registry{
		secret:    secret,
		tokenTTL:  30 * time.Minute,
		idleTTL:   15 * time.Minute,
		instances: make(map[string]*Instance),
		burned:    make(map[[tokenNonceLen]byte]struct{}),
	}
}

// reserve claims the session's single connection slot for this dial.
//
// The claim is what serialises two helpers arriving at once, and what keeps
// a dial that will be refused from having any effect on the session's state.
// It is held only for the length of the dial.
func (r *Registry) reserve(instanceID string, parsed signedToken) (*Instance, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, burned := r.burned[parsed.Nonce]; burned {
		return nil, ErrTokenInvalid
	}
	inst, ok := r.instances[instanceID]
	if !ok || inst.isClosed() {
		return nil, ErrTokenInvalid
	}

	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.connecting {
		return nil, errors.New("jupytertunnel: another helper is already connecting to this instance")
	}
	if inst.tunnel != nil && !tunnelDead(inst.tunnel) {
		// Already connected and still carrying traffic. Refuse so a
		// helper-restart inside the job doesn't blow up an active session.
		return nil, errors.New("jupytertunnel: instance already has an active tunnel")
	}
	if inst.tunnel != nil {
		// The old tunnel is gone -- this server restarted, or the socket
		// broke -- and the helper is dialing back. Replacing it is the
		// whole point of the redial: refusing here would leave a live
		// JupyterLab permanently unreachable behind a dead session.
		_ = inst.tunnel.Close()
		inst.tunnel = nil
	}
	inst.connecting = true
	return inst, nil
}

func (i *Instance) releaseConnecting() {
	i.mu.Lock()
	i.connecting = false
	i.mu.Unlock()
}

// rollToken spends the presented token and mints the one that replaces it.
//
// Returns the new token for the caller to hand to the helper. A roller that
// reports the swap did not apply means this nonce was not the one the session
// was waiting for -- a replay, or a second helper that lost the race -- and
// the connection is refused.
func (r *Registry) rollToken(instanceID string, spent signedToken) (string, error) {
	next, nextParsed, err := mintToken(r.secret, spent.ID, r.tokenTTL)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), rollTimeout)
	defer cancel()
	ok, err := r.roller.RollNonce(ctx, instanceID, spent.Nonce[:], nextParsed.Nonce[:])
	if err != nil {
		// A storage failure is not an authentication failure, and saying
		// so matters: "invalid token" would send an operator hunting a
		// credential problem that is really a database one.
		return "", fmt.Errorf("jupytertunnel: recording the spent token: %w", err)
	}
	if !ok {
		return "", ErrTokenInvalid
	}
	return next, nil
}

// rollTimeout bounds the nonce swap. Short: it is one indexed UPDATE, and a
// helper waiting on a wedged database should be told rather than hung.
const rollTimeout = 5 * time.Second

// PendingNonce is the nonce of the token this instance is waiting for,
// which a caller persists so the session can be re-adopted after a restart.
//
// The nonce rather than the token: it is what identifies which token is
// live, and unlike the token it is useless to anyone without the signing
// secret, so a caller writing it down is not writing down a credential.
func (r *Registry) PendingNonce(instanceID string) ([]byte, bool) {
	r.mu.Lock()
	inst, ok := r.instances[instanceID]
	r.mu.Unlock()
	if !ok {
		return nil, false
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.pending == nil {
		return nil, false
	}
	nonce := make([]byte, len(inst.pending.Nonce))
	copy(nonce, inst.pending.Nonce[:])
	return nonce, true
}

// NextToken is the token this instance will accept on its next dial, or "".
func (i *Instance) NextToken() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.nextToken
}

// tunnelDead reports whether a yamux session has gone.
//
// A tunnel whose far side vanished is indistinguishable from a live one by
// inspection alone -- the struct is still there -- so this asks yamux, whose
// IsClosed flips when the underlying connection breaks or the keepalive
// fails. Getting this wrong in the safe direction (reporting a live tunnel
// dead) would let one helper displace another's working session, which is
// why it is a positive check rather than a timeout.
func tunnelDead(s *yamux.Session) bool {
	return s == nil || s.IsClosed()
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

// AdoptInstance re-registers a session this process did not create.
//
// A restarted server has the job still running, JupyterLab still up inside
// it, and a helper about to dial back -- and no memory of any of it. Adoption
// puts the instance back in the map, with no tunnel, so that dial has
// something to attach to. Everything else about the session is already
// durable: the identity came off the job ad and the credential out of the
// store.
//
// Deliberately not minting a token. The helper already holds the only one
// that will be accepted, and issuing another here would put a second live
// credential into a session whose whole design is that exactly one exists.
func (r *Registry) AdoptInstance(id, owner string, created time.Time, meta map[string]string) (*Instance, error) {
	if id == "" || owner == "" {
		return nil, errors.New("jupytertunnel: adopting an instance needs an id and an owner")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.instances[id]; ok {
		// Already known -- a second sweep, or a client that named it
		// before the sweep ran. Keeping the existing one preserves any
		// tunnel that has attached in the meantime.
		return existing, nil
	}
	inst := &Instance{
		ID:      id,
		Created: created,
		Owner:   owner,
		Meta:    copyMeta(meta),
	}
	r.instances[id] = inst
	return inst, nil
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

	// Claim the session's one connection slot BEFORE spending the token.
	//
	// Order matters since the roll gained a grace step. Rolling first
	// meant a dial that was going to be refused anyway -- a replay while
	// a healthy helper is connected -- still moved the nonce on, and the
	// connected helper's next token stopped being the one expected. A
	// replay could end a working session that way. Nothing is spent now
	// until the caller is the one that will get the tunnel.
	inst, err := r.reserve(instanceID, parsed)
	if err != nil {
		return nil, err
	}
	// Released on every path: a claim left behind would lock the session
	// out of reconnecting for the rest of the job.
	defer inst.releaseConnecting()

	var nextToken string
	if r.roller != nil {
		// Outside the registry lock: it is a database write, and holding
		// the lock across it would stall every proxied request behind one
		// dial. The claim above is what makes that safe.
		if nextToken, err = r.rollToken(instanceID, parsed); err != nil {
			return nil, err
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

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
	inst.nextToken = nextToken
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
		// Director is deprecated in favour of Rewrite, and this stays on
		// Director deliberately.
		//
		// Rewrite is not a drop-in here. ReverseProxy strips
		// X-Forwarded-For, -Host and -Proto before calling it and expects
		// SetXForwarded to put them back -- but SetXForwarded also sets
		// -Host and -Proto, which Director mode never did, and JupyterLab
		// builds URLs from those. Swapping the hook silently changes what
		// the notebook thinks its own address is.
		//
		// Worth revisiting with a test that drives a real notebook: under
		// Rewrite the upgrade type is computed and the Connection/Upgrade
		// headers re-added before the hook runs, which makes the footgun
		// described below impossible rather than merely avoided.
		//nolint:staticcheck // SA1019: see above; migrating changes forwarded headers
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
			// Dial was set to the same function alongside this one.
			// http.Transport uses DialContext when both are present, so
			// the second was never called -- it only kept a deprecated
			// field alive.
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
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
