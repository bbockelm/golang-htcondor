package jupytertunnel

import (
	"bytes"
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

	"github.com/bbockelm/golang-htcondor/webapi/proxyscrub"
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
	// roller records which token each session accepts next. A durable one
	// is what keeps tokens single-use across a restart; without one the
	// registry keeps that record in memory (mem), which is right for a
	// registry whose secret is per-process anyway.
	roller NonceRoller
	mem    *memNonces

	// tokenTTL bounds how long a minted token stays usable. After expiry
	// the helper must request a new instance. Default 30 minutes; see
	// SetStartTokenTTL.
	tokenTTL time.Duration

	// reconnectGrace is how long a session whose tunnel dropped waits for
	// its helper to dial back before it is closed. Zero closes it at once.
	// See SetReconnectGrace.
	reconnectGrace time.Duration

	// now is the clock tokens are verified against. A seam for tests.
	now func() time.Time

	// expireRecheck is how soon an expiry that found a dial in flight looks
	// again. A seam for tests.
	expireRecheck time.Duration

	// reconnectTTL bounds the token handed to a connected helper for its
	// next dial. Zero means tokenTTL. See SetReconnectTokenTTL.
	reconnectTTL time.Duration

	// idleTTL bounds how long an instance can sit in "pending" (created but
	// helper hasn't connected back) before garbage collection. Default
	// 15 minutes.
	idleTTL time.Duration

	mu        sync.Mutex
	instances map[string]*Instance // keyed by hex(id)
}

// Instance is the registry's view of a single Jupyter session.
type Instance struct {
	ID      string // hex(id)
	Created time.Time

	// Owner is the authenticated username that created this instance.
	// Used by the proxy handler for ACL checks.
	Owner string

	mu sync.Mutex
	// meta is free-form metadata the submitter wants to remember (e.g.
	// cluster id, docker image); the registry never interprets it. Guarded
	// by mu: the creator stamps the cluster id on an instance the registry
	// has already published, while list and detail requests read it. Use
	// MetaValue and SetMeta.
	meta    map[string]string
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
	// lostAt is when the tunnel last dropped, zero while it is up or if
	// it never was. adopted marks a session this process inherited from
	// the last one, whose tunnel went with it. Either makes an instance
	// with no live tunnel one that is reconnecting rather than starting.
	lostAt  time.Time
	adopted bool

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
	// EventTunnelLost fires when a connected helper's tunnel drops. The
	// instance stays for the reconnect grace period; EventTunnelConnected
	// follows if the helper dials back, EventClosed if it does not.
	EventTunnelLost EventKind = "tunnel-lost"
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
		i.mu.Lock()
		ev.Meta = copyMeta(i.meta) // snapshot at moment of connect
		i.mu.Unlock()
	}
	i.subscribersMu.Lock()
	if i.lastEvents == nil {
		i.lastEvents = make(map[EventKind]Event)
	}
	i.lastEvents[kind] = ev
	// Connected and lost replace each other: a subscriber arriving later
	// gets the sticky events in map order, and both at once would leave
	// it guessing which is current.
	switch kind {
	case EventTunnelConnected:
		delete(i.lastEvents, EventTunnelLost)
	case EventTunnelLost:
		delete(i.lastEvents, EventTunnelConnected)
	}
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
	if roller != nil {
		r.roller, r.mem = roller, nil
	}
	return r, nil
}

func newRegistry(secret []byte) *Registry {
	mem := newMemNonces()
	return &Registry{
		secret:    secret,
		roller:    mem,
		mem:       mem,
		tokenTTL:  30 * time.Minute,
		idleTTL:   15 * time.Minute,
		now:       time.Now,
		instances: make(map[string]*Instance),

		expireRecheck: time.Second,
	}
}

// memNonces is the NonceRoller a registry with no session store uses: the
// same conditional roll, with the same one step of grace, as the database
// one, kept in memory.
//
// It replaced a set of spent nonces. That set made a token single-use but
// had no notion of a next one, so no reconnect token was ever minted: after
// a tunnel drop the helper could only redial with the token it had already
// spent, and was refused -- a deployment without an application database
// lost a session to any blip, whatever the reconnect grace period said.
type memNonces struct {
	mu   sync.Mutex
	next map[string][]byte
	prev map[string][]byte
}

func newMemNonces() *memNonces {
	return &memNonces{next: map[string][]byte{}, prev: map[string][]byte{}}
}

func (m *memNonces) set(id string, nonce []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next[id] = append([]byte(nil), nonce...)
	delete(m.prev, id)
}

func (m *memNonces) forget(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.next, id)
	delete(m.prev, id)
}

// RollNonce mirrors jupyterStore.RollNonce: from must be the next nonce, or
// the previous one while its grace is unspent; rolling from the previous one
// spends the grace.
func (m *memNonces) RollNonce(_ context.Context, id string, from, to []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, ok := m.next[id]
	if !ok {
		return false, nil
	}
	switch prev, hasPrev := m.prev[id]; {
	case bytes.Equal(next, from):
		m.prev[id] = next
	case hasPrev && bytes.Equal(prev, from):
		delete(m.prev, id)
	default:
		return false, nil
	}
	m.next[id] = append([]byte(nil), to...)
	return true, nil
}

// reserve claims the session's single connection slot for this dial.
//
// The claim is what serialises two helpers arriving at once, and what keeps
// a dial that will be refused from having any effect on the session's state.
// It is held only for the length of the dial.
func (r *Registry) reserve(instanceID string) (*Instance, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Single use is the roll's to enforce (rollToken), with the one step
	// of grace a helper needs when a drop races delivery of its next token.
	// An in-memory set of spent nonces checked here refused exactly that
	// helper: the token it still holds is the one this process just saw.
	inst, ok := r.instances[instanceID]
	if !ok || inst.isClosed() {
		return nil, ErrTokenInvalid
	}

	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.connecting {
		return nil, fmt.Errorf("%w: another helper is already connecting to this instance", ErrBusy)
	}
	if inst.tunnel != nil && !tunnelDead(inst.tunnel) {
		// Already connected and still carrying traffic. Refuse so a
		// helper-restart inside the job doesn't blow up an active session.
		//
		// Busy rather than invalid: the usual way here is a helper that
		// saw its connection drop before this side did, and it has to
		// keep trying until the keepalive notices the old tunnel is dead.
		return nil, fmt.Errorf("%w: instance already has an active tunnel", ErrBusy)
	}
	if inst.tunnel != nil {
		// The old tunnel is gone -- the socket broke -- and the helper is
		// dialing back within the grace period. Replacing it is the whole
		// point of the redial: refusing here would leave a live JupyterLab
		// permanently unreachable behind a dead session.
		//
		// Left in place until the new one is installed: the grace timer
		// closes the instance if the tunnel is still this dead one, and a
		// redial that fails part-way must not leave a session that neither
		// connects nor expires.
		_ = inst.tunnel.Close()
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
	ttl := r.reconnectTTL
	if ttl <= 0 {
		ttl = r.tokenTTL
	}
	next, nextParsed, err := mintToken(r.secret, spent.ID, ttl)
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

// SetReconnectTokenTTL sets how long the token handed to a connected helper
// stays usable. Call it before the registry is shared.
//
// That token is held until the tunnel next drops, which for a healthy session
// is the next server restart -- hours or days away, not minutes. Minted with
// the first-dial TTL it expired thirty minutes after the helper connected, so
// a restart refused every session older than that, and the helper, refused,
// ended its job. The token is still single-use: only the nonce the store holds
// is accepted, so a long lifetime does not revive a spent one. Callers pass
// the session's own horizon, past which the store has dropped the row anyway.
func (r *Registry) SetReconnectTokenTTL(d time.Duration) {
	r.reconnectTTL = d
}

// SetReconnectGrace sets how long a session whose tunnel dropped is kept
// for its helper to dial back. Zero or less closes it as soon as the tunnel
// drops. Call it before the registry is shared.
func (r *Registry) SetReconnectGrace(d time.Duration) {
	r.reconnectGrace = d
}

// SetStartTokenTTL sets how long the token a new session is created with
// stays usable: the time its job has to get through the queue and dial in.
// Call it before the registry is shared.
func (r *Registry) SetStartTokenTTL(d time.Duration) {
	if d > 0 {
		r.tokenTTL = d
	}
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

// MetaValue returns one metadata value, or "".
func (i *Instance) MetaValue(key string) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.meta[key]
}

// SetMeta records one metadata value.
func (i *Instance) SetMeta(key, value string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.meta == nil {
		i.meta = make(map[string]string)
	}
	i.meta[key] = value
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
		meta:    copyMeta(opts.Meta),
		pending: &parsed,
	}

	r.mu.Lock()
	r.instances[inst.ID] = inst
	r.mu.Unlock()
	if r.mem != nil {
		// With a durable roller the caller records this nonce (it
		// persists PendingNonce); in memory there is no caller to.
		r.mem.set(inst.ID, parsed.Nonce[:])
	}

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
//
// wasConnected says whether the session's helper had connected before. One
// that had lost its tunnel with the last process, so it is reconnecting, and
// it gets the same reconnect grace period as a tunnel that drops in this one:
// a helper that does not dial back within it is not coming. One that had not
// is still waiting for its job to start -- possibly for hours -- and is left
// to the start grace and the job's own fate.
func (r *Registry) AdoptInstance(id, owner string, created time.Time, meta map[string]string, wasConnected bool) (*Instance, error) {
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
		meta:    copyMeta(meta),
		adopted: wasConnected,
	}
	r.instances[id] = inst
	if wasConnected && r.reconnectGrace > 0 {
		r.expireAfterGrace(inst, nil)
	}
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
	return i.tunnel != nil && !i.tunnel.IsClosed()
}

// Reconnecting reports whether this session had a tunnel and is waiting for
// its helper to dial back: one dropped in this process, or one inherited
// from the last.
//
// A tunnel that is still installed but closed counts as dropped: yamux
// marks the session closed before tunnelLost runs and records lostAt, and
// in that gap the session is reconnecting, not starting.
func (i *Instance) Reconnecting() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return false
	}
	if i.tunnel != nil {
		return i.tunnel.IsClosed()
	}
	return !i.lostAt.IsZero() || i.adopted
}

// AcceptTunnel hands a websocket-upgraded connection to the registry. The
// registry verifies the bearer token, ensures the instance is still pending,
// wraps the websocket with yamux as a *client* (it will be opening streams
// later), and registers it as the live tunnel for this instance.
//
// The handler that called this function should then block until the yamux
// session reports "closed" so it can clean up the upgraded HTTP request.
// AcceptTunnel returns once the tunnel is registered; the caller waits via
// the returned Tunnel's Wait for teardown.
func (r *Registry) AcceptTunnel(instanceID, bearer string, ws *websocket.Conn) (*Tunnel, error) {
	parsed, err := parseAndVerify(r.secret, bearer, r.now())
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
	inst, err := r.reserve(instanceID)
	if err != nil {
		return nil, err
	}
	// Released on every path: a claim left behind would lock the session
	// out of reconnecting for the rest of the job.
	defer inst.releaseConnecting()

	// Outside the registry lock: it may be a database write, and holding
	// the lock across it would stall every proxied request behind one
	// dial. The claim above is what makes that safe.
	nextToken, err := r.rollToken(instanceID, parsed)
	if err != nil {
		return nil, err
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
	if inst.closed {
		// The grace period ran out while this dial was in flight.
		inst.mu.Unlock()
		_ = session.Close()
		return nil, ErrTokenInvalid
	}
	inst.tunnel = session
	inst.pending = nil
	inst.nextToken = nextToken
	inst.lostAt = time.Time{}
	inst.adopted = false
	inst.mu.Unlock()

	inst.publish(EventTunnelConnected)

	go func() {
		<-session.CloseChan()
		r.tunnelLost(inst, session)
	}()
	return &Tunnel{Instance: inst, session: session, nextToken: nextToken}, nil
}

// Tunnel is one accepted connection of an instance: the instance, plus the
// session and next token this particular dial produced.
//
// Bound to its own session rather than read off the instance. Once a drop
// can be followed by a redial, the instance's tunnel is whichever dial came
// last, and a handler that read it late -- to wait on, or to send the next
// token down -- could find a newer connection than its own: it then held its
// request open for the other dial's lifetime, or handed that dial a token.
type Tunnel struct {
	*Instance
	session   *yamux.Session
	nextToken string
}

// NextToken is the token this dial's helper should use for its next one.
func (t *Tunnel) NextToken() string { return t.nextToken }

// SendNextToken hands this dial's helper its next token. Best-effort; see
// sendNextToken.
func (t *Tunnel) SendNextToken() error { return sendNextToken(t.session, t.nextToken) }

// Wait blocks until this dial's session has closed (helper hung up, the
// connection dropped, CloseInstance called).
func (t *Tunnel) Wait() { <-t.session.CloseChan() }

// tunnelLost handles a tunnel that has dropped.
//
// A drop is not the end of a session. The job and JupyterLab are still
// running, the helper holds a token for exactly this, and it dials back
// within seconds. Closing the instance here -- as this once did -- left
// that redial nothing to attach to: it was refused, and a refused helper
// ends its job, so a network blip of any length ended the session.
//
// The instance stays, without a tunnel, for the grace period. A redial in
// that time replaces the dead tunnel (reserve); past it, the session is
// closed as before.
func (r *Registry) tunnelLost(inst *Instance, session *yamux.Session) {
	inst.mu.Lock()
	if inst.closed || inst.tunnel != session {
		// Closed deliberately, or already replaced by a redial.
		inst.mu.Unlock()
		return
	}
	grace := r.reconnectGrace
	if grace <= 0 {
		inst.mu.Unlock()
		r.CloseInstance(inst.ID)
		return
	}
	inst.lostAt = r.now()
	inst.mu.Unlock()
	inst.publish(EventTunnelLost)
	r.expireAfterGrace(inst, session)
}

// expireAfterGrace closes inst once the reconnect grace period has passed,
// unless by then a dial has replaced lost -- the tunnel that dropped, or nil
// for a session adopted from the last process, which arrives with none.
func (r *Registry) expireAfterGrace(inst *Instance, lost *yamux.Session) {
	var expire func()
	expire = func() {
		inst.mu.Lock()
		switch {
		case inst.closed || inst.tunnel != lost:
			// Closed, or the helper came back.
			inst.mu.Unlock()
			return
		case inst.connecting:
			// A redial is in flight. Let it finish rather than close the
			// session out from under it; look again shortly.
			inst.mu.Unlock()
			time.AfterFunc(r.expireRecheck, expire)
			return
		}
		inst.mu.Unlock()
		r.CloseInstance(inst.ID)
	}
	time.AfterFunc(r.reconnectGrace, expire)
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
	if r.mem != nil {
		r.mem.forget(id)
	}

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
// method are forwarded as-is, less this server's credentials, which scrub
// removes (nil removes the fixed set). WebSocket upgrades are handled by
// Go's httputil.ReverseProxy automatically (since Go 1.20+).
func (r *Registry) Proxy(inst *Instance, upstreamPath string, w http.ResponseWriter, req *http.Request, scrub *proxyscrub.Scrubber) {
	inst.mu.Lock()
	tun := inst.tunnel
	inst.mu.Unlock()
	if tun == nil || tun.IsClosed() {
		// 503, not 404 or 502: the session exists and is expected back,
		// and Retry-After says when to look again. A drop inside the
		// reconnect grace period lands here, as does a session whose
		// helper has not dialed in yet.
		msg := "JupyterLab has not connected yet"
		if inst.Reconnecting() {
			msg = "JupyterLab is reconnecting"
		}
		w.Header().Set("Retry-After", "5")
		http.Error(w, msg, http.StatusServiceUnavailable)
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
			// The caller's session and bearer stop here: whatever the
			// notebook runs could read them and act as the caller.
			scrub.Request(r)
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
		ModifyResponse: scrub.Response,
		Transport:      &yamuxRoundTripper{session: tun},
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
