package jupytertunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const graceSentinel = "grace-jupyter-OK"

// tunnelHarness is a registry behind an HTTP server that refuses dials the
// way the API server does, keeps the hijacked tunnel connections so a test
// can cut them, and a "JupyterLab" on a Unix socket.
type tunnelHarness struct {
	reg  *Registry
	srv  *httptest.Server
	sock string
	dir  string

	mu       sync.Mutex
	conns    []net.Conn
	accepted []*Tunnel
}

func newTunnelHarness(t *testing.T, reg *Registry) *tunnelHarness {
	t.Helper()
	// Under /tmp: sun_path is about a hundred bytes.
	dir, err := os.MkdirTemp("/tmp", "jtg")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	h := &tunnelHarness{reg: reg, sock: filepath.Join(dir, "j.sock"), dir: dir}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", h.sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	uds := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, graceSentinel)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = uds.Serve(ln) }()
	t.Cleanup(func() { _ = uds.Close() })

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/tunnel/")
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		inst, err := reg.AcceptTunnel(id, bearer, ws)
		if err != nil {
			_ = ws.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(RefusalCloseCode(err), "refused"))
			_ = ws.Close()
			return
		}
		h.mu.Lock()
		h.accepted = append(h.accepted, inst)
		h.mu.Unlock()
		if inst.NextToken() != "" {
			_ = inst.SendNextToken()
		}
		inst.Wait()
	})
	mux.HandleFunc("/proxy/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/proxy/")
		inst, ok := reg.Lookup(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		reg.Proxy(inst, "/", w, r)
	})
	h.srv = httptest.NewUnstartedServer(mux)
	h.srv.Config.ConnState = func(c net.Conn, st http.ConnState) {
		if st == http.StateHijacked {
			h.mu.Lock()
			h.conns = append(h.conns, c)
			h.mu.Unlock()
		}
	}
	h.srv.Start()
	t.Cleanup(h.srv.Close)
	return h
}

// sever cuts every tunnel connection from the server side, the way a
// network drop does: no close frame, no goodbye.
func (h *tunnelHarness) sever() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.conns {
		_ = c.Close()
	}
	h.conns = nil
}

// dial runs the helper once with the given token and waits until the
// server has the tunnel, or the helper gives up. It returns the helper's
// exit channel and, if the dial failed, the error.
func (h *tunnelHarness) dial(t *testing.T, id, token string) (<-chan error, error) {
	t.Helper()
	tokenPath := filepath.Join(h.dir, "token-"+id)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- RunHelperTunnel(ctx, HelperConfig{
			UpstreamURL: strings.Replace(h.srv.URL, "http://", "ws://", 1) + "/tunnel/" + id,
			Token:       token,
			SocketPath:  h.sock,
			TokenPath:   tokenPath,
		})
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			if err == nil {
				err = errors.New("the tunnel closed before it was seen up")
			}
			return nil, err
		default:
		}
		if inst, ok := h.reg.Lookup(id); ok && inst.HasTunnel() {
			return done, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the dial neither connected nor failed")
	return nil, nil
}

// nextToken is the token the server handed the helper on its last
// connection.
func (h *tunnelHarness) nextToken(t *testing.T, id string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		//nolint:gosec // G304: the token file this harness told the helper to write
		if b, err := os.ReadFile(filepath.Join(h.dir, "token-"+id)); err == nil && len(b) > 0 {
			return string(b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the helper was never handed a next token")
	return ""
}

func (h *tunnelHarness) proxy(t *testing.T, id string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/proxy/"+id, nil)
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func newGraceRegistry(t *testing.T, grace time.Duration) (*Registry, *memRoller) {
	t.Helper()
	roller := newMemRoller()
	reg, err := NewRegistryWithSecret(make([]byte, 32), roller)
	if err != nil {
		t.Fatalf("NewRegistryWithSecret: %v", err)
	}
	reg.SetReconnectGrace(grace)
	return reg, roller
}

func createForDial(t *testing.T, reg *Registry, roller *memRoller) (string, string) {
	t.Helper()
	id, token, err := reg.CreateInstance(CreateInstanceOptions{Owner: "alice"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	nonce, _ := reg.PendingNonce(id)
	roller.set(id, nonce)
	return id, token
}

// A dropped tunnel is not an ended session. The instance waits, answers
// 503 rather than 404 while it does, and the helper's redial puts it back.
//
// It used to be closed the moment the tunnel dropped, so the redial found
// nothing, was refused, and the helper -- refused -- ended its job.
func TestTunnelDropWithinGraceIsReconnected(t *testing.T) {
	reg, roller := newGraceRegistry(t, 30*time.Second)
	h := newTunnelHarness(t, reg)
	id, token := createForDial(t, reg, roller)

	done, err := h.dial(t, id, token)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	if code, body := h.proxy(t, id); code != http.StatusOK || body != graceSentinel {
		t.Fatalf("before the drop: %d %q", code, body)
	}
	next := h.nextToken(t, id)

	h.sever()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the helper never saw the drop")
	}
	waitFor(5*time.Second, func() bool {
		inst, ok := reg.Lookup(id)
		return !ok || !inst.HasTunnel()
	})

	inst, ok := reg.Lookup(id)
	if !ok {
		t.Fatal("the session was closed the moment its tunnel dropped")
	}
	if !inst.Reconnecting() {
		t.Error("a session whose tunnel dropped does not report itself reconnecting")
	}
	code, body := h.proxy(t, id)
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "reconnecting") {
		t.Errorf("during the gap: %d %q, want 503 reconnecting", code, body)
	}

	if _, err := h.dial(t, id, next); err != nil {
		t.Fatalf("redial within the grace period: %v", err)
	}
	if code, body := h.proxy(t, id); code != http.StatusOK || body != graceSentinel {
		t.Errorf("after the redial: %d %q", code, body)
	}
	if inst.Reconnecting() {
		t.Error("still reports reconnecting after the helper came back")
	}
}

// Past the grace period the session is closed, as it always was, and a
// late redial is refused -- which is what tells the helper to end its job.
func TestTunnelRedialAfterGraceIsRefused(t *testing.T) {
	reg, roller := newGraceRegistry(t, 200*time.Millisecond)
	h := newTunnelHarness(t, reg)
	id, token := createForDial(t, reg, roller)

	done, err := h.dial(t, id, token)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	next := h.nextToken(t, id)
	h.sever()
	<-done

	if !waitFor(5*time.Second, func() bool { _, ok := reg.Lookup(id); return !ok }) {
		t.Fatal("the session outlived its grace period")
	}
	_, err = h.dial(t, id, next)
	if err == nil {
		t.Fatal("a redial after the grace period was accepted")
	}
	if !IsRejection(err) {
		t.Errorf("the late redial failed with %v; the helper would keep retrying a session that is gone", err)
	}
}

// The first token lives exactly as long as it was minted for.
func TestFirstDialAtTheStartGraceBoundary(t *testing.T) {
	reg, roller := newGraceRegistry(t, time.Minute)
	reg.SetStartTokenTTL(time.Hour)
	var offset atomic.Int64
	reg.now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	h := newTunnelHarness(t, reg)

	early, earlyToken := createForDial(t, reg, roller)
	late, lateToken := createForDial(t, reg, roller)

	offset.Store(int64(time.Hour - time.Minute))
	if _, err := h.dial(t, early, earlyToken); err != nil {
		t.Errorf("a first dial a minute inside the start grace was refused: %v", err)
	}

	offset.Store(int64(time.Hour + time.Minute))
	_, err := h.dial(t, late, lateToken)
	if err == nil {
		t.Fatal("a first dial a minute past the start grace was accepted")
	}
	if !IsRejection(err) {
		t.Errorf("an expired first token failed with %v, want a rejection", err)
	}
}

// Only a bad token is final. A dial refused because the old tunnel has not
// been seen to die yet is told to come back.
func TestOnlyABadTokenIsARejection(t *testing.T) {
	busy := fmt.Errorf("%w: instance already has an active tunnel", ErrBusy)
	if code := RefusalCloseCode(busy); code != websocket.CloseTryAgainLater {
		t.Errorf("busy refusal sends close code %d, want %d", code, websocket.CloseTryAgainLater)
	}
	if IsRejection(&websocket.CloseError{Code: RefusalCloseCode(busy)}) {
		t.Error("the helper treats a busy refusal as final and would end its job")
	}
	if code := RefusalCloseCode(errors.New("storage is down")); code != websocket.CloseTryAgainLater {
		t.Errorf("storage failure sends close code %d, want %d", code, websocket.CloseTryAgainLater)
	}
	if code := RefusalCloseCode(ErrTokenInvalid); code != websocket.ClosePolicyViolation {
		t.Errorf("bad token sends close code %d, want %d", code, websocket.ClosePolicyViolation)
	}
}

// The idle clock pauses while the tunnel is down and does not restart on a
// reconnect: a disconnect is not idleness, and a reconnect is not use.
func TestIdleClockPausesWhileDisconnected(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	var c IdleClock
	c.up(t0)
	c.touch(t0.Add(10 * time.Second))
	c.down(t0.Add(20 * time.Second))
	if got := c.idleFor(t0.Add(500 * time.Second)); got != 10*time.Second {
		t.Errorf("idle while disconnected = %s, want 10s: time spent down was counted", got)
	}
	c.up(t0.Add(600 * time.Second))
	if got := c.idleFor(t0.Add(605 * time.Second)); got != 15*time.Second {
		t.Errorf("idle after reconnecting = %s, want 15s: the reconnect reset the clock or the outage was counted", got)
	}
}

// A dial the server refuses is not a connection. The helper resets its
// reconnect backoff on OnConnected, and OnConnected used to fire as soon as
// the websocket and yamux were up -- before the server had looked at the
// token -- so a helper refused with "try again later" (a busy session, a
// database it could not write) redialed at the 2-second floor for the whole
// grace period.
func TestRefusedDialDoesNotCountAsConnected(t *testing.T) {
	reg, roller := newGraceRegistry(t, 30*time.Second)
	h := newTunnelHarness(t, reg)
	id, token := createForDial(t, reg, roller)

	// start runs the helper with tok and reports, through the returned
	// flag, whether it counted itself connected.
	start := func(ctx context.Context, tok string) (*atomic.Bool, <-chan error) {
		var connected atomic.Bool
		done := make(chan error, 1)
		go func() {
			done <- RunHelperTunnel(ctx, HelperConfig{
				UpstreamURL: strings.Replace(h.srv.URL, "http://", "ws://", 1) + "/tunnel/" + id,
				Token:       tok,
				SocketPath:  h.sock,
				TokenPath:   filepath.Join(h.dir, "token-"+id),
				OnConnected: func() { connected.Store(true) },
			})
		}()
		return &connected, done
	}

	// Accepted: the server sends the next token, and that counts. This
	// helper stays connected for the rest of the test.
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	connectedA, _ := start(ctxA, token)
	next := h.nextToken(t, id)
	if !waitFor(5*time.Second, connectedA.Load) {
		t.Fatal("an accepted dial never reported itself connected")
	}

	// A second dial while that tunnel is live is refused with
	// try-again-later.
	ctxB, cancelB := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelB()
	connectedB, doneB := start(ctxB, next)
	err := <-doneB
	if err == nil || IsRejection(err) {
		t.Fatalf("wanted a try-again-later refusal, got %v", err)
	}
	if connectedB.Load() {
		t.Error("a refused dial reported itself connected; the helper would reset its backoff and redial at the floor rate")
	}
}

// The in-memory roller keeps the database one's contract: roll from the
// next nonce, or once from the previous one, and nothing else.
func TestMemNoncesMatchTheStoreContract(t *testing.T) {
	m := newMemNonces()
	ctx := context.Background()
	m.set("s", []byte("a"))
	roll := func(from, to string) bool {
		ok, err := m.RollNonce(ctx, "s", []byte(from), []byte(to))
		if err != nil {
			t.Fatalf("RollNonce: %v", err)
		}
		return ok
	}
	if !roll("a", "b") {
		t.Fatal("rolling from the next nonce was refused")
	}
	if !roll("a", "c") {
		t.Error("the previous nonce was refused its one step of grace")
	}
	if roll("a", "d") {
		t.Error("the previous nonce was accepted twice")
	}
	if roll("b", "e") {
		t.Error("a nonce rolled past was accepted")
	}
	if !roll("c", "f") {
		t.Error("the current next nonce was refused")
	}
	m.forget("s")
	if roll("f", "g") {
		t.Error("a forgotten session still rolls")
	}
}

// A dial's Wait is bound to its own session. Once a redial can replace a
// dropped tunnel, the instance's tunnel is whichever dial came last; reading
// it at Wait time made a handler that got there late wait on the NEW dial,
// holding its dead request open for that connection's whole lifetime.
func TestTunnelWaitIsBoundToItsOwnDial(t *testing.T) {
	reg, roller := newGraceRegistry(t, 30*time.Second)
	h := newTunnelHarness(t, reg)
	id, token := createForDial(t, reg, roller)

	if _, err := h.dial(t, id, token); err != nil {
		t.Fatalf("first dial: %v", err)
	}
	next := h.nextToken(t, id)
	h.sever()
	waitFor(5*time.Second, func() bool {
		inst, ok := reg.Lookup(id)
		return ok && !inst.HasTunnel()
	})
	if _, err := h.dial(t, id, next); err != nil {
		t.Fatalf("redial: %v", err)
	}

	h.mu.Lock()
	tunnels := append([]*Tunnel(nil), h.accepted...)
	h.mu.Unlock()
	if len(tunnels) != 2 {
		t.Fatalf("accepted %d dials, want 2", len(tunnels))
	}
	first, second := tunnels[0], tunnels[1]

	done := make(chan struct{})
	go func() { first.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the first dial's Wait is blocked on the second dial's session")
	}
	if first.NextToken() == second.NextToken() {
		t.Error("both dials report the same next token; one was read off the instance")
	}
}
