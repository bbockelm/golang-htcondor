package jupytertunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestEndToEnd drives the full reverse-tunnel path:
//
//  1. Launch a tiny HTTP server bound to a Unix domain socket. Acts as
//     the "Jupyter" service.
//  2. Stand up a webapp-side httptest server with two routes:
//     POST /tunnel : accepts the helper's websocket and registers the
//     yamux session with our Registry.
//     ANY  /proxy/ : looks up the registered instance and forwards the
//     request through the tunnel.
//  3. Mint an instance + token, run the helper in a goroutine, wait for
//     it to connect, then issue HTTP requests against /proxy/ and verify
//     they hit the UDS service end-to-end.
//
// This is the Phase 1 acceptance test: no HTCondor, no Jupyter — just bytes
// flowing through the tunnel.
//
//nolint:gocyclo // Test is long but linear; splitting hides the protocol.
func TestEndToEnd(t *testing.T) {
	// --- Step 1: UDS-bound "Jupyter" stand-in -------------------------------

	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "u.sock")
	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = listener.Close() }()

	udsServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/echo":
				// gosec G705 (XSS) flags this because untrusted
				// fields from the request flow into the response
				// body. Test fixture: this server is reachable only
				// over an in-process UDS, never from a browser, and
				// the Content-Type is text/plain so no script
				// execution context exists. The echo behavior is
				// the entire point of the test.
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				body, _ := io.ReadAll(r.Body)
				_, _ = fmt.Fprintf(w, "uds-saw method=%s path=%s body=%q", //nolint:gosec
					r.Method, r.URL.Path, string(body))
			case "/big":
				// 1 MiB response to exercise multi-frame yamux paths.
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(http.StatusOK)
				buf := make([]byte, 4096)
				for i := range buf {
					buf[i] = byte(i)
				}
				for i := 0; i < 256; i++ {
					_, _ = w.Write(buf)
				}
			default:
				http.NotFound(w, r)
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = udsServer.Serve(listener) }()
	defer func() { _ = udsServer.Close() }()

	// --- Step 2: registry + webapp-side test server -------------------------

	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel/", func(w http.ResponseWriter, r *http.Request) {
		// Path: /tunnel/{instance_id}
		id := strings.TrimPrefix(r.URL.Path, "/tunnel/")
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade error: %v", err)
			return
		}
		inst, err := reg.AcceptTunnel(id, bearer, ws)
		if err != nil {
			t.Logf("AcceptTunnel: %v", err)
			_ = ws.Close()
			return
		}
		// Block until tunnel closes so the upgraded request stays open.
		inst.Wait()
	})
	mux.HandleFunc("/proxy/", func(w http.ResponseWriter, r *http.Request) {
		// Path: /proxy/{instance_id}/{rest...}
		rest := strings.TrimPrefix(r.URL.Path, "/proxy/")
		var id, upstream string
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			id, upstream = rest[:i], rest[i:]
		} else {
			id, upstream = rest, "/"
		}
		inst, ok := reg.Lookup(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		reg.Proxy(inst, upstream, w, r)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// --- Step 3: create instance, run helper, hammer the proxy --------------

	instID, token, err := reg.CreateInstance(CreateInstanceOptions{Owner: "tester"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}

	wsURL := strings.Replace(srv.URL, "http://", "ws://", 1) + "/tunnel/" + instID

	helperCtx, helperCancel := context.WithCancel(context.Background())
	defer helperCancel()

	var helperErr error
	helperDone := make(chan struct{})
	go func() {
		defer close(helperDone)
		helperErr = RunHelperTunnel(helperCtx, HelperConfig{
			UpstreamURL: wsURL,
			Token:       token,
			SocketPath:  sockPath,
			Logger: func(f string, args ...any) {
				t.Logf("helper: "+f, args...)
			},
		})
	}()

	// Wait for the registry to see the tunnel.
	if !waitFor(2*time.Second, func() bool {
		inst, ok := reg.Lookup(instID)
		if !ok {
			return false
		}
		inst.mu.Lock()
		defer inst.mu.Unlock()
		return inst.tunnel != nil
	}) {
		t.Fatalf("helper never registered")
	}

	ctx := context.Background()
	doGet := func(u string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		return http.DefaultClient.Do(req)
	}
	doPost := func(u, ct string, body io.Reader) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", ct)
		return http.DefaultClient.Do(req)
	}

	// (a) Simple round-trip.
	{
		resp, err := doGet(srv.URL + "/proxy/" + instID + "/echo")
		if err != nil {
			t.Fatalf("GET /echo: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("echo: status %d, body %q", resp.StatusCode, body)
		}
		got := string(body)
		want := `uds-saw method=GET path=/echo body=""`
		if got != want {
			t.Errorf("echo body:\n got %q\nwant %q", got, want)
		}
	}

	// (b) POST with body.
	{
		resp, err := doPost(srv.URL+"/proxy/"+instID+"/echo",
			"text/plain", strings.NewReader("hello, jupyter"))
		if err != nil {
			t.Fatalf("POST /echo: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), `body="hello, jupyter"`) {
			t.Errorf("echo POST: status=%d body=%s", resp.StatusCode, body)
		}
	}

	// (c) Big response (multi-frame, exercises yamux flow control).
	{
		resp, err := doGet(srv.URL + "/proxy/" + instID + "/big")
		if err != nil {
			t.Fatalf("GET /big: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("big: status %d", resp.StatusCode)
		}
		const want = 4096 * 256
		if len(body) != want {
			t.Errorf("big body length: got %d want %d", len(body), want)
		}
	}

	// (d) Concurrent requests share one tunnel.
	{
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				resp, err := doGet(srv.URL + "/proxy/" + instID + "/echo")
				if err != nil {
					errs <- err
					return
				}
				_, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != 200 {
					errs <- fmt.Errorf("worker %d: status %d", i, resp.StatusCode)
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Errorf("concurrent: %v", e)
		}
	}

	// (e) Tunnel teardown propagates: kill the helper, future proxy fails 502.
	helperCancel()
	<-helperDone
	if helperErr != nil && !errors.Is(helperErr, context.Canceled) {
		// "use of closed network connection" or yamux EOF are also fine.
		if !strings.Contains(helperErr.Error(), "closed") {
			t.Logf("helper exit error (informational): %v", helperErr)
		}
	}

	if !waitFor(2*time.Second, func() bool {
		inst, ok := reg.Lookup(instID)
		if !ok {
			return true
		}
		inst.mu.Lock()
		defer inst.mu.Unlock()
		return inst.tunnel == nil || inst.tunnel.IsClosed()
	}) {
		t.Errorf("registry did not observe tunnel close")
	}
}

// TestProxyWebSocketUpgrade is the regression test for two bugs that
// silently broke every JupyterLab kernel + terminal connection:
//
//  1. The proxy Director used to do `r.Header.Del("Connection")` to
//     "strip hop-by-hop headers httputil forgets about in older Go".
//     httputil.ReverseProxy's upgrade detection (upgradeType()) reads
//     the request's Connection header AFTER the Director runs. With
//     Connection deleted, upgradeType returns "" and ReverseProxy
//     skips the upgrade flow entirely — the request goes upstream as
//     a plain GET, the upstream's WebSocket handler sees no upgrade
//     headers and replies 400. (The visible symptom in the wild was
//     "Replacing stale connection ... 400 GET .../channels".)
//
//  2. Go's HTTP/2 ResponseWriter does not implement http.Hijacker, so
//     even with #1 fixed, an HTTPS server using the default ALPN
//     auto-negotiated HTTP/2 will fail to hijack on the upgrade path.
//     This test runs against an HTTP/1.1 httptest.Server, exercising
//     the same code path the demo's TLSNextProto={} pinning forces.
//
// If either regresses, the dial below fails with ErrBadHandshake and
// the test fails loudly.
func TestProxyWebSocketUpgrade(t *testing.T) {
	// --- Step 1: UDS-bound "Jupyter" with a websocket echo endpoint ---

	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "u.sock")
	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = listener.Close() }()

	udsUpgrader := websocket.Upgrader{
		// Helper dials with arbitrary host; accept anything.
		CheckOrigin: func(*http.Request) bool { return true },
	}
	udsServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/ws" {
				http.NotFound(w, r)
				return
			}
			// Sanity: verify the request reached us with the upgrade
			// headers intact. If the proxy Director stripped Connection
			// the request would have come in as a plain GET and the
			// Upgrade call below would error out.
			if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				http.Error(w, "missing Upgrade header (proxy stripped it?)", http.StatusBadRequest)
				return
			}
			ws, err := udsUpgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer func() { _ = ws.Close() }()
			// Echo a single text frame back.
			mt, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			_ = ws.WriteMessage(mt, append([]byte("echo:"), msg...))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = udsServer.Serve(listener) }()
	defer func() { _ = udsServer.Close() }()

	// --- Step 2: registry + webapp-side test server -------------------

	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	tunnelUpgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/tunnel/")
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		ws, err := tunnelUpgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("tunnel upgrade error: %v", err)
			return
		}
		inst, err := reg.AcceptTunnel(id, bearer, ws)
		if err != nil {
			t.Logf("AcceptTunnel: %v", err)
			_ = ws.Close()
			return
		}
		inst.Wait()
	})
	mux.HandleFunc("/proxy/", func(w http.ResponseWriter, r *http.Request) {
		// Forward the FULL incoming path so the upstream sees the same
		// URL the browser would (mirroring the production handler).
		id := strings.TrimPrefix(r.URL.Path, "/proxy/")
		if i := strings.IndexByte(id, '/'); i >= 0 {
			id = id[:i]
		}
		inst, ok := reg.Lookup(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		// upstreamPath: strip "/proxy/<id>" prefix to get what the
		// upstream UDS server should see.
		upstreamPath := strings.TrimPrefix(r.URL.Path, "/proxy/"+id)
		if upstreamPath == "" {
			upstreamPath = "/"
		}
		reg.Proxy(inst, upstreamPath, w, r)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// --- Step 3: instance + helper, then upgrade through the proxy ---

	instID, token, err := reg.CreateInstance(CreateInstanceOptions{Owner: "tester"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}

	wsTunnelURL := strings.Replace(srv.URL, "http://", "ws://", 1) + "/tunnel/" + instID

	helperCtx, helperCancel := context.WithCancel(context.Background())
	defer helperCancel()

	helperDone := make(chan struct{})
	go func() {
		defer close(helperDone)
		_ = RunHelperTunnel(helperCtx, HelperConfig{
			UpstreamURL: wsTunnelURL,
			Token:       token,
			SocketPath:  sockPath,
			Logger: func(f string, args ...any) {
				t.Logf("helper: "+f, args...)
			},
		})
	}()

	if !waitFor(2*time.Second, func() bool {
		inst, ok := reg.Lookup(instID)
		if !ok {
			return false
		}
		inst.mu.Lock()
		defer inst.mu.Unlock()
		return inst.tunnel != nil
	}) {
		t.Fatalf("helper never registered")
	}

	// Browser-side dial: WebSocket through the proxy, talking to /ws on
	// the upstream.
	proxyURL := strings.Replace(srv.URL, "http://", "ws://", 1) +
		"/proxy/" + instID + "/ws"
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	wsClient, resp, err := dialer.Dial(proxyURL, nil)
	if err != nil {
		status := -1
		if resp != nil {
			status = resp.StatusCode
			_ = resp.Body.Close()
		}
		t.Fatalf("websocket dial through proxy failed: %v (resp status %d)", err, status)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	defer func() { _ = wsClient.Close() }()

	// Echo round-trip.
	const want = "hello via proxy"
	if err := wsClient.WriteMessage(websocket.TextMessage, []byte(want)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, msg, err := wsClient.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(msg)
	if got != "echo:"+want {
		t.Errorf("ws echo: got %q want %q", got, "echo:"+want)
	}

	helperCancel()
	<-helperDone
}

// TestTokenSingleUse checks that the same token can't be redeemed twice.
func TestTokenSingleUse(t *testing.T) {
	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	id, tok, err := reg.CreateInstance(CreateInstanceOptions{Owner: "x"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Take the first one and let the registry burn the nonce, then
		// the second connection attempt should fail.
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		_, err = reg.AcceptTunnel(id, bearer, ws)
		if err != nil {
			_ = ws.Close()
			return
		}
		// Hold the connection open briefly so the test sees the second attempt fail
		// because the instance "already has a tunnel"; we want to assert that the
		// nonce-burn path is also airtight, so close it here.
		reg.CloseInstance(id)
	}))
	defer srv.Close()

	wsURL := strings.Replace(srv.URL, "http://", "ws://", 1)

	// First redemption should succeed.
	dialOnce := func() error {
		u, _ := url.Parse(wsURL)
		hdr := http.Header{}
		hdr.Set("Authorization", "Bearer "+tok)
		ws, resp, err := websocket.DefaultDialer.Dial(u.String(), hdr)
		if ws != nil {
			_ = ws.Close()
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := dialOnce(); err != nil && !errors.Is(err, websocket.ErrBadHandshake) {
		// websocket.ErrBadHandshake covers "instance already closed" race;
		// either way the first attempt did burn the nonce.
		t.Logf("first dial returned: %v", err)
	}
	// Second redemption with same token must NOT succeed in registering.
	// We can't easily inspect the websocket result, but the registry side
	// should refuse: synthesize the call directly.
	_, err = reg.AcceptTunnel(id, tok, nil)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid on replay, got %v", err)
	}
}

func waitFor(d time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fn()
}
