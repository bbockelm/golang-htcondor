package httpserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/jobssh"
)

// fakeJobConn stands in for the condor_ssh_to_job transport: every
// DialContext lands on backend, whatever address was asked for, which
// is exactly what a real forward does (the address is resolved inside
// the sandbox, not here).
type fakeJobConn struct {
	backend string
	dials   atomic.Int32
	done    chan struct{}
	once    sync.Once
}

func (f *fakeJobConn) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	f.dials.Add(1)
	var d net.Dialer
	return d.DialContext(ctx, "tcp", f.backend)
}

func (f *fakeJobConn) Wait() error { <-f.done; return nil }

func (f *fakeJobConn) Close() error {
	f.once.Do(func() { close(f.done) })
	return nil
}

// newProxyTestHandler builds a Handler authenticated by header, with
// its transport cache pre-seeded to reach backend instead of a job.
func newProxyTestHandler(t *testing.T, backend string) *Handler {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	h := &Handler{
		logger:                   logger,
		tokenCache:               NewTokenCache(),
		userHeader:               "X-Test-User",
		userHeaderUnsafeAllowAll: true,
		signingKeyPath:           writeSigningKey(t),
		trustDomain:              "test.htcondor.org",
		uidDomain:                "test.htcondor.org",
	}
	conn := &fakeJobConn{backend: backend, done: make(chan struct{})}
	cache, err := jobssh.NewCache(jobssh.Options{
		Dial: func(context.Context, jobssh.Key) (jobssh.Conn, error) { return conn, nil },
	})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	h.jobSSHCache = cache
	t.Cleanup(h.closeJobSSHCache)
	return h
}

func TestJobProxyForwardsPathAndPreservesHost(t *testing.T) {
	var gotPath, gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotHost = r.URL.Path, r.Host
		_, _ = fmt.Fprint(w, "hello from the job")
	}))
	defer backend.Close()

	h := newProxyTestHandler(t, strings.TrimPrefix(backend.URL, "http://"))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/jobs/12.0/proxy/8080/editor/index.html", nil)
	r.Header.Set("X-Test-User", "alice")
	r.Host = "api.example.com"
	w := httptest.NewRecorder()

	h.handleJobProxy(w, r, 12, 0, 8080, "/editor/index.html")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "hello from the job" {
		t.Errorf("body = %q, want the job's response", got)
	}
	if gotPath != "/editor/index.html" {
		t.Errorf("the job saw path %q, want /editor/index.html", gotPath)
	}
	// Web apps compare Host against Origin to reject cross-site
	// requests; code-server and JupyterLab both do. A rewritten Host
	// makes the app 404 its own internal API calls.
	if gotHost != "api.example.com" {
		t.Errorf("the job saw Host %q, want the browser's api.example.com", gotHost)
	}
}

// TestJobProxyReusesOneTransport is the reason the cache exists: a
// page load is many requests, and each must not cost a schedd RPC, a
// CEDAR handshake and an sshd spawn.
func TestJobProxyReusesOneTransport(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	var dialCalls atomic.Int32
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	h := &Handler{
		logger: logger, tokenCache: NewTokenCache(),
		userHeader: "X-Test-User", userHeaderUnsafeAllowAll: true,
		signingKeyPath: writeSigningKey(t),
		trustDomain:    "test.htcondor.org", uidDomain: "test.htcondor.org",
	}
	conn := &fakeJobConn{backend: strings.TrimPrefix(backend.URL, "http://"), done: make(chan struct{})}
	cache, err := jobssh.NewCache(jobssh.Options{
		Dial: func(context.Context, jobssh.Key) (jobssh.Conn, error) {
			dialCalls.Add(1)
			return conn, nil
		},
	})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	h.jobSSHCache = cache
	t.Cleanup(h.closeJobSSHCache)

	for i := 0; i < 6; i++ {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"/api/v1/jobs/12.0/proxy/8080/", nil)
		r.Header.Set("X-Test-User", "alice")
		w := httptest.NewRecorder()
		h.handleJobProxy(w, r, 12, 0, 8080, "/")
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, w.Code)
		}
	}
	if got := dialCalls.Load(); got != 1 {
		t.Errorf("opened %d transports for 6 requests, want 1", got)
	}
}

// TestJobProxyCarriesWebSocketUpgrade is the one an editor actually
// depends on: code-server loads over plain HTTP and then does all its
// work over a WebSocket. The failure it guards against is subtle --
// deleting the Connection header in the Director turns every upgrade
// into a plain GET, so the page loads and then simply never connects.
func TestJobProxyCarriesWebSocketUpgrade(t *testing.T) {
	upgrader := websocket.Upgrader{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		mt, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		_ = c.WriteMessage(mt, append([]byte("echo:"), msg...))
	}))
	defer backend.Close()

	h := newProxyTestHandler(t, strings.TrimPrefix(backend.URL, "http://"))

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Test-User", "alice")
		h.handleJobProxy(w, r, 12, 0, 8080, "/socket")
	}))
	defer front.Close()

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	ws, resp, err := dialer.Dial("ws"+strings.TrimPrefix(front.URL, "http")+"/socket", nil)
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		status := "no response"
		if resp != nil {
			status = resp.Status
		}
		t.Fatalf("WebSocket through the proxy failed: %v (%s)", err, status)
	}
	defer func() { _ = ws.Close() }()

	if err := ws.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != "echo:ping" {
		t.Errorf("got %q, want %q", msg, "echo:ping")
	}
}

func TestParseProxyPort(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"8080", 8080, false},
		{"1", 1, false},
		{"65535", 65535, false},
		{"0", 0, true},     // not a destination anything can listen on
		{"65536", 0, true}, // out of range
		{"-1", 0, true},
		{"http", 0, true},
		{"", 0, true},
	} {
		got, err := parseProxyPort(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseProxyPort(%q) = %d, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseProxyPort(%q): %v", tc.in, err)
		} else if got != tc.want {
			t.Errorf("parseProxyPort(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestJobProxyUpstreamPath(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, "/"},
		{[]string{}, "/"},
		{[]string{"index.html"}, "/index.html"},
		{[]string{"a", "b", "c"}, "/a/b/c"},
		{[]string{""}, "/"}, // trailing slash on the prefix
	} {
		if got := jobProxyUpstreamPath(tc.in); got != tc.want {
			t.Errorf("jobProxyUpstreamPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
