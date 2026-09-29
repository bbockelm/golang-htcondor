package httpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	backend     string
	noDeadlines bool
	dials       atomic.Int32
	done        chan struct{}
	once        sync.Once
}

func (f *fakeJobConn) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	f.dials.Add(1)
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", f.backend)
	if err != nil {
		return nil, err
	}
	if f.noDeadlines {
		return deadlinelessConn{c}, nil
	}
	return c, nil
}

// deadlinelessConn refuses deadlines the way an SSH-forwarded
// connection does: x/crypto/ssh's chanConn has nowhere to put one and
// returns an error from all three setters. Everything this proxy hands
// to http.Transport in production is one of those, so a test using a
// plain TCP socket proves less than it appears to.
type deadlinelessConn struct{ net.Conn }

func (deadlinelessConn) SetDeadline(time.Time) error {
	return errors.New("ssh: tcpChan: deadline not supported")
}
func (deadlinelessConn) SetReadDeadline(time.Time) error {
	return errors.New("ssh: tcpChan: deadline not supported")
}
func (deadlinelessConn) SetWriteDeadline(time.Time) error {
	return errors.New("ssh: tcpChan: deadline not supported")
}

// Run stands in for asking the sandbox where its scratch directory
// is. The TCP tests never need it; it exists so the fake satisfies the
// interface.
func (f *fakeJobConn) Run(context.Context, string) (string, error) {
	return "/var/lib/condor/execute/dir_42\n", nil
}

// OpenSession is unused by the proxy -- forwarding uses direct-tcpip
// channels, which are not sessions -- and exists so the fake satisfies
// the interface.
func (f *fakeJobConn) OpenSession(context.Context) (jobssh.JobSession, error) {
	return nil, errors.New("the proxy does not open sessions")
}

func (f *fakeJobConn) Wait() error { <-f.done; return nil }

func (f *fakeJobConn) Close() error {
	f.once.Do(func() { close(f.done) })
	return nil
}

// newProxyTestHandler builds a Handler authenticated by header, with
// its transport cache pre-seeded to reach backend instead of a job.
func newProxyTestHandler(t *testing.T, backend string) *Handler {
	return newProxyTestHandlerOpts(t, backend, false)
}

func newProxyTestHandlerOpts(t *testing.T, backend string, noDeadlines bool) *Handler {
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
	conn := &fakeJobConn{backend: backend, noDeadlines: noDeadlines, done: make(chan struct{})}
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

	h.handleJobProxy(w, r, 12, 0, jobProxyTarget{Port: 8080}, "/editor/index.html")

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
		h.handleJobProxy(w, r, 12, 0, jobProxyTarget{Port: 8080}, "/")
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
		h.handleJobProxy(w, r, 12, 0, jobProxyTarget{Port: 8080}, "/socket")
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

// TestJobProxyOverDeadlinelessConn is the shape of connection this
// proxy actually gets. An SSH-forwarded connection cannot carry a
// deadline, so every setter returns an error; net/http and
// gorilla/websocket must both cope, and the other tests here use plain
// TCP sockets, which do not prove it.
func TestJobProxyOverDeadlinelessConn(t *testing.T) {
	upgrader := websocket.Upgrader{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if websocket.IsWebSocketUpgrade(r) {
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
			return
		}
		_, _ = fmt.Fprint(w, "plain ok")
	}))
	defer backend.Close()

	h := newProxyTestHandlerOpts(t, strings.TrimPrefix(backend.URL, "http://"), true)

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Test-User", "alice")
		h.handleJobProxy(w, r, 12, 0, jobProxyTarget{Port: 8080}, r.URL.Path)
	}))
	defer front.Close()

	greq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, front.URL+"/plain", nil)
	resp, err := http.DefaultClient.Do(greq)
	if err != nil {
		t.Fatalf("plain GET over a deadlineless conn: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "plain ok" {
		t.Fatalf("plain GET: status %d body %q", resp.StatusCode, body)
	}

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	ws, wresp, err := dialer.Dial("ws"+strings.TrimPrefix(front.URL, "http")+"/socket", nil)
	if wresp != nil {
		defer func() { _ = wresp.Body.Close() }()
	}
	if err != nil {
		t.Fatalf("WebSocket over a deadlineless conn: %v", err)
	}
	defer func() { _ = ws.Close() }()
	if err := ws.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, msg, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != "echo:ping" {
		t.Errorf("got %q, want %q", msg, "echo:ping")
	}
}

func TestParseProxyTarget(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       []string
		want     jobProxyTarget
		wantRest []string
		wantErr  bool
	}{
		{"tcp port", []string{"8080", "a", "b"}, jobProxyTarget{Port: 8080}, []string{"a", "b"}, false},
		{"tcp port bare", []string{"8080"}, jobProxyTarget{Port: 8080}, []string{}, false},
		{"unix socket", []string{"unix", "vscode.sock", "x"}, jobProxyTarget{Socket: "vscode.sock"}, []string{"x"}, false},
		{"unix socket bare", []string{"unix", "vscode.sock"}, jobProxyTarget{Socket: "vscode.sock"}, []string{}, false},
		{"unix with no name", []string{"unix"}, jobProxyTarget{}, nil, true},
		{"nothing at all", nil, jobProxyTarget{}, nil, true},
		{"not a port", []string{"http"}, jobProxyTarget{}, nil, true},
		{"port zero", []string{"0"}, jobProxyTarget{}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, rest, err := parseProxyTarget(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseProxyTarget(%q) = %+v, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProxyTarget(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("target = %+v, want %+v", got, tc.want)
			}
			if strings.Join(rest, "/") != strings.Join(tc.wantRest, "/") {
				t.Errorf("rest = %q, want %q", rest, tc.wantRest)
			}
		})
	}
}

// TestJobProxyToUnixSocket drives the path anything we launch should
// use. A socket name with a separator in it must be refused before it
// reaches the sandbox: every other component of the path comes from
// the job, so this is the only part a request controls.
func TestJobProxyToUnixSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := dir + "/vscode.sock"
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Skipf("cannot bind a unix socket here: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// The path is recorded rather than echoed: reflecting a request
	// path into a response body is a real XSS shape, and a test that
	// writes one teaches the pattern even where it is harmless.
	var pathMu sync.Mutex
	var seenPath string
	backend := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pathMu.Lock()
			seenPath = r.URL.Path
			pathMu.Unlock()
			_, _ = io.WriteString(w, "served over a socket")
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = backend.Serve(ln) }()
	defer func() { _ = backend.Close() }()

	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	h := &Handler{
		logger: logger, tokenCache: NewTokenCache(),
		userHeader: "X-Test-User", userHeaderUnsafeAllowAll: true,
		signingKeyPath: writeSigningKey(t),
		trustDomain:    "test.htcondor.org", uidDomain: "test.htcondor.org",
	}
	conn := &unixJobConn{dir: dir, done: make(chan struct{})}
	cache, err := jobssh.NewCache(jobssh.Options{
		Dial: func(context.Context, jobssh.Key) (jobssh.Conn, error) { return conn, nil },
	})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	h.jobSSHCache = cache
	t.Cleanup(h.closeJobSSHCache)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/jobs/12.0/proxy/unix/vscode.sock/hello", nil)
	r.Header.Set("X-Test-User", "alice")
	w := httptest.NewRecorder()
	h.handleJobProxy(w, r, 12, 0, jobProxyTarget{Socket: "vscode.sock"}, "/hello")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "served over a socket" {
		t.Errorf("body = %q", got)
	}
	pathMu.Lock()
	gotPath := seenPath
	pathMu.Unlock()
	if gotPath != "/hello" {
		t.Errorf("the socket server saw path %q, want /hello", gotPath)
	}

	// A name that escapes the scratch directory must never be dialled.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/jobs/12.0/proxy/unix/x/", nil)
	r2.Header.Set("X-Test-User", "alice")
	h.handleJobProxy(w2, r2, 12, 0, jobProxyTarget{Socket: "../../../tmp/evil.sock"}, "/")
	if w2.Code != http.StatusBadGateway {
		t.Errorf("a traversing socket name gave status %d, want it refused", w2.Code)
	}
}

// unixJobConn is a transport whose sandbox scratch directory is a real
// local directory, so a real Unix socket stands in for one in a job.
type unixJobConn struct {
	dir  string
	done chan struct{}
	once sync.Once
}

func (u *unixJobConn) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
func (u *unixJobConn) Run(context.Context, string) (string, error) { return u.dir + "\n", nil }
func (u *unixJobConn) OpenSession(context.Context) (jobssh.JobSession, error) {
	return nil, errors.New("the proxy does not open sessions")
}
func (u *unixJobConn) Wait() error  { <-u.done; return nil }
func (u *unixJobConn) Close() error { u.once.Do(func() { close(u.done) }); return nil }

// TestJobProxyRedirectsToTrailingSlash pins the thing that makes a web
// app served this way work at all. Neither code-server nor
// openvscode-server can be told the path it is served under, so the
// arrangement is a prefix-stripping proxy plus relative URLs -- and a
// relative URL only resolves correctly when the browser's address ends
// in a slash. Without the redirect the page loads and every asset
// 404s, one path component too high.
func TestJobProxyRedirectsToTrailingSlash(t *testing.T) {
	h := newProxyTestHandler(t, "127.0.0.1:1") // never dialled

	for _, tc := range []struct {
		name     string
		url      string
		wantLoc  string
		wantCode int
	}{
		{
			name:     "bare prefix redirects",
			url:      "/api/v1/jobs/12.0/proxy/unix/vscode.sock",
			wantLoc:  "/api/v1/jobs/12.0/proxy/unix/vscode.sock/",
			wantCode: http.StatusTemporaryRedirect,
		},
		{
			name:     "query is carried across",
			url:      "/api/v1/jobs/12.0/proxy/unix/vscode.sock?folder=/work",
			wantLoc:  "/api/v1/jobs/12.0/proxy/unix/vscode.sock/?folder=/work",
			wantCode: http.StatusTemporaryRedirect,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.url, nil)
			r.Header.Set("X-Test-User", "alice")
			w := httptest.NewRecorder()
			h.handleJobProxy(w, r, 12, 0, jobProxyTarget{Socket: "vscode.sock"}, "/")
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantCode)
			}
			if got := w.Header().Get("Location"); got != tc.wantLoc {
				t.Errorf("Location = %q, want %q", got, tc.wantLoc)
			}
		})
	}

	// The trailing-slash form must be proxied, not redirected again --
	// a redirect to itself is an infinite loop in a browser.
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/jobs/12.0/proxy/unix/vscode.sock/", nil)
	r.Header.Set("X-Test-User", "alice")
	w := httptest.NewRecorder()
	h.handleJobProxy(w, r, 12, 0, jobProxyTarget{Socket: "vscode.sock"}, "/")
	if w.Code == http.StatusTemporaryRedirect {
		t.Fatalf("the trailing-slash form redirected to %q; that is a loop",
			w.Header().Get("Location"))
	}
}

// TestJobProxyRedirectCannotLeaveTheSite: a redirect assembled by
// appending to r.URL.Path carries whatever the request put there, and
// a path beginning "//" becomes a protocol-relative URL a browser
// follows off-site. The route prefix happens to prevent that today,
// which is the kind of guarantee that stops holding when a route
// moves, so the target is built from the job id and the parsed target
// instead.
func TestJobProxyRedirectCannotLeaveTheSite(t *testing.T) {
	h := newProxyTestHandler(t, "127.0.0.1:1") // never dialled

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/jobs/12.0/proxy/8080", nil)
	// A request that would poison a path-derived redirect.
	r.URL.Path = "//evil.example/api/v1/jobs/12.0/proxy/8080"
	r.Header.Set("X-Test-User", "alice")
	w := httptest.NewRecorder()

	h.handleJobProxy(w, r, 12, 0, jobProxyTarget{Port: 8080}, "/")

	loc := w.Header().Get("Location")
	if strings.HasPrefix(loc, "//") || strings.Contains(loc, "evil.example") {
		t.Fatalf("Location %q leaves the site", loc)
	}
	if loc != "/api/v1/jobs/12.0/proxy/8080/" {
		t.Errorf("Location = %q, want the canonical prefix", loc)
	}
}

// TestProxyTargetRejectsBadSocketNamesAtParse: the socket name is the
// only part of the socket path a request controls, so it is refused
// where it arrives rather than travelling as far as a dial.
func TestProxyTargetRejectsBadSocketNamesAtParse(t *testing.T) {
	for _, name := range []string{"..", "a b", "sock;rm", "."} {
		if _, _, err := parseProxyTarget([]string{"unix", name}); err == nil {
			t.Errorf("parseProxyTarget accepted socket name %q", name)
		}
	}
	if _, _, err := parseProxyTarget([]string{"unix", "vscode.sock"}); err != nil {
		t.Errorf("parseProxyTarget rejected a good socket name: %v", err)
	}
}
