package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/gorilla/websocket"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/jobssh"
)

// Job content is served on this server's origin, so a browser session with
// superuser mode armed must not be handed any of it. These tests go through
// ServeHTTP, so the routing that reaches each proxy is covered as well.

// armedAppRefusal is a phrase of the message the UI shows.
const armedAppRefusal = "Turn off superuser mode"

// enableArmableSessions switches h to session-cookie authentication with
// superuser mode configured: "admins" is the global group and alice leads
// Physics. It also builds the routes, so requests go through ServeHTTP.
func enableArmableSessions(t *testing.T, h *Handler) {
	t.Helper()
	h.userHeader = ""
	h.userHeaderUnsafeAllowAll = false
	h.sessionStore = createTestSessionStore(t, time.Hour)
	h.initSuperuserMode(HandlerConfig{
		SuperuserGroup:   "admins",
		ProjectLeadsFile: writeLeadsFile(t, "Physics alice\n"),
	}, h.logger)
	h.superuserPolicy.source = &fakeSuperUsers{users: []string{"condor@test.htcondor.org"}}
	_ = h.superuserPolicy.Refresh(context.Background())
	h.mux = http.NewServeMux()
	h.setupRoutes()
}

func newAppSession(t *testing.T, h *Handler, user string, groups ...string) string {
	t.Helper()
	sid, _, err := h.sessionStore.Create(user, groups)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// armAppSession arms sid the way the toggle does: global for a member of
// the superuser group, project scope otherwise.
func armAppSession(h *Handler, sid, user string, groups ...string) {
	armed := h.resolveImpersonationIdentity(context.Background(), user)
	armed.projectScoped = !h.globalSuperuser(groups)
	h.superuserArmed.Arm(sid, armed)
}

func serveAppRequest(h *Handler, method, path, sid string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	if sid != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec // test cookie
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// dialAppWebSocket opens a WebSocket to path on front with sid's cookie,
// echoes one message, and returns the handshake status.
func dialAppWebSocket(t *testing.T, front *httptest.Server, path, sid string) int {
	t.Helper()
	hdr := http.Header{}
	hdr.Set("Cookie", sessionCookieName+"="+sid)
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	ws, resp, err := dialer.Dial("ws"+strings.TrimPrefix(front.URL, "http")+path, hdr)
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		if resp == nil {
			t.Fatalf("WebSocket dial: %v", err)
		}
		return resp.StatusCode
	}
	defer func() { _ = ws.Close() }()
	if err := ws.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, msg, err := ws.ReadMessage(); err != nil || string(msg) != "echo:ping" {
		t.Fatalf("WebSocket echo = %q, %v", msg, err)
	}
	return resp.StatusCode
}

// jobAppTransports counts what the job proxy opens: transports into the job
// and connections through them to the app.
type jobAppTransports struct {
	opened atomic.Int32
	conn   *fakeJobConn
}

func (c *jobAppTransports) total() int32 { return c.opened.Load() + c.conn.dials.Load() }

// newArmableJobProxyHandler is a job-proxy handler whose transports land on
// a backend serving plain HTTP and a WebSocket echo.
func newArmableJobProxyHandler(t *testing.T) (*Handler, *jobAppTransports) {
	t.Helper()
	upgrader := websocket.Upgrader{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !websocket.IsWebSocketUpgrade(r) {
			_, _ = w.Write([]byte("hello from the job"))
			return
		}
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
	t.Cleanup(backend.Close)

	addr := strings.TrimPrefix(backend.URL, "http://")
	h := newProxyTestHandler(t, addr)
	h.closeJobSSHCache()
	counts := &jobAppTransports{conn: &fakeJobConn{backend: addr, done: make(chan struct{})}}
	cache, err := jobssh.NewCache(jobssh.Options{
		Dial: func(context.Context, jobssh.Key) (jobssh.Conn, error) {
			counts.opened.Add(1)
			return counts.conn, nil
		},
	})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	h.jobSSHCache = cache
	// Job 12 is bob's and running in Physics, which alice leads: the job
	// her elevation would otherwise reach.
	ad := leadJobAd(12, "bob", "Physics", 2)
	h.jobQueryOverride = func(_ context.Context, constraint string, _ *htcondor.QueryOptions) ([]*classad.ClassAd, error) {
		if evalConstraint(t, constraint, ad) {
			return []*classad.ClassAd{ad}, nil
		}
		return nil, nil
	}
	enableArmableSessions(t, h)
	return h, counts
}

// TestJobProxyRefusedWhileArmed: an armed session -- global superuser or
// project lead, on anybody's job including its own -- is refused before the
// job is reached, on plain requests and WebSocket upgrades alike. The same
// operator disarmed, and an ordinary user, are proxied.
func TestJobProxyRefusedWhileArmed(t *testing.T) {
	h, counts := newArmableJobProxyHandler(t)
	const path = "/api/v1/jobs/12.0/proxy/8080/"

	refused := func(name, sid string) {
		t.Helper()
		before := counts.total()
		w := serveAppRequest(h, http.MethodGet, path, sid)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), armedAppRefusal) {
			t.Errorf("%s: %d %s, want 403 telling them to turn off superuser mode", name, w.Code, w.Body.String())
		}
		if got := counts.total(); got != before {
			t.Errorf("%s: the job was reached (%d transports or connections) although the request was refused", name, got-before)
		}
	}
	proxied := func(name, sid string) {
		t.Helper()
		before := counts.conn.dials.Load()
		w := serveAppRequest(h, http.MethodGet, path, sid)
		if w.Code != http.StatusOK || w.Body.String() != "hello from the job" {
			t.Errorf("%s: %d %s, want the job's page", name, w.Code, w.Body.String())
		}
		if counts.conn.dials.Load() == before {
			t.Errorf("%s: answered without reaching the job", name)
		}
	}

	root := newAppSession(t, h, "root", "admins")
	armAppSession(h, root, "root", "admins")
	refused("armed superuser", root)

	lead := newAppSession(t, h, "alice")
	armAppSession(h, lead, "alice")
	refused("armed project lead", lead)

	front := httptest.NewServer(h)
	defer front.Close()
	before := counts.total()
	if code := dialAppWebSocket(t, front, path+"socket", root); code != http.StatusForbidden {
		t.Errorf("armed WebSocket upgrade answered %d, want 403", code)
	}
	if got := counts.total(); got != before {
		t.Errorf("armed WebSocket upgrade reached the job (%d)", got-before)
	}

	// The same operator, disarmed: proxied, WebSocket included.
	h.superuserArmed.Disarm(root)
	proxied("disarmed superuser", root)
	if code := dialAppWebSocket(t, front, path+"socket", root); code != http.StatusSwitchingProtocols {
		t.Errorf("disarmed WebSocket upgrade answered %d, want 101", code)
	}

	// Arming while the app is open refuses its next request: every
	// request is checked, not only the first.
	armAppSession(h, root, "root", "admins")
	refused("superuser armed after opening the app", root)

	proxied("ordinary user", newAppSession(t, h, "carol"))
}

// TestJobWarmRefusedWhileArmed: warming serves only the job proxy, so it is
// refused on the same terms and opens no transport.
func TestJobWarmRefusedWhileArmed(t *testing.T) {
	h, counts := newArmableJobProxyHandler(t)
	const path = "/api/v1/jobs/12.0/warm"

	for _, c := range []struct {
		name, user string
		groups     []string
	}{
		{"armed superuser", "root", []string{"admins"}},
		{"armed project lead", "alice", nil},
	} {
		sid := newAppSession(t, h, c.user, c.groups...)
		armAppSession(h, sid, c.user, c.groups...)
		before := counts.opened.Load()
		w := serveAppRequest(h, http.MethodPost, path, sid)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), armedAppRefusal) {
			t.Errorf("%s: %d %s, want 403", c.name, w.Code, w.Body.String())
		}
		if got := counts.opened.Load(); got != before {
			t.Errorf("%s: %d transports opened for a refused warm", c.name, got-before)
		}

		h.superuserArmed.Disarm(sid)
		w = serveAppRequest(h, http.MethodPost, path, sid)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ready":true`) {
			t.Errorf("%s disarmed: %d %s, want a warmed transport", c.name, w.Code, w.Body.String())
		}
	}
}

// TestJupyterProxyRefusedWhileArmed: the owner of a notebook is refused it
// while their session is armed, for plain requests and WebSocket upgrades,
// without the request reaching JupyterLab; disarmed it is proxied.
func TestJupyterProxyRefusedWhileArmed(t *testing.T) {
	stubJupyterHelper(t)
	schedd := newJupyterFakeSchedd()
	h := newJupyterRestartHandler(t, filepath.Join(t.TempDir(), "app.db"), schedd)
	created := createJupyterSession(t, h)
	cluster, err := strconv.Atoi(created.ClusterID)
	if err != nil {
		t.Fatalf("cluster id %q: %v", created.ClusterID, err)
	}
	helper := startJupyterTestHelper(t, created.InstanceID, schedd.token(t, cluster))
	tunnel := httptest.NewServer(http.HandlerFunc(h.handleJupyterPath))
	defer tunnel.Close()
	_ = helper.connect(t, tunnel.URL)

	enableArmableSessions(t, h)
	path := "/api/v1/jupyter/instances/" + created.InstanceID + "/proxy/lab"
	front := httptest.NewServer(h)
	defer front.Close()

	for _, c := range []struct {
		name   string
		groups []string
	}{
		{"armed superuser", []string{"admins"}},
		{"armed project lead", nil},
	} {
		sid := newAppSession(t, h, "alice", c.groups...)
		armAppSession(h, sid, "alice", c.groups...)
		before := helper.hits.Load()
		w := serveAppRequest(h, http.MethodGet, path, sid)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), armedAppRefusal) {
			t.Errorf("%s: %d %s, want 403", c.name, w.Code, w.Body.String())
		}
		if code := dialAppWebSocket(t, front, path, sid); code != http.StatusForbidden {
			t.Errorf("%s: WebSocket upgrade answered %d, want 403", c.name, code)
		}
		if got := helper.hits.Load(); got != before {
			t.Errorf("%s: %d requests reached JupyterLab although refused", c.name, got-before)
		}

		h.superuserArmed.Disarm(sid)
		w = serveAppRequest(h, http.MethodGet, path, sid)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), jupyterTestSentinel) {
			t.Errorf("%s disarmed: %d %s, want the notebook", c.name, w.Code, w.Body.String())
		}
		if helper.hits.Load() == before {
			t.Errorf("%s disarmed: answered without reaching JupyterLab", c.name)
		}
	}
}
