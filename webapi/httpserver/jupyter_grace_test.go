package httpserver

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/jupytertunnel"
)

// jupyterSeverableServer serves a Handler and keeps the hijacked tunnel
// connections, so a test can drop them the way a network does.
type jupyterSeverableServer struct {
	*httptest.Server
	mu    sync.Mutex
	conns []net.Conn
}

func newJupyterSeverableServer(t *testing.T, h *Handler) *jupyterSeverableServer {
	t.Helper()
	s := &jupyterSeverableServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(h.handleJupyterPath))
	s.Config.ConnState = func(c net.Conn, st http.ConnState) {
		if st == http.StateHijacked {
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
		}
	}
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func (s *jupyterSeverableServer) sever() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
}

// waitJupyterDisconnected waits for the server to see the tunnel gone.
func waitJupyterDisconnected(t *testing.T, h *Handler, id string) {
	t.Helper()
	reg, _ := h.getOrCreateJupyterRegistry()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if inst, ok := reg.Lookup(id); !ok || !inst.HasTunnel() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the server never saw the tunnel drop")
}

// A drop can race the server handing the helper its next token, leaving
// the helper with only the one it connected on. That token is accepted
// once more -- in the same process, not only after a restart -- and only
// once.
//
// In-process it used to be refused regardless: the in-memory burned set
// still held it, so the database's one step of grace never got a say.
func TestJupyterRedialWithThePreviousTokenIsAcceptedOnce(t *testing.T) {
	stubJupyterHelper(t)
	schedd := newJupyterFakeSchedd()
	h := newJupyterRestartHandler(t, filepath.Join(t.TempDir(), "app.db"), schedd)
	created := createJupyterSession(t, h)
	cluster, _ := strconv.Atoi(created.ClusterID)
	schedd.setStatus(cluster, 2)
	first := schedd.token(t, cluster)

	srv := newJupyterSeverableServer(t, h)
	helper := startJupyterTestHelper(t, created.InstanceID, first)
	helper.connect(t, srv.URL)

	// The drop, and the next token lost with it: the helper still holds
	// the first one.
	srv.sever()
	helper.waitDisconnected(t)
	waitJupyterDisconnected(t, h, created.InstanceID)

	// While it is gone the session is still there, and says why it is
	// not answering.
	w := jupyterRequest(t, h, http.MethodGet, "/api/v1/jupyter/instances/"+created.InstanceID+"/proxy/lab", nil)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "reconnecting") {
		t.Errorf("proxy during the gap: %d %q, want 503 reconnecting", w.Code, w.Body.String())
	}
	if list := listJupyterSessions(t, h); len(list) != 1 || !list[0].Reconnecting {
		t.Errorf("list during the gap: %+v, want the session marked reconnecting", list)
	}

	helper.useToken(t, first)
	if _, err := helper.tryConnect(t, srv.URL); err != nil {
		t.Fatalf("redial with the previous token was refused: %v", err)
	}
	if got := proxyThrough(t, h, created.InstanceID); !strings.Contains(got, jupyterTestSentinel) {
		t.Errorf("proxied request after the redial: %q", got)
	}

	// The grace is spent.
	srv.sever()
	helper.waitDisconnected(t)
	waitJupyterDisconnected(t, h, created.InstanceID)
	helper.useToken(t, first)
	_, err := helper.tryConnect(t, srv.URL)
	if err == nil {
		t.Fatal("the previous token was accepted a second time")
	}
	if !jupytertunnel.IsRejection(err) {
		t.Errorf("the replay failed with %v, want a rejection", err)
	}
}

// An unset or out-of-range reconnect grace never makes it absent or
// unbounded.
func TestJupyterReconnectGraceIsBounded(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, DefaultJupyterReconnectGraceSec},
		{-1, DefaultJupyterReconnectGraceSec},
		{60, 60},
		{MaxJupyterReconnectGraceSec + 1, MaxJupyterReconnectGraceSec},
	}
	for _, c := range cases {
		h := &Handler{jupyterReconnectGraceSec: c.in}
		if got := h.jupyterReconnectGrace(); got != c.want {
			t.Errorf("reconnect grace %d -> %d, want %d", c.in, got, c.want)
		}
	}
}
