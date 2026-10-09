package httpserver

import (
	"context"
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

// The job carries the start grace as well as the ceiling, so it is removed
// rather than started once its token is dead, and says why.
func TestJupyterSubmitRemovesAJobThatDoesNotStartInTime(t *testing.T) {
	got := buildJupyterSubmitFile(jupyterSubmitArgs{InstanceID: "x", MaxLifetimeSec: 28800, StartGraceSec: 14400})
	for _, want := range []string{
		"((time() - QDate) > 14400)",
		"JobCurrentStartExecutingDate =?= UNDEFINED",
		"((time() - JobStartDate) > 28800)",
		" || ",
		"+PeriodicRemoveReason = ifThenElse(JobCurrentStartExecutingDate =?= UNDEFINED",
		`"JupyterLab session did not start within 4 hours"`,
		`"JupyterLab session reached its 8 hours limit"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("submit file lacks %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "periodic_remove") != 1 {
		t.Errorf("want exactly one periodic_remove (a second replaces the first):\n%s", got)
	}

	// And the handler always sends one.
	stubJupyterHelper(t)
	schedd := newJupyterFakeSchedd()
	h := newJupyterRestartHandler(t, filepath.Join(t.TempDir(), "app.db"), schedd)
	_ = createJupyterSession(t, h)
	if len(schedd.submitted) != 1 || !strings.Contains(schedd.submitted[0],
		"((time() - QDate) > "+strconv.Itoa(DefaultJupyterStartGraceSec)+")") {
		t.Errorf("create submitted no start grace:\n%v", schedd.submitted)
	}
}

// The stored session lasts as long as its job can: the time to start plus
// the time to run. Sized to the ceiling alone it expired early by however
// long the job had queued.
func TestJupyterSessionRowCoversTheStartGraceAndTheCeiling(t *testing.T) {
	stubJupyterHelper(t)
	schedd := newJupyterFakeSchedd()
	h := newJupyterRestartHandler(t, filepath.Join(t.TempDir(), "app.db"), schedd)
	h.jupyterStartGraceSec = 7200
	h.jupyterMaxLifetimeSec = 3600
	created := createJupyterSession(t, h)

	row, err := h.jupyterSessionStore().Get(context.Background(), created.InstanceID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	want := 7200*time.Second + jupyterStartDialSlack + 3600*time.Second
	if got := row.ExpiresAt.Sub(row.CreatedAt); got < want-5*time.Second || got > want+5*time.Second {
		t.Errorf("row lives %s, want start grace + dial slack + ceiling = %s", got, want)
	}

	// The token in the job lives through the start grace, not thirty
	// minutes.
	cluster, _ := strconv.Atoi(created.ClusterID)
	exp := jupyterTokenExpiry(t, schedd.token(t, cluster))
	wantExp := time.Now().Add(7200*time.Second + jupyterStartDialSlack)
	if d := exp.Sub(wantExp); d < -time.Minute || d > time.Minute {
		t.Errorf("the job's token expires at %s, want about %s", exp, wantExp)
	}
}

// Zero, negative and past-the-ceiling values never make the start grace
// absent or unbounded.
func TestJupyterStartGraceIsBounded(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, DefaultJupyterStartGraceSec},
		{-1, DefaultJupyterStartGraceSec},
		{60, 60},
		{MaxJupyterStartGraceSec + 1, MaxJupyterStartGraceSec},
	}
	for _, c := range cases {
		h := &Handler{jupyterStartGraceSec: c.in}
		if got := h.jupyterStartGrace(); got != c.want {
			t.Errorf("start grace %d -> %d, want %d", c.in, got, c.want)
		}
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

// Both session types that carry a generated periodic_remove refuse a
// caller line that would replace it.
func TestSessionLimitsCannotBeOverriddenBySubmitLines(t *testing.T) {
	const override = "periodic_remove = false"

	jr := JupyterCreateRequest{SubmitLines: override}
	jr.applyDefaults()
	if err := jr.validate(); err == nil {
		t.Error("a JupyterLab session accepted a caller periodic_remove")
	}

	ar := AppCreateRequest{Type: AppTypeCodeServer, SubmitLines: override}
	ar.applyDefaults()
	if err := ar.validate(); err == nil {
		t.Error("a VS Code session accepted a caller periodic_remove")
	}

	// Through the handler: refused before anything is submitted.
	stubJupyterHelper(t)
	schedd := newJupyterFakeSchedd()
	h := newJupyterRestartHandler(t, filepath.Join(t.TempDir(), "app.db"), schedd)
	w := jupyterRequest(t, h, http.MethodPost, "/api/v1/jupyter/instances",
		strings.NewReader(`{"submit_lines":"+PeriodicRemove = false"}`))
	if w.Code != http.StatusBadRequest {
		t.Errorf("create with an overriding submit line: %d %s, want 400", w.Code, w.Body.String())
	}
	if len(schedd.submitted) != 0 {
		t.Error("a job was submitted anyway")
	}
}

// Without an application database a session cannot survive a restart, but
// it should still survive a tunnel drop. It could not: no reconnect token
// was ever minted, so the helper's redial carried the token it had already
// spent and was refused. And the reconnect token's lifetime was set only on
// the database path, so it would have lapsed with the first-dial TTL.
func TestJupyterSessionWithoutADatabaseSurvivesATunnelDrop(t *testing.T) {
	stubJupyterHelper(t)
	schedd := newJupyterFakeSchedd()
	h := taggingHandler(t)
	h.jupyterScheddOverride = schedd
	if h.jupyterSessionStore() != nil {
		t.Fatal("the handler has a session store; this test is about running without one")
	}

	created := createJupyterSession(t, h)
	cluster, _ := strconv.Atoi(created.ClusterID)
	schedd.setStatus(cluster, 2)

	srv := newJupyterSeverableServer(t, h)
	helper := startJupyterTestHelper(t, created.InstanceID, schedd.token(t, cluster))
	next := helper.connect(t, srv.URL)
	if exp := jupyterTokenExpiry(t, next); time.Until(exp) < h.jupyterSessionTTL()-time.Minute {
		t.Errorf("the reconnect token expires in %s, want the session's %s",
			time.Until(exp).Round(time.Minute), h.jupyterSessionTTL())
	}

	srv.sever()
	helper.waitDisconnected(t)
	waitJupyterDisconnected(t, h, created.InstanceID)
	if _, err := helper.tryConnect(t, srv.URL); err != nil {
		t.Fatalf("redial after the drop was refused: %v", err)
	}
	if got := proxyThrough(t, h, created.InstanceID); !strings.Contains(got, jupyterTestSentinel) {
		t.Errorf("proxied request after the redial: %q", got)
	}
}
