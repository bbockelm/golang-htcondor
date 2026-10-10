package jupytertunnel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"

	"github.com/bbockelm/golang-htcondor/webapi/proxyscrub"
)

// yamuxInstance is an Instance whose tunnel is one end of a yamux pair
// with an HTTP server on the other, standing in for the helper and the
// notebook behind it.
func yamuxInstance(t *testing.T, notebook http.Handler) *Instance {
	t.Helper()
	a, b := net.Pipe()
	client, err := yamux.Client(a, defaultYamuxConfig())
	if err != nil {
		t.Fatalf("yamux.Client: %v", err)
	}
	server, err := yamux.Server(b, defaultYamuxConfig())
	if err != nil {
		t.Fatalf("yamux.Server: %v", err)
	}
	srv := &http.Server{Handler: notebook, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(server) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = client.Close()
		_ = server.Close()
	})
	return &Instance{ID: "test", tunnel: client}
}

func setCredentialHeaders(h http.Header) {
	h.Set("Cookie", "htcondor_session=secret; other=x; idp_session=idp")
	h.Set("Authorization", "Bearer t")
	h.Set("Proxy-Authorization", "Basic dTpw")
	h.Set("X-Site-User", "alice") // the configured user header
	h.Set("X-Forwarded-User", "alice")
	h.Set("X-Forwarded-For", "192.0.2.1")
}

func checkCredentialHeaders(t *testing.T, got http.Header) {
	t.Helper()
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "X-Site-User",
		"X-Forwarded-User", "X-Forwarded-For",
	} {
		if v := got.Values(name); len(v) > 0 {
			t.Errorf("the notebook saw %s: %q", name, v)
		}
	}
	if c := got.Get("Cookie"); c != "other=x" {
		t.Errorf("the notebook saw Cookie %q, want only its own other=x", c)
	}
}

// TestProxyStripsCallerCredentials: the notebook runs whatever the user
// installs, so the session or bearer that reached the proxy must stop
// there, and the notebook must not be able to set this server's cookies.
func TestProxyStripsCallerCredentials(t *testing.T) {
	gotCh := make(chan http.Header, 1)
	inst := yamuxInstance(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCh <- r.Header.Clone()
		w.Header().Add("Set-Cookie", "htcondor_session=fixed; Path=/")
		w.Header().Add("Set-Cookie", "_xsrf=abc; Path=/")
		w.WriteHeader(http.StatusOK)
	}))
	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/lab", nil)
	setCredentialHeaders(r.Header)
	w := httptest.NewRecorder()
	reg.Proxy(inst, "/lab", w, r, proxyscrub.New("X-Site-User"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", w.Code, w.Body.String())
	}
	select {
	case got := <-gotCh:
		checkCredentialHeaders(t, got)
	default:
		t.Fatal("the request never reached the notebook")
	}
	if sc := w.Header().Values("Set-Cookie"); len(sc) != 1 || sc[0] != "_xsrf=abc; Path=/" {
		t.Errorf("browser got Set-Cookie %q, want only the notebook's _xsrf", sc)
	}
}

// TestProxyStripsCredentialsOnWebSocketUpgrade: kernels and terminals
// are WebSockets, and the handshake carries the same cookie.
func TestProxyStripsCredentialsOnWebSocketUpgrade(t *testing.T) {
	gotCh := make(chan http.Header, 1)
	upgrader := websocket.Upgrader{}
	inst := yamuxInstance(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCh <- r.Header.Clone()
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = c.Close()
	}))
	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reg.Proxy(inst, r.URL.Path, w, r, proxyscrub.New("X-Site-User"))
	}))
	defer front.Close()

	hdr := http.Header{}
	setCredentialHeaders(hdr)
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	ws, resp, err := dialer.Dial("ws"+strings.TrimPrefix(front.URL, "http")+"/api/kernels/k/channels", hdr)
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		t.Fatalf("WebSocket through the tunnel failed: %v", err)
	}
	_ = ws.Close()

	select {
	case got := <-gotCh:
		checkCredentialHeaders(t, got)
	case <-time.After(10 * time.Second):
		t.Fatal("the handshake never reached the notebook")
	}
}
