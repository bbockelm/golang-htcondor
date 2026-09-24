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
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// The roll is not transactional with its delivery: the server commits the
// next nonce and then hands the token over, so a helper that dies in
// between keeps a token the server has moved past. Nothing recovers it --
// re-issuing needs the authentication that just failed -- so retrying is
// a slot held for the rest of the job behind an unreachable JupyterLab.
func TestPolicyViolationIsTerminal(t *testing.T) {
	err := &websocket.CloseError{Code: websocket.ClosePolicyViolation, Text: "tunnel auth failed"}
	if !IsRejection(err) {
		t.Error("a policy-violation close must end the session, not be retried")
	}
	// Wrapped, which is how it reaches the reconnect loop.
	if !IsRejection(fmt.Errorf("helper: accept stream: %w", err)) {
		t.Error("a wrapped rejection was not recognised")
	}
}

// Everything else is the server being away, which is precisely when a
// helper should come back -- that is the whole point of reconnecting.
func TestTransientFailuresAreRetried(t *testing.T) {
	for _, err := range []error{
		nil,
		io.EOF,
		errors.New("dial tcp: connection refused"),
		&websocket.CloseError{Code: websocket.CloseGoingAway},
		&websocket.CloseError{Code: websocket.CloseNormalClosure},
		&websocket.CloseError{Code: websocket.CloseAbnormalClosure},
	} {
		if IsRejection(err) {
			t.Errorf("%v was treated as terminal; the session would not come back", err)
		}
	}
}

// An idle session must not be reconnected: dialing straight back in is
// what would make the timeout a no-op.
func TestIdleTimeoutIsNotARejection(t *testing.T) {
	if IsRejection(ErrIdleTimeout) {
		t.Error("idle timeout is its own outcome, handled separately from a rejection")
	}
	if !errors.Is(fmt.Errorf("wrapped: %w", ErrIdleTimeout), ErrIdleTimeout) {
		t.Error("a wrapped idle timeout is not recognisable")
	}
}

// The classification is only useful if RunHelperTunnel actually reports
// the idle timeout. It looks identical to a lost connection at the accept
// loop -- both are a closed session -- and a reconnect loop that cannot
// tell them apart dials straight back in, which is the timeout not
// working at all.
func TestRunHelperTunnelReportsIdleTimeout(t *testing.T) {
	// Not t.TempDir(): it embeds the test name, and this one is long
	// enough to push the socket path past the AF_UNIX limit (104 bytes on
	// macOS) -- the very failure the launch script's comments describe.
	dir, err := os.MkdirTemp("", "j")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sockPath := filepath.Join(dir, "u.sock")
	var lc net.ListenConfig
	ln, err2 := lc.Listen(context.Background(), "unix", sockPath)
	if err2 != nil {
		t.Fatalf("listen: %v", err2)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel/", func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		ws, uerr := up.Upgrade(w, r, nil)
		if uerr != nil {
			return
		}
		// "Bearer " prefix stripped, as the real handler does.
		inst, aerr := reg.AcceptTunnel(strings.TrimPrefix(r.URL.Path, "/tunnel/"),
			strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ws)
		if aerr != nil {
			t.Logf("AcceptTunnel: %v", aerr)
			_ = ws.Close()
			return
		}
		inst.Wait()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	id, token, err := reg.CreateInstance(CreateInstanceOptions{Owner: "tester"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}

	// No stream is ever opened, so the watcher fires on its own.
	err = RunHelperTunnel(context.Background(), HelperConfig{
		UpstreamURL: strings.Replace(srv.URL, "http://", "ws://", 1) + "/tunnel/" + id,
		Token:       token,
		SocketPath:  sockPath,
		IdleTimeout: 300 * time.Millisecond,
		Logger:      func(string, ...any) {},
	})
	if !errors.Is(err, ErrIdleTimeout) {
		t.Errorf("RunHelperTunnel returned %v, want ErrIdleTimeout; the reconnect loop would dial straight back in", err)
	}
}
