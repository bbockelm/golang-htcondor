package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/gorilla/websocket"
)

// A timeout must be reported as a timeout. "context deadline exceeded"
// names the mechanism, not the event, and it is the failure users
// actually hit: the shell open waits on a schedd round trip and then a
// handshake with the starter, and 30 seconds of nothing looks identical
// to a hang.
func TestDescribeShellOpenErrorNamesTheTimeout(t *testing.T) {
	label, detail := describeShellOpenError(context.DeadlineExceeded)

	if !strings.Contains(label, "timed out") {
		t.Errorf("label %q does not say it timed out", label)
	}
	if !strings.Contains(detail, sshSetupTimeout.String()) {
		t.Errorf("detail does not say how long it waited: %q", detail)
	}
	// The things a reader can act on: is the job up, is the node
	// reachable. A bare error names none of them.
	for _, want := range []string{"starting up", "unreachable"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail does not mention %q: %q", want, detail)
		}
	}
}

// Anything else keeps its own error rather than being flattened into the
// timeout wording.
func TestDescribeShellOpenErrorKeepsOtherCauses(t *testing.T) {
	label, detail := describeShellOpenError(errors.New("connection refused"))

	if strings.Contains(label, "timed out") {
		t.Errorf("a non-timeout was labelled a timeout: %q", label)
	}
	if !strings.Contains(detail, "connection refused") {
		t.Errorf("the underlying error was dropped: %q", detail)
	}
}

// A non-WebSocket caller is refused immediately.
//
// It used to run the whole setup first -- up to 30 seconds of opening a
// shell on the execute node -- and only then discover it could not
// upgrade. Nothing was ever going to consume that shell.
func TestJobSSHRejectsNonWebSocketWithoutDoingTheWork(t *testing.T) {
	s := sshFailureTestServer(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs/1.0/ssh", nil)
	// Authenticated on purpose. Without a token this is refused at the
	// door with a 401 and never reaches the check under test, so the
	// assertions below would hold no matter what this handler did.
	req.Header.Set("Authorization", "Bearer "+createTestJWTToken(3600))
	w := httptest.NewRecorder()

	start := time.Now()
	s.handleJobSSH(w, req)
	elapsed := time.Since(start)

	if w.Code != http.StatusUpgradeRequired {
		t.Fatalf("status %d, want 426: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "WebSocket") {
		t.Errorf("the refusal does not say what the endpoint wants: %s", w.Body.String())
	}
	if elapsed > 5*time.Second {
		t.Errorf("took %s to refuse a non-WebSocket request; it should not do the setup work first", elapsed)
	}
}

// The point of the whole change: a setup failure has to arrive somewhere
// the page can read it.
//
// The server used to write a 502 with a real message before upgrading,
// which reads well in a log and is invisible to a browser -- a failed
// WebSocket handshake gives the page an Event with no status and no
// body. So the failure must come over an established socket instead:
// first an error frame carrying the full text, then a close whose reason
// carries a short label.
func TestFailSSHSetupDeliversTheReasonOverTheSocket(t *testing.T) {
	s := sshFailureTestServer(t)

	const label = "timed out"
	const detail = "Timed out after 30s opening a shell on the execute node."

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		s.failSSHSetup(conn, label, detail)
	}))
	defer srv.Close()

	client, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer func() { _ = client.Close() }()
	if resp != nil {
		_ = resp.Body.Close()
	}

	// Frame one: the full explanation.
	_, data, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("no error frame arrived: %v", err)
	}
	var frame wsControlMsg
	if err := json.Unmarshal(data, &frame); err != nil {
		t.Fatalf("error frame is not JSON (%v): %s", err, data)
	}
	if frame.Type != "error" {
		t.Errorf("frame type = %q, want \"error\"", frame.Type)
	}
	if frame.Message != detail {
		t.Errorf("message = %q, want the full detail %q", frame.Message, detail)
	}

	// Frame two: a close the page can also read, carrying the label.
	_, _, err = client.ReadMessage()
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) {
		t.Fatalf("expected a close frame, got %v", err)
	}
	if !strings.Contains(closeErr.Text, label) {
		t.Errorf("close reason = %q, want it to carry %q", closeErr.Text, label)
	}
}

func sshFailureTestServer(t *testing.T) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stdout"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	s, err := NewServer(Config{
		Logger:       logger,
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		OAuth2DBPath: t.TempDir() + "/oauth2.db",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	return s
}
