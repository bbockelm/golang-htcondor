package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// Who a stream may show is the one decision here with a wrong answer
// that matters, so it is a named function rather than four lines inside
// the handler.
func TestActivityStreamScope(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested string
		isAdmin   bool
		want      string
	}{
		{"default is your own jobs", "", false, "alice"},
		{"an admin also defaults to their own", "", true, "alice"},
		{"an admin may ask for the whole access point", "false", true, ""},
		// The important one. A non-admin who sends owned_by_me=false is
		// given their own jobs, not everyone's.
		{"a non-admin asking for everything gets themselves", "false", false, "alice"},
		{"asking for your own explicitly", "true", true, "alice"},
		{"nonsense falls back to your own", "banana", true, "alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := activityStreamScope("alice", tc.requested, tc.isAdmin); got != tc.want {
				t.Errorf("scope = %q, want %q", got, tc.want)
			}
		})
	}
}

// A recorder that can flush, which is what ResponseController needs.
type flushRecorder struct{ *httptest.ResponseRecorder }

func (f flushRecorder) Flush() { f.ResponseRecorder.Flush() }

// lockedWriter is for the tests that read the response while the stream
// goroutine is still writing it. httptest.ResponseRecorder is not safe
// for that, and the race detector is right to say so.
type lockedWriter struct {
	mu   sync.Mutex
	buf  strings.Builder
	hdr  http.Header
	code int
}

func newLockedWriter() *lockedWriter { return &lockedWriter{hdr: http.Header{}} }

func (l *lockedWriter) Header() http.Header { return l.hdr }

func (l *lockedWriter) WriteHeader(code int) { l.code = code }

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedWriter) Flush() {}

func (l *lockedWriter) body() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func TestActivityEventFrameShape(t *testing.T) {
	rec := flushRecorder{httptest.NewRecorder()}
	err := writeActivityEvent(rec, http.NewResponseController(rec), jobwatch.ActivityEvent{
		Kind: jobwatch.ActivityHeld, Cluster: 42, Proc: 3,
		Owner: "alice", At: 1_700_000_000, Detail: "output transfer failed", Skipped: 2,
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	body := rec.Body.String()

	// EventSource dispatches on the event name and needs the blank line
	// to know the frame ended. Both are easy to lose in a refactor and
	// neither shows up as an error -- the browser just never fires.
	if !strings.HasPrefix(body, "event: activity\n") {
		t.Errorf("frame does not open with a named event: %q", body)
	}
	if !strings.HasSuffix(body, "\n\n") {
		t.Errorf("frame is not terminated by a blank line: %q", body)
	}

	line, ok := strings.CutPrefix(strings.TrimSuffix(strings.SplitN(body, "\n", 2)[1], "\n\n"), "data: ")
	if !ok {
		t.Fatalf("no data line in %q", body)
	}
	var got activityStreamEvent
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("data is not JSON: %v (%q)", err, line)
	}
	want := activityStreamEvent{
		Kind: "held", Cluster: 42, Proc: 3, Owner: "alice",
		At: 1_700_000_000, Detail: "output transfer failed", Skipped: 2,
	}
	if got != want {
		t.Errorf("decoded %+v, want %+v", got, want)
	}
}

// A frame must be a single SSE record. A detail carrying a newline --
// a hold reason quoting a multi-line error, say -- would otherwise split
// the frame and everything after the break would be parsed as a new
// field.
func TestDetailWithNewlinesCannotSplitTheFrame(t *testing.T) {
	rec := flushRecorder{httptest.NewRecorder()}
	if err := writeActivityEvent(rec, http.NewResponseController(rec), jobwatch.ActivityEvent{
		Kind: jobwatch.ActivityHeld, Cluster: 1, Detail: "line one\n\nline two\ndata: injected",
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	body := rec.Body.String()
	if strings.Count(body, "\n\n") != 1 || !strings.HasSuffix(body, "\n\n") {
		t.Errorf("a newline in the detail broke the frame into pieces: %q", body)
	}
	// Count FIELD lines, not occurrences of the text: the JSON payload
	// legitimately contains "data: " inside the escaped detail, and an
	// assertion that counted those would fail on a correct frame.
	fields := 0
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n\n"), "\n") {
		if strings.HasPrefix(line, "data: ") {
			fields++
		}
	}
	if fields != 1 {
		t.Errorf("the detail introduced %d data fields: %q", fields, body)
	}
}

func TestStreamActivityWritesEventsAndStops(t *testing.T) {
	rec := flushRecorder{httptest.NewRecorder()}
	events := make(chan jobwatch.ActivityEvent, 4)
	events <- jobwatch.ActivityEvent{Kind: jobwatch.ActivityStarted, Cluster: 7}
	events <- jobwatch.ActivityEvent{Kind: jobwatch.ActivityCompleted, Cluster: 7, Detail: "exit 0"}
	close(events)

	streamActivity(context.Background(), rec, http.NewResponseController(rec), events, time.Hour)

	body := rec.Body.String()
	if strings.Count(body, "event: activity") != 2 {
		t.Errorf("wrote %d frames for two events: %q", strings.Count(body, "event: activity"), body)
	}
	// A closed feed ends the response rather than hanging the request:
	// the browser reconnects, which is what EventSource is for.
}

// A disconnected browser must end the loop. Without this the handler
// holds a subscription for the life of the process, and the feed fans
// out to a socket nobody is reading.
func TestStreamActivityStopsWhenTheClientGoesAway(t *testing.T) {
	rec := newLockedWriter()
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan jobwatch.ActivityEvent)

	done := make(chan struct{})
	go func() {
		streamActivity(ctx, rec, http.NewResponseController(rec), events, time.Hour)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream outlived the request context")
	}
}

// A quiet access point produces nothing for minutes at a time, which a
// proxy cannot distinguish from a dead connection.
func TestStreamActivitySendsAHeartbeat(t *testing.T) {
	rec := newLockedWriter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan jobwatch.ActivityEvent)

	done := make(chan struct{})
	go func() {
		streamActivity(ctx, rec, http.NewResponseController(rec), events, 10*time.Millisecond)
		close(done)
	}()

	deadline := time.After(5 * time.Second)
	for {
		if strings.Contains(rec.body(), ": keepalive") {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("no heartbeat on an idle stream: %q", rec.body())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}
