package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// The event vocabulary is the one the collection-backed path
// established. A client that understands that path has to understand
// this one without being told which it is talking to.
func TestJobsWatchEventNames(t *testing.T) {
	for kind, want := range map[jobwatch.ActivityKind]string{
		jobwatch.ActivitySubmitted: "upsert",
		jobwatch.ActivityStarted:   "upsert",
		jobwatch.ActivityHeld:      "upsert",
		jobwatch.ActivityReleased:  "upsert",
		jobwatch.ActivityCompleted: "upsert",
		jobwatch.ActivityRemoved:   "delete",
	} {
		if got := jobsWatchEventName(kind); got != want {
			t.Errorf("jobsWatchEventName(%q) = %q, want %q", kind, got, want)
		}
	}
}

// An unrecognised transition must still read as a change. Silence
// would leave a client believing a stale queue, which is worse than
// telling it to look again for a reason it does not recognise.
func TestAnUnknownTransitionIsStillAChange(t *testing.T) {
	if got := jobsWatchEventName(jobwatch.ActivityKind("teleported")); got != "upsert" {
		t.Errorf("jobsWatchEventName(unknown) = %q, want upsert", got)
	}
}

func TestJobsWatchKeyIsTheUsualJobID(t *testing.T) {
	got := jobsWatchKey(jobwatch.ActivityEvent{Cluster: 11946368, Proc: 3})

	if got != "11946368.3" {
		t.Errorf("jobsWatchKey = %q, want 11946368.3", got)
	}
}

// Own jobs by default; the pool-wide stream is an explicit ask and
// only an administrator gets it. Shared with the dashboard stream so
// the two cannot drift apart.
func TestJobsWatchScopeFollowsTheSameRuleAsTheDashboard(t *testing.T) {
	if got := activityStreamScope("alice", "", false); got != "alice" {
		t.Errorf("default scope = %q, want alice", got)
	}
	if got := activityStreamScope("alice", "false", false); got != "alice" {
		t.Errorf("a non-admin asking for everything got %q, want their own jobs", got)
	}
	if got := activityStreamScope("alice", "false", true); got != "" {
		t.Errorf("an admin asking for everything got %q, want the whole access point", got)
	}
}

// A ResponseWriter a test can read while the handler is still
// writing. A plain recorder cannot: the handler holds it for the life
// of the stream, so every read is a data race.
type syncRecorder struct {
	mu     sync.Mutex
	body   strings.Builder
	header http.Header
}

func newSyncRecorder() *syncRecorder {
	return &syncRecorder{header: http.Header{}}
}

func (r *syncRecorder) Header() http.Header { return r.header }

func (r *syncRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.Write(p)
}

func (r *syncRecorder) WriteHeader(int) {}

// So http.NewResponseController can flush.
func (r *syncRecorder) Flush() {}

func (r *syncRecorder) text() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.String()
}

// waitFor polls until the stream contains `want`, or gives up.
func (r *syncRecorder) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(r.text(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waited for %q, stream held: %s", want, r.text())
}

// The endpoint has to stream, in the format the other path emits,
// from the feed that is actually running. Everything above tests a
// mapping; this tests that the mapping reaches the wire.
func TestJobsWatchStreamsFromTheMirrorFeed(t *testing.T) {
	s := warmTestServer(t)
	feed := jobwatch.NewFeed(nil)
	s.jobWatchFeed = feed

	ctx, cancel := context.WithCancel(
		htcondor.WithAuthenticatedUser(context.Background(), "alice"))
	defer cancel()

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/jobs/watch", nil)
	w := newSyncRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.streamJobsWatchFromMirror(ctx, w, req)
	}()

	// Wait until the handler has said something, which it only does
	// after subscribing. Applying before that races the subscription
	// and the events go nowhere.
	w.waitFor(t, "data:")

	// A job of alice's appearing, then starting to run.
	feed.Apply(jobwatch.WatchEvent{
		Kind:   jobwatch.WatchUpsert,
		Key:    "12.0",
		AdText: `[ ClusterId = 12; ProcId = 0; Owner = "alice"; JobStatus = 1 ]`,
	})
	feed.Apply(jobwatch.WatchEvent{
		Kind:   jobwatch.WatchUpsert,
		Key:    "12.0",
		AdText: `[ ClusterId = 12; ProcId = 0; Owner = "alice"; JobStatus = 2 ]`,
	})

	w.waitFor(t, "12.0")
	cancel()
	<-done

	body := w.text()
	if !strings.Contains(body, "event: upsert") {
		t.Errorf("no upsert frame reached the wire: %s", body)
	}
	if !strings.Contains(body, `"key":"12.0"`) {
		t.Errorf("the frame does not name the job: %s", body)
	}
	// No cursor: this feed has no resumable position, and an id frame
	// would hand the client something stale to resume from.
	if strings.Contains(body, "id: ") {
		t.Errorf("a cursor was sent for a stream that cannot resume: %s", body)
	}
}

// Another owner's job must not appear on this stream. The filter is
// inside the feed, so this is checking that the right scope was asked
// for -- the mistake would be opening a pool-wide stream and trusting
// the client not to look.
func TestJobsWatchDoesNotCarryAnotherOwnersJobs(t *testing.T) {
	s := warmTestServer(t)
	feed := jobwatch.NewFeed(nil)
	s.jobWatchFeed = feed

	ctx, cancel := context.WithCancel(
		htcondor.WithAuthenticatedUser(context.Background(), "alice"))
	defer cancel()

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/jobs/watch", nil)
	w := newSyncRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.streamJobsWatchFromMirror(ctx, w, req)
	}()
	w.waitFor(t, "data:")

	for _, status := range []int{1, 2} {
		feed.Apply(jobwatch.WatchEvent{
			Kind:   jobwatch.WatchUpsert,
			Key:    "99.0",
			AdText: fmt.Sprintf(`[ ClusterId = 99; ProcId = 0; Owner = "bob"; JobStatus = %d ]`, status),
		})
	}
	// Then one of alice's, so there is something to wait for that
	// proves the stream was live while bob's went past.
	for _, status := range []int{1, 2} {
		feed.Apply(jobwatch.WatchEvent{
			Kind:   jobwatch.WatchUpsert,
			Key:    "12.0",
			AdText: fmt.Sprintf(`[ ClusterId = 12; ProcId = 0; Owner = "alice"; JobStatus = %d ]`, status),
		})
	}

	w.waitFor(t, "12.0")
	cancel()
	<-done

	if strings.Contains(w.text(), "99.0") {
		t.Errorf("another owner's job reached this stream: %s", w.text())
	}
}
