package httpserver

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// Both watch sources hand one delivery to every watcher of a job. These
// open several watches on one job and let deliveries flow, so that under
// -race a watcher touching the shared ClassAd -- whose marshalling sorts
// its attributes in place -- is reported. Without -race they still check
// that the deliveries reach every stream.

const fanOutWatchers = 8

// watchStream is one open watch, counting the SSE events it has read.
type watchStream struct {
	snapshots atomic.Int64
	updates   atomic.Int64
}

func openWatchStreams(t *testing.T, srv *httptest.Server, path string, auth func(*http.Request), n int) []*watchStream {
	t.Helper()
	streams := make([]*watchStream, n)
	for i := range streams {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		auth(req)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("watch %d: status %d, want 200", i+1, resp.StatusCode)
		}
		ws := &watchStream{}
		streams[i] = ws
		go func() {
			sc := bufio.NewScanner(resp.Body)
			for sc.Scan() {
				switch sc.Text() {
				case "event: snapshot":
					ws.snapshots.Add(1)
				case "event: update":
					ws.updates.Add(1)
				}
			}
		}()
	}
	waitUntil(t, "every watch to send its snapshot", func() bool {
		for _, ws := range streams {
			if ws.snapshots.Load() == 0 {
				return false
			}
		}
		return true
	})
	return streams
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// The schedd poll: one query per tick, its ad broadcast to every watcher.
func TestJobWatchPollFanOutSharesNoAd(t *testing.T) {
	f := twoOwnerScheddServer(t)
	// Ticks fast enough that many broadcasts land while the watches are
	// open; at the production two seconds a short test sees none.
	f.s.jobPolls = newJobPollHub(2*time.Millisecond, testLogger(t), f.s.scheddJobQuery)
	f.s.jobPolls.queryMany = f.s.scheddJobsQuery
	srv := httptest.NewServer(f.s)
	// A cleanup, not a defer: Close waits for open connections, so it has
	// to run after the streams' own cleanups have hung them up.
	t.Cleanup(srv.Close)

	openWatchStreams(t, srv, "/api/v1/jobs/1.0/watch", f.bearer(t, "alice"), fanOutWatchers)

	start, _ := f.schedd.JobQueries()
	waitUntil(t, "100 poll ticks", func() bool {
		n, _ := f.schedd.JobQueries()
		return n-start >= 100
	})
}

// The mirror feed: one upsert, delivered to every subscriber of the job.
func TestJobWatchFeedFanOutSharesNoAd(t *testing.T) {
	f := twoOwnerScheddServer(t)
	feed := jobwatch.NewFeed(nil)
	events := make(chan jobwatch.WatchEvent)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = feed.Run(ctx, func(context.Context) (<-chan jobwatch.WatchEvent, func(), error) {
			return events, func() {}, nil
		})
	}()
	waitUntil(t, "the feed to warm", feed.Warm)
	f.s.jobWatchFeed = feed
	srv := httptest.NewServer(f.s)
	// A cleanup, not a defer: Close waits for open connections, so it has
	// to run after the streams' own cleanups have hung them up.
	t.Cleanup(srv.Close)

	streams := openWatchStreams(t, srv, "/api/v1/jobs/1.0/watch", f.bearer(t, "alice"), fanOutWatchers)

	for i := 0; i < 200; i++ {
		ev := jobwatch.WatchEvent{
			Kind: jobwatch.WatchUpsert,
			Key:  "1.0",
			AdText: fmt.Sprintf(`[ClusterId = 1; ProcId = 0; Owner = "alice"; JobStatus = %d; NumJobStarts = %d]`,
				1+i%2, i),
		}
		select {
		case events <- ev:
		case <-time.After(20 * time.Second):
			t.Fatal("the feed stopped reading")
		}
	}
	waitUntil(t, "every watch to stream an update", func() bool {
		for _, ws := range streams {
			if ws.updates.Load() == 0 {
				return false
			}
		}
		return true
	})
}
