//go:build integration

package httpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The activity stream, end to end over HTTP.
//
// The unit tests drive the transition rules by handing jobwatch.Feed
// ads built by hand, which says nothing about whether a change committed
// to a real htcondordb ever arrives in that shape. The chain under test
// here is the whole one: a write to the jobs table, the watch opcode,
// the feed's fold, the transition, the subscription, and the SSE frames
// coming back out of the handler.
//
// One link in it cannot be checked any other way. The unit tests always
// hand the feed a COMPLETE ad, because that is the convenient thing to
// write. A real SetAttribute changes one attribute -- and if the mirror's
// watch carried only the changed attribute rather than the whole ad, the
// transition logic would find no ClusterId and no JobStatus, emit
// nothing, and the ticker would sit silent while the access point
// worked. Every unit test would still pass. That is the same shape as
// the archive bug, so this test asserts the round trip rather than
// assuming it.

// authenticate puts the handler into user-header mode, which is how this
// server runs behind an authenticating proxy and the only way to reach
// the real requireAuthentication path from a test without a browser
// session. The alternative -- calling the stream loop directly -- would
// skip the authentication and scoping the handler does first, which is
// exactly the part a unit test cannot reach.
func authenticate(t *testing.T, h *Handler) {
	t.Helper()
	// On-disk signing keys are XOR-scrambled with 0xdeadbeef; write one
	// in that format so GenerateJWT can sign with it.
	raw := []byte("activity-stream-integration-test-key")
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	scrambled := make([]byte, len(raw))
	for i := range raw {
		scrambled[i] = raw[i] ^ deadbeef[i%len(deadbeef)]
	}
	keyPath := filepath.Join(t.TempDir(), "POOL")
	if err := os.WriteFile(keyPath, scrambled, 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	h.userHeader = "X-Remote-User"
	// The header is honoured only from a trusted proxy; httptest dials
	// from a loopback port that is not in any configured CIDR.
	h.userHeaderUnsafeAllowAll = true
	h.signingKeyPath = keyPath
	h.trustDomain = "test.htcondor.org"
	h.uidDomain = "test.htcondor.org"
}

// sseReader pulls parsed activity events off a live SSE response.
type sseReader struct {
	t      *testing.T
	events chan activityStreamEvent
	body   func()
}

func readActivityStream(t *testing.T, url string) *sseReader {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The handler authenticates from this header; see userHeader mode.
	req.Header.Set("X-Remote-User", "tester")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("opening the stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 512)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		t.Fatalf("stream returned %d: %s", resp.StatusCode, body[:n])
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type is %q; EventSource discards anything else", ct)
	}

	r := &sseReader{t: t, events: make(chan activityStreamEvent, 32), body: func() { _ = resp.Body.Close() }}
	go func() {
		defer close(r.events)
		sc := bufio.NewScanner(resp.Body)
		var kind string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				kind = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: ") && kind == "activity":
				var ev activityStreamEvent
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err == nil {
					r.events <- ev
				}
			}
		}
	}()
	return r
}

// next waits for one event, failing the test rather than hanging.
func (r *sseReader) next(what string) activityStreamEvent {
	r.t.Helper()
	select {
	case ev, ok := <-r.events:
		if !ok {
			r.t.Fatalf("the stream closed while waiting for %s", what)
		}
		return ev
	case <-time.After(30 * time.Second):
		r.t.Fatalf("no %s arrived within 30s", what)
		return activityStreamEvent{}
	}
}

func (r *sseReader) nothingWithin(d time.Duration) (activityStreamEvent, bool) {
	select {
	case ev := <-r.events:
		return ev, false
	case <-time.After(d):
		return activityStreamEvent{}, true
	}
}

func TestActivityStreamEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	h, feed, write := mirrorFeed(t, ctx)
	h.jobWatchFeed = feed
	authenticate(t, h)

	srv := httptest.NewServer(http.HandlerFunc(h.handleDashboardActivityStream))
	defer srv.Close()

	stream := readActivityStream(t, srv.URL+"/api/v1/dashboard/activity/stream")
	defer stream.body()

	now := time.Now().Unix()

	// 1. A job arrives. QDate has to be recent or this is a first
	//    sighting of an old job, which is deliberately silent.
	write(ctx, func(w *txWriter) {
		w.newJob("50.0", 50, 0, 1)
		w.set("50.0", "QDate", fmt.Sprintf("%d", now))
		w.set("50.0", "Cmd", `"/home/tester/analyze.sh"`)
	})
	ev := stream.next("the submission")
	if ev.Kind != "submitted" {
		t.Errorf("kind = %q, want submitted (%+v)", ev.Kind, ev)
	}
	if ev.Cluster != 50 || ev.Proc != 0 {
		t.Errorf("event identifies %d.%d, want 50.0", ev.Cluster, ev.Proc)
	}
	if ev.Owner != "tester" {
		t.Errorf("owner = %q, want tester", ev.Owner)
	}

	// 2. It starts running -- via a real SetAttribute, which is the link
	//    that only exists in the round trip. A watch event carrying just
	//    the changed attribute would produce nothing here.
	write(ctx, func(w *txWriter) {
		w.set("50.0", "JobStatus", "2")
		w.set("50.0", "RemoteHost", `"slot1@ep.example"`)
	})
	ev = stream.next("the start")
	if ev.Kind != "started" {
		t.Fatalf("kind = %q, want started -- a one-attribute update did not carry the whole ad (%+v)",
			ev.Kind, ev)
	}
	if ev.Cluster != 50 {
		t.Errorf("started event lost the job identity: %+v", ev)
	}

	// 3. It goes on hold, carrying the reason.
	write(ctx, func(w *txWriter) {
		w.set("50.0", "JobStatus", "5")
		w.set("50.0", "HoldReason", `"output transfer failed"`)
	})
	ev = stream.next("the hold")
	if ev.Kind != "held" {
		t.Errorf("kind = %q, want held (%+v)", ev.Kind, ev)
	}
	if !strings.Contains(ev.Detail, "transfer failed") {
		t.Errorf("hold event carries no reason: %q", ev.Detail)
	}

	// 4. Released, then finishes and leaves the queue. The delete
	//    carries only the key, so the outcome has to come from the ad
	//    the feed kept -- the reason this is not just a queue poll.
	write(ctx, func(w *txWriter) {
		w.set("50.0", "JobStatus", "1")
	})
	if ev = stream.next("the release"); ev.Kind != "released" {
		t.Errorf("kind = %q, want released (%+v)", ev.Kind, ev)
	}

	write(ctx, func(w *txWriter) {
		w.set("50.0", "JobStatus", "4")
		w.set("50.0", "ExitCode", "0")
	})
	if ev = stream.next("the completion"); ev.Kind != "completed" {
		t.Errorf("kind = %q, want completed (%+v)", ev.Kind, ev)
	}

	write(ctx, func(w *txWriter) {
		w.destroy("50.0")
	})
	// The job left the queue having already been recorded as completed.
	// A second completion for the same job is acceptable -- it is a real
	// transition -- but nothing else is.
	if ev, quiet := stream.nothingWithin(5 * time.Second); !quiet && ev.Kind != "completed" {
		t.Errorf("the delete produced %q, want nothing or a completion (%+v)", ev.Kind, ev)
	}
}

// The write that is not an event, over the real transport. On a busy
// access point this is the overwhelming majority of them, and it is what
// makes a stream of status changes cheap enough to leave open. Asserted
// here and not only in the unit tests because "the mirror emits one
// watch event per attribute written" is a property of the round trip.
func TestActivityStreamIgnoresAttributeChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	h, feed, write := mirrorFeed(t, ctx)
	h.jobWatchFeed = feed
	authenticate(t, h)

	srv := httptest.NewServer(http.HandlerFunc(h.handleDashboardActivityStream))
	defer srv.Close()

	// A running job, established before the stream opens so its start is
	// not one of the events counted below.
	write(ctx, func(w *txWriter) {
		w.newJob("60.0", 60, 0, 2)
		w.set("60.0", "QDate", fmt.Sprintf("%d", time.Now().Add(-6*time.Hour).Unix()))
		w.set("60.0", "JobCurrentStartDate", fmt.Sprintf("%d", time.Now().Add(-5*time.Hour).Unix()))
	})
	time.Sleep(2 * time.Second)

	stream := readActivityStream(t, srv.URL+"/api/v1/dashboard/activity/stream")
	defer stream.body()

	// Twenty usage reports: the shape of a running job's traffic.
	for i := 0; i < 20; i++ {
		write(ctx, func(w *txWriter) {
			w.set("60.0", "RemoteSysCpu", fmt.Sprintf("%d.0", i))
			w.set("60.0", "ImageSize", fmt.Sprintf("%d", 1000+i))
		})
	}

	if ev, quiet := stream.nothingWithin(6 * time.Second); !quiet {
		t.Errorf("forty attribute writes on a running job produced %+v", ev)
	}
}

// The stream carries other people's job activity when an administrator
// asks for it, so an unauthenticated caller must not get one at all.
// The end-to-end test above proves authentication WORKS; this proves it
// is REQUIRED, which is a different claim and the one that matters.
func TestActivityStreamRefusesUnauthenticated(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	h, feed, _ := mirrorFeed(t, ctx)
	h.jobWatchFeed = feed
	authenticate(t, h)

	srv := httptest.NewServer(http.HandlerFunc(h.handleDashboardActivityStream))
	defer srv.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		srv.URL+"/api/v1/dashboard/activity/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately no identity header.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unauthenticated stream request returned %d, want 401", resp.StatusCode)
	}
	// And it must not have become a stream: a 200 that happens to carry
	// an error body would still leave EventSource connected and
	// receiving whatever the handler wrote next.
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("refused request still opened an event stream (Content-Type %q)", ct)
	}
}
