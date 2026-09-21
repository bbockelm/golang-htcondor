package httpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
	"github.com/bbockelm/golang-htcondor/webapi/watchpoll"
)

// watchShareHandler builds a Handler wired to a real watch store. No
// evaluator: jobwatch.Await tolerates a nil one, and these tests are
// about what the endpoint does with what the store holds, not about the
// sweep that puts it there.
func watchShareHandler(t *testing.T) (*Handler, *jobwatch.Store) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "POOL")
	if err := os.WriteFile(keyPath, []byte("test pool signing key"), 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	key, err := shareurl.KeyFromSigningKeyFile(keyPath)
	if err != nil {
		t.Fatalf("derive share key: %v", err)
	}
	signer, err := shareurl.NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	db, err := appdb.Open(filepath.Join(t.TempDir(), "watch.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("appdb.Migrate: %v", err)
	}
	store := jobwatch.NewStore(db)
	return &Handler{
		logger:              testLogger(t),
		shareSigner:         signer,
		signingKeyPath:      keyPath,
		uidDomain:           "example.org",
		trustDomain:         "example.org",
		jobWatch:            store,
		watchHeartbeatEvery: 20 * time.Millisecond,
	}, store
}

// registerWatch registers alice's "done" watch over cluster 42. The
// owner is fixed because these tests vary the TOKEN's owner, not the
// watch's -- see TestSharedWatchWillNotReadAnotherOwnersWatch.
func registerWatch(t *testing.T, store *jobwatch.Store) *jobwatch.Watch {
	t.Helper()
	w, err := jobwatch.New("alice", "done-42", "ClusterId == 42", jobwatch.EventDone, "", jobwatch.ModeAll)
	if err != nil {
		t.Fatalf("jobwatch.New: %v", err)
	}
	w, err = store.Register(context.Background(), w, time.Hour)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return w
}

func watchToken(t *testing.T, h *Handler, owner, watchID string, exp time.Time) string {
	t.Helper()
	tok, err := h.signShareToken(shareurl.Payload{
		Owner: owner, Exp: exp.Unix(), Kind: shareurl.KindWatch, Watch: watchID,
	})
	if err != nil {
		t.Fatalf("signShareToken: %v", err)
	}
	return tok
}

func pollWatch(t *testing.T, h *Handler, tok string, waitSeconds int) watchpoll.Answer {
	t.Helper()
	url := "/api/v1/share/watch?t=" + tok + "&wait=" + itoaTest(waitSeconds)
	w := httptest.NewRecorder()
	h.handleSharedWatch(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, url, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("poll returned %d: %s", w.Code, w.Body.String())
	}
	var a watchpoll.Answer
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
		t.Fatalf("decoding the answer: %v (body %s)", err, w.Body.String())
	}
	return a
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A watch that has already fired answers on the first pass without
// blocking: an answer that exists must not be withheld for the length of
// the wait.
func TestSharedWatchAnswersAFiredWatchImmediately(t *testing.T) {
	h, store := watchShareHandler(t)
	w := registerWatch(t, store)
	if err := store.Fire(context.Background(), w.ID, jobwatch.Outcome{
		Fires: true, Satisfied: 2,
		Matched: []jobwatch.JobRef{{JobID: jobwatch.JobID{Cluster: 42, Proc: 0}}},
	}, time.Now()); err != nil {
		t.Fatalf("Fire: %v", err)
	}

	start := time.Now()
	a := pollWatch(t, h, watchToken(t, h, "alice", w.ID, time.Now().Add(time.Hour)), 30)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("a fired watch blocked for %v; it should answer at once", elapsed)
	}
	if a.State != watchpoll.StateFired || a.PollAgain {
		t.Fatalf("state=%q poll_again=%v, want fired and no further polling", a.State, a.PollAgain)
	}
	if a.WatchID != w.ID || a.MatchedTotal != 2 || len(a.Matched) != 1 {
		t.Fatalf("answer did not carry the outcome: %+v", a)
	}
}

// A watch still waiting blocks for the whole wait and then says so. The
// elapsed time is what tells a poller its wait was honoured rather than
// short-circuited.
func TestSharedWatchBlocksThenReportsWaiting(t *testing.T) {
	h, store := watchShareHandler(t)
	w := registerWatch(t, store)

	start := time.Now()
	a := pollWatch(t, h, watchToken(t, h, "alice", w.ID, time.Now().Add(time.Hour)), 1)
	elapsed := time.Since(start)
	if elapsed < time.Second {
		t.Fatalf("returned after %v; the 1s wait was not honoured", elapsed)
	}
	if a.State != watchpoll.StateWaiting || !a.PollAgain {
		t.Fatalf("state=%q poll_again=%v, want waiting and poll again", a.State, a.PollAgain)
	}
	if a.WaitedSeconds < 1 {
		t.Fatalf("waited_seconds=%d after blocking %v; the caller cannot see what it paid",
			a.WaitedSeconds, elapsed)
	}
}

// The whole point of a long poll: a watch that fires DURING the wait is
// reported by that call, not by the next one.
func TestSharedWatchPicksUpAFiringMidWait(t *testing.T) {
	h, store := watchShareHandler(t)
	w := registerWatch(t, store)

	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = store.Fire(context.Background(), w.ID,
			jobwatch.Outcome{Fires: true, Satisfied: 1}, time.Now())
	}()

	start := time.Now()
	a := pollWatch(t, h, watchToken(t, h, "alice", w.ID, time.Now().Add(time.Hour)), 30)
	elapsed := time.Since(start)
	if a.State != watchpoll.StateFired {
		t.Fatalf("state=%q after %v, want fired", a.State, elapsed)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("took %v to notice a firing; the wait is not re-evaluating", elapsed)
	}
}

// A watch that is gone is a FINAL answer. A poller told to try again
// would hold a dead URL forever.
func TestSharedWatchReportsAMissingWatchAsGone(t *testing.T) {
	h, _ := watchShareHandler(t)
	a := pollWatch(t, h, watchToken(t, h, "alice", "no-such-watch", time.Now().Add(time.Hour)), 30)
	if a.State != watchpoll.StateGone {
		t.Fatalf("state=%q, want gone", a.State)
	}
	if a.PollAgain {
		t.Fatal("a gone watch told the caller to poll again; that is an endless loop on a dead URL")
	}
}

// The token is scoped to one owner, and a watch belonging to somebody
// else must be indistinguishable from one that does not exist.
func TestSharedWatchWillNotReadAnotherOwnersWatch(t *testing.T) {
	h, store := watchShareHandler(t)
	w := registerWatch(t, store)

	a := pollWatch(t, h, watchToken(t, h, "mallory", w.ID, time.Now().Add(time.Hour)), 1)
	if a.State != watchpoll.StateGone {
		t.Fatalf("state=%q for another owner's watch, want gone", a.State)
	}
	if a.Label != "" || a.MatchedTotal != 0 {
		t.Fatalf("leaked another owner's watch detail: %+v", a)
	}
}

// Kinds must not be interchangeable: an upload URL redeemed here would
// turn a write capability into a read of somebody's watches.
func TestSharedWatchRejectsOtherKinds(t *testing.T) {
	h, _ := watchShareHandler(t)
	for _, kind := range []shareurl.Kind{shareurl.KindInput, shareurl.KindOutput} {
		tok, err := h.signShareToken(shareurl.Payload{
			Cluster: 42, Proc: 0, Owner: "alice",
			Exp: time.Now().Add(time.Hour).Unix(), Kind: kind,
		})
		if err != nil {
			t.Fatalf("signShareToken: %v", err)
		}
		w := httptest.NewRecorder()
		h.handleSharedWatch(w, httptest.NewRequestWithContext(context.Background(),
			http.MethodGet, "/api/v1/share/watch?t="+tok, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("kind %q was accepted at the watch endpoint: %d", kind, w.Code)
		}
	}
}

func TestSharedWatchRejectsBadTokens(t *testing.T) {
	h, store := watchShareHandler(t)
	w := registerWatch(t, store)
	good := watchToken(t, h, "alice", w.ID, time.Now().Add(time.Hour))

	expired := watchToken(t, h, "alice", w.ID, time.Now().Add(-time.Minute))
	tampered := []byte(good)
	tampered[0] ^= 0x01

	for name, tok := range map[string]string{
		"expired":  expired,
		"tampered": string(tampered),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.handleSharedWatch(rec, httptest.NewRequestWithContext(context.Background(),
				http.MethodGet, "/api/v1/share/watch?t="+tok, nil))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", rec.Code)
			}
		})
	}

	rec := httptest.NewRecorder()
	h.handleSharedWatch(rec, httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/api/v1/share/watch", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a tokenless poll got %d, want 400", rec.Code)
	}
}

// The streaming form must emit liveness while it waits and finish with
// the answer. The heartbeat is what lets a poller tell "still waiting"
// from "the server died".
func TestSharedWatchStreamsHeartbeatsThenTheAnswer(t *testing.T) {
	h, store := watchShareHandler(t)
	w := registerWatch(t, store)

	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = store.Fire(context.Background(), w.ID,
			jobwatch.Outcome{Fires: true, Satisfied: 1}, time.Now())
	}()

	tok := watchToken(t, h, "alice", w.ID, time.Now().Add(time.Hour))
	rec := httptest.NewRecorder()
	h.handleSharedWatch(rec, httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/api/v1/share/watch?t="+tok+"&wait=30&stream=sse", nil))

	events := parseSSE(t, rec.Body.String())
	if len(events) == 0 {
		t.Fatal("the stream produced no frames")
	}
	var heartbeats int
	for _, e := range events[:len(events)-1] {
		if e.name != "heartbeat" {
			t.Fatalf("frame before the answer was %q, want heartbeat", e.name)
		}
		heartbeats++
		// A heartbeat must stay small: it is emitted repeatedly and is
		// read by something paying per token for it.
		if len(e.data) > 64 {
			t.Fatalf("heartbeat frame is %d bytes: %s", len(e.data), e.data)
		}
	}
	if heartbeats == 0 {
		t.Fatal("no heartbeat arrived before the answer; a slow wait would look like a dead connection")
	}

	last := events[len(events)-1]
	if last.name != watchpoll.StateFired {
		t.Fatalf("terminal frame is %q, want %q", last.name, watchpoll.StateFired)
	}
	var a watchpoll.Answer
	if err := json.Unmarshal([]byte(last.data), &a); err != nil {
		t.Fatalf("decoding the terminal frame: %v", err)
	}
	if a.State != watchpoll.StateFired || a.PollAgain {
		t.Fatalf("terminal answer %+v", a)
	}
	// The reason waited_seconds is on the answer at all: without it a
	// reader has to count heartbeats to learn how long it waited.
	if a.WaitedSeconds < 0 {
		t.Fatalf("waited_seconds=%d", a.WaitedSeconds)
	}
}

type sseEvent struct{ name, data string }

func parseSSE(t *testing.T, body string) []sseEvent {
	t.Helper()
	var out []sseEvent
	var cur sseEvent
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			cur.name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			cur.data = strings.TrimPrefix(line, "data: ")
		case line == "":
			if cur.name != "" {
				out = append(out, cur)
			}
			cur = sseEvent{}
		}
	}
	return out
}

// Only {id}/share is served under /api/v1/watches/. Registering and
// reading watches is MCP's; a half-REST surface that answered some watch
// questions and not others would be the more confusing thing to offer.
func TestWatchPathServesOnlyTheShareMint(t *testing.T) {
	h, _ := watchShareHandler(t)
	for _, path := range []string{
		"/api/v1/watches/",
		"/api/v1/watches/w1",
		"/api/v1/watches/w1/cancel",
		"/api/v1/watches/w1/share/extra",
		"/api/v1/watches//share",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.handleWatchPath(rec, httptest.NewRequestWithContext(context.Background(),
				http.MethodPost, path, nil))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s returned %d, want 404", path, rec.Code)
			}
		})
	}
}

// The mint refuses before it authenticates when the deployment cannot
// produce a usable URL at all, so an operator sees which piece is
// missing rather than an auth error.
func TestWatchShareRefusesWhenUnconfigured(t *testing.T) {
	h, store := watchShareHandler(t)
	w := registerWatch(t, store)
	path := "/api/v1/watches/" + w.ID + "/share"

	rec := httptest.NewRecorder()
	h.handleWatchShare(rec, httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, path, nil), w.ID)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on the mint got %d, want 405", rec.Code)
	}

	noKey, _ := watchShareHandler(t)
	noKey.signingKeyPath = ""
	rec = httptest.NewRecorder()
	noKey.handleWatchShare(rec, httptest.NewRequestWithContext(context.Background(),
		http.MethodPost, path, nil), w.ID)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("mint without a signing key got %d, want 501", rec.Code)
	}

	noWatches, _ := watchShareHandler(t)
	noWatches.jobWatch = nil
	rec = httptest.NewRecorder()
	noWatches.handleWatchShare(rec, httptest.NewRequestWithContext(context.Background(),
		http.MethodPost, path, nil), w.ID)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("mint with no watch store got %d, want 503", rec.Code)
	}

	rec = httptest.NewRecorder()
	noWatches.handleSharedWatch(rec, httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/api/v1/share/watch?t=x", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("redeem with no watch store got %d, want 503", rec.Code)
	}
}
