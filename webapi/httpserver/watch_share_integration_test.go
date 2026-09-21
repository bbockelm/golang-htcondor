//go:build integration

package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
	"github.com/bbockelm/golang-htcondor/webapi/watchpoll"
)

// The watch URL, end to end, against a real htcondordb mirror.
//
// The unit tests drive the endpoint over a store they fired by hand with
// store.Fire, which says nothing about the half of the feature that has
// to work in production: that a blocked poll RUNS THE EVALUATOR, and so
// notices a job completing in the mirror while it waits. Those tests
// pass a nil evaluator -- jobwatch.Await tolerates one -- so every line
// that turns a real queue change into a fired watch was uncovered.
//
// It is also the only place the mint is exercised through real
// authentication rather than by signing a token beside it, which is the
// difference between "the signer works" and "the endpoint that hands out
// signatures works".
func TestWatchURLReportsARealFiring(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	h, feed, write := mirrorFeed(t, ctx)

	// An empty history table, so the archive read returns cleanly with
	// zero rows: this job only ever exists in the jobs table.
	dbc, closer, _, err := h.dbMirror.Client(ctx)
	if err != nil {
		t.Fatalf("connecting to the mirror: %v", err)
	}
	if err := dbc.CreateTable(ctx, "history"); err != nil {
		t.Fatalf("creating the history table: %v", err)
	}
	closer()

	// Real requireAuthentication, via the user-header mode this server
	// runs in behind an authenticating proxy.
	authenticate(t, h)
	key, err := shareurl.KeyFromSigningKeyFile(h.signingKeyPath)
	if err != nil {
		t.Fatalf("deriving the share key: %v", err)
	}
	if h.shareSigner, err = shareurl.NewSigner(key); err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	// Store and evaluator wired to the same mirror through watchSource,
	// exactly as NewHandler does, and hung on the handler so the endpoint
	// uses them.
	db, err := appdb.Open(filepath.Join(t.TempDir(), "watch.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(ctx, db); err != nil {
		t.Fatalf("appdb.Migrate: %v", err)
	}
	store := jobwatch.NewStore(db)
	h.jobWatch = store
	h.jobWatchEval = jobwatch.NewEvaluator(store, watchSource{h: h, feed: feed},
		func(msg string, args ...any) { t.Logf(msg+" %v", args...) })

	w, err := jobwatch.New("tester", "done-9002", "ClusterId == 9002", jobwatch.EventDone, "", jobwatch.ModeAll)
	if err != nil {
		t.Fatalf("jobwatch.New: %v", err)
	}
	if w, err = store.Register(ctx, w, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Mint through the endpoint, as an agent would.
	url := mintWatchURL(t, h, w.ID)

	// The job is still running when the poll starts, so the first pass
	// finds nothing: what this test needs to catch is the poll noticing
	// the completion WITHOUT being called again.
	write(ctx, func(tx *txWriter) { tx.newJob("9002.0", 9002, 0, 2) })

	answers := make(chan watchpoll.Answer, 1)
	go func() { answers <- pollWatchURL(t, h, url, 90) }()

	// Let the poll block through at least one fruitless pass, so a later
	// "fired" cannot be the first read racing the write.
	time.Sleep(3 * time.Second)
	write(ctx, func(tx *txWriter) {
		tx.set("9002.0", "JobStatus", "4")
		tx.set("9002.0", "ExitCode", "0")
	})

	select {
	case a := <-answers:
		if a.State != watchpoll.StateFired {
			t.Fatalf("poll answered %q after the job completed in the mirror; "+
				"the blocked call is not evaluating watches (answer %+v)", a.State, a)
		}
		if a.PollAgain {
			t.Error("a fired watch told the caller to poll again")
		}
		if a.WatchID != w.ID {
			t.Errorf("answer names watch %q, want %q", a.WatchID, w.ID)
		}
		if a.MatchedTotal != 1 {
			t.Errorf("matched_total = %d, want the 1 job that completed", a.MatchedTotal)
		}
		// The whole reason the call blocked rather than returning at
		// once: it waited for something that had not happened yet.
		if a.WaitedSeconds < 1 {
			t.Errorf("waited_seconds = %d; the poll reported no wait despite blocking for the firing",
				a.WaitedSeconds)
		}
	case <-ctx.Done():
		t.Fatal("the poll never answered; a watch that fires in the mirror must release it")
	}

	// And the answer survives the call: a second poll of the same URL
	// reports the same firing, which is what a poller that crashed
	// mid-wait comes back to.
	again := pollWatchURL(t, h, url, 5)
	if again.State != watchpoll.StateFired {
		t.Fatalf("re-polling a fired watch answered %q; the outcome must stay readable", again.State)
	}
}

// mintWatchURL calls the real mint endpoint as an authenticated user and
// returns the URL it hands back.
func mintWatchURL(t *testing.T, h *Handler, watchID string) string {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/watches/"+watchID+"/share", nil)
	req.Header.Set("X-Remote-User", "tester")
	rec := httptest.NewRecorder()
	h.handleWatchPath(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("minting the watch URL returned %d: %s", rec.Code, rec.Body.String())
	}
	var resp ShareWatchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding the mint response: %v (body %s)", err, rec.Body.String())
	}
	if resp.WatchID != watchID || resp.Owner != "tester" {
		t.Fatalf("mint answered for watch %q owner %q", resp.WatchID, resp.Owner)
	}
	if !strings.Contains(resp.URL, "/api/v1/share/watch?t=") {
		t.Fatalf("minted URL does not point at the redeem endpoint: %s", resp.URL)
	}
	return resp.URL
}

// pollWatchURL redeems a minted URL the way an external poller would:
// by its path and query, with no session of its own.
func pollWatchURL(t *testing.T, h *Handler, url string, waitSeconds int) watchpoll.Answer {
	t.Helper()
	cut := strings.Index(url, "/api/v1/share/watch")
	if cut < 0 {
		t.Fatalf("not a watch URL: %s", url)
	}
	target := url[cut:] + "&wait=" + strconv.Itoa(waitSeconds)
	rec := httptest.NewRecorder()
	h.handleSharedWatch(rec, httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("polling the watch URL returned %d: %s", rec.Code, rec.Body.String())
	}
	var a watchpoll.Answer
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatalf("decoding the poll answer: %v (body %s)", err, rec.Body.String())
	}
	return a
}
