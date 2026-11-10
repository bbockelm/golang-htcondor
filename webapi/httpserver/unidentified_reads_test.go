package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/jobqueue"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// Reads this server answers from its own copy of the queue -- a tailed
// job_queue.log, the htcondordb mirror's change feed, the mirror's
// archives -- have no schedd behind them to refuse a caller. These tests
// drive those endpoints through ServeHTTP with a caller nobody could
// name, with an ordinary user, and with an administrator, and check
// both what each sees and what each does not.

// unidentifiedReadsServer is a server that can mint a token for a
// browser session (so session requests authenticate) and has an admin
// group configured.
func unidentifiedReadsServer(t *testing.T) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "test.domain"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.webuiAdminGroups = newGroupSet("condor-admins")
	s.setupRoutes()
	return s
}

// withSession attaches a browser session for user to req.
func withSession(t *testing.T, s *Server, req *http.Request, user string, groups ...string) {
	t.Helper()
	sid, _, err := s.sessionStore.Create(user, groups)
	if err != nil {
		t.Fatalf("creating a session for %s: %v", user, err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec // test cookie
}

// twoOwnerQueue is a tailed job_queue.log holding one job of alice's
// (1.0) and one of bob's (2.0).
func twoOwnerQueue(t *testing.T) *jobqueue.Mirror {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "job_queue.log")
	log := "107 1 CreationTimestamp 1700000000\n" +
		"105\n101 1.0 Job\n103 1.0 Owner \"alice\"\n103 1.0 JobStatus 1\n106\n" +
		"105\n101 2.0 Job\n103 2.0 Owner \"bob\"\n103 2.0 JobStatus 1\n106\n"
	if err := os.WriteFile(logPath, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := jobqueue.New(logPath, jobqueue.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	return m
}

// serveBounded runs one request through ServeHTTP under a deadline, so a
// stream that should have been refused but was not ends the test with a
// body to inspect rather than hanging it.
func serveBounded(s *Server, req *http.Request, limit time.Duration) *httptest.ResponseRecorder {
	ctx, cancel := context.WithTimeout(req.Context(), limit)
	defer cancel()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req.WithContext(ctx))
	return w
}

func TestJobsWatchFromJobQueueLogRefusesAnUnnamedCaller(t *testing.T) {
	s := unidentifiedReadsServer(t)
	s.jobMirror = twoOwnerQueue(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs/watch", nil)
	req.Header.Set("Authorization", "Bearer "+forgedToken(t, "alice@test.domain"))
	w := serveBounded(s, req, 700*time.Millisecond)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	body := w.Body.String()
	for _, leaked := range []string{"event: upsert", `"1.0"`, `"2.0"`, "alice", "bob"} {
		if strings.Contains(body, leaked) {
			t.Errorf("a refused caller was sent %q: %s", leaked, body)
		}
	}
}

func TestJobsWatchFromJobQueueLogIsOwnerScoped(t *testing.T) {
	s := unidentifiedReadsServer(t)
	s.jobMirror = twoOwnerQueue(t)

	stream := func(t *testing.T, path string, auth func(*http.Request)) string {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		auth(req)
		w := serveBounded(s, req, 700*time.Millisecond)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	asAlice := func(r *http.Request) {
		// A bearer, qualified as a bearer's identity is: the case that
		// used to be served the whole queue.
		r.Header.Set("Authorization", "Bearer "+identifiedBearer(t, s.Handler))
	}
	asAdmin := func(r *http.Request) { withSession(t, s, r, "root", "condor-admins") }

	t.Run("a user sees their own job and not another's", func(t *testing.T) {
		body := stream(t, "/api/v1/jobs/watch", asAlice)
		if !strings.Contains(body, `"1.0"`) {
			t.Errorf("alice's own job is missing: %s", body)
		}
		if strings.Contains(body, `"2.0"`) || strings.Contains(body, `"bob"`) {
			t.Errorf("bob's job reached alice: %s", body)
		}
	})

	t.Run("asking for everyone does not widen a user", func(t *testing.T) {
		body := stream(t, "/api/v1/jobs/watch?owned_by_me=false", asAlice)
		if strings.Contains(body, `"2.0"`) {
			t.Errorf("bob's job reached alice with owned_by_me=false: %s", body)
		}
	})

	t.Run("a caller constraint cannot escape the owner clause", func(t *testing.T) {
		body := stream(t, "/api/v1/jobs/watch?constraint="+url.QueryEscape(`true) || (true`), asAlice)
		if strings.Contains(body, `"2.0"`) {
			t.Errorf("an unbalanced constraint widened the stream: %s", body)
		}
		if !strings.Contains(body, "bad constraint") {
			t.Errorf("an unparseable constraint was not reported: %s", body)
		}
	})

	t.Run("an administrator asking for everyone sees both", func(t *testing.T) {
		body := stream(t, "/api/v1/jobs/watch?owned_by_me=false", asAdmin)
		if !strings.Contains(body, `"1.0"`) || !strings.Contains(body, `"2.0"`) {
			t.Errorf("an administrator asking for the whole queue did not get it: %s", body)
		}
	})
}

// feedServer is a server following the queue through the mirror's change
// feed rather than a local job_queue.log.
func feedServer(t *testing.T) (*Server, *jobwatch.Feed) {
	t.Helper()
	s := unidentifiedReadsServer(t)
	feed := jobwatch.NewFeed(nil)
	s.jobWatchFeed = feed
	// Enabled is all the jobs watch asks of the locator; nothing here
	// dials it.
	s.dbMirror = dbmirror.NewLocator(htcondor.NewCollector("collector.invalid:9618"), config.NewEmpty())
	return s, feed
}

// startedJob drives one job through a transition the feed reports.
func startedJob(feed *jobwatch.Feed, cluster int, owner string) {
	for _, status := range []int{1, 2} {
		feed.Apply(jobwatch.WatchEvent{
			Kind: jobwatch.WatchUpsert,
			Key:  fmt.Sprintf("%d.0", cluster),
			AdText: fmt.Sprintf(`[ ClusterId = %d; ProcId = 0; Owner = %q; JobStatus = %d ]`,
				cluster, owner, status),
		})
	}
}

// liveFeedStream opens a streaming request in the background, lets it
// subscribe, pushes bob's job and then alice's through the feed, and
// returns what the stream carried once alice's arrived (or the wait gave
// up). alice's job goes second so it proves the stream was live while
// bob's went past.
func liveFeedStream(t *testing.T, s *Server, feed *jobwatch.Feed, req *http.Request, aliceMarker string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(req.Context())
	w := newSyncRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeHTTP(w, req.WithContext(ctx))
	}()
	defer func() {
		cancel()
		<-done
	}()

	// Both streams write something once subscribed: the jobs watch a
	// synced/resync frame, the activity stream a comment while the feed
	// is cold. Applying before that races the subscription.
	w.waitFor(t, "\n\n")
	startedJob(feed, 99, "bob")
	startedJob(feed, 12, "alice")
	if aliceMarker != "" {
		w.waitFor(t, aliceMarker)
	}
	return w.text()
}

func TestJobsWatchFromTheMirrorFeedRefusesAnUnnamedCaller(t *testing.T) {
	s, _ := feedServer(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs/watch", nil)
	req.Header.Set("Authorization", "Bearer "+forgedToken(t, "alice@test.domain"))
	w := serveBounded(s, req, time.Second)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "event:") {
		t.Errorf("a refused caller was sent stream frames: %s", w.Body.String())
	}
}

func TestJobsWatchFromTheMirrorFeedIsOwnerScoped(t *testing.T) {
	t.Run("a bearer user sees their own job and not another's", func(t *testing.T) {
		s, feed := feedServer(t)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs/watch", nil)
		req.Header.Set("Authorization", "Bearer "+identifiedBearer(t, s.Handler))

		body := liveFeedStream(t, s, feed, req, `"12.0"`)
		if strings.Contains(body, `"99.0"`) {
			t.Errorf("bob's job reached alice: %s", body)
		}
	})

	t.Run("an administrator asking for everyone sees both", func(t *testing.T) {
		s, feed := feedServer(t)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"/api/v1/jobs/watch?owned_by_me=false", nil)
		withSession(t, s, req, "root", "condor-admins")

		body := liveFeedStream(t, s, feed, req, `"12.0"`)
		if !strings.Contains(body, `"99.0"`) {
			t.Errorf("an administrator asking for the whole queue did not get bob's job: %s", body)
		}
	})
}

func TestActivityStreamRefusesAnUnnamedCaller(t *testing.T) {
	s, _ := feedServer(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/dashboard/activity/stream?owned_by_me=false", nil)
	req.Header.Set("Authorization", "Bearer "+forgedToken(t, "alice@test.domain"))
	w := serveBounded(s, req, time.Second)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "event:") {
		t.Errorf("a refused caller was sent stream frames: %s", w.Body.String())
	}
}

func TestActivityStreamIsOwnerScoped(t *testing.T) {
	t.Run("a bearer user sees their own job and not another's", func(t *testing.T) {
		s, feed := feedServer(t)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"/api/v1/dashboard/activity/stream", nil)
		req.Header.Set("Authorization", "Bearer "+identifiedBearer(t, s.Handler))

		body := liveFeedStream(t, s, feed, req, `"cluster_id":12`)
		if strings.Contains(body, `"cluster_id":99`) || strings.Contains(body, `"bob"`) {
			t.Errorf("bob's job reached alice: %s", body)
		}
	})

	t.Run("an administrator asking for everyone sees both", func(t *testing.T) {
		s, feed := feedServer(t)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"/api/v1/dashboard/activity/stream?owned_by_me=false", nil)
		withSession(t, s, req, "root", "condor-admins")

		body := liveFeedStream(t, s, feed, req, `"cluster_id":12`)
		if !strings.Contains(body, `"cluster_id":99`) {
			t.Errorf("an administrator asking for the whole access point did not get bob's job: %s", body)
		}
	})
}

func TestMetricsRefusesAnUnnamedCaller(t *testing.T) {
	s := unidentifiedReadsServer(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/metrics/job_metrics?group_by=Owner&agg=count:*", nil)
	req.Header.Set("Authorization", "Bearer "+forgedToken(t, "alice@test.domain"))
	w := serveBounded(s, req, time.Second)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: %s", w.Code, w.Body.String())
	}
}

// The metrics archive is read with this daemon's credential, so the
// clause localReadOwnerScope adds is the only thing between one user and
// another's samples -- for a bearer as much as for a browser session.
func TestLocalReadOwnerScope(t *testing.T) {
	alice := htcondor.WithAuthenticatedUser(context.Background(), "alice@test.domain")

	scoped, err := localReadOwnerScope(alice, "JobStatus == 5", false)
	if err != nil {
		t.Fatalf("scoping alice: %v", err)
	}
	if !scopeAdmits(t, scoped, "alice") {
		t.Errorf("alice's own rows are excluded: %q", scoped)
	}
	if scopeAdmits(t, scoped, "bob") {
		t.Errorf("bob's rows are admitted for alice: %q", scoped)
	}

	if _, err := localReadOwnerScope(alice, "true) || (true", false); err == nil {
		t.Error("an unbalanced constraint was accepted")
	}

	if got, err := localReadOwnerScope(alice, "JobStatus == 5", true); err != nil || got != "JobStatus == 5" {
		t.Errorf("an unconfined read = (%q, %v), want the constraint unchanged", got, err)
	}

	// Nobody, even with all set: that combination is the one that used
	// to read the whole archive.
	for _, all := range []bool{false, true} {
		if _, err := localReadOwnerScope(context.Background(), "true", all); !errors.Is(err, errUnidentifiedCaller) {
			t.Errorf("all=%t: an unnamed caller got %v, want errUnidentifiedCaller", all, err)
		}
	}
}

// Every route that answers from this daemon's own copy of the queue
// refuses a caller nobody could name, through the shared gate rather
// than each handler remembering to.
func TestSchedlessReadsRefuseAnUnnamedCaller(t *testing.T) {
	s, _ := feedServer(t)
	s.jobMirror = twoOwnerQueue(t)

	for _, path := range []string{
		"/api/v1/jobs/watch",
		"/api/v1/dashboard/activity/stream",
		"/api/v1/metrics/job_metrics",
		"/api/v1/dashboard",
		"/api/v1/dashboard/activity",
		"/api/v1/issues",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer "+forgedToken(t, "alice@test.domain"))
			w := serveBounded(s, req, time.Second)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401: %s", w.Code, w.Body.String())
			}
		})
	}
}

// whoami through the router: a credential that names nobody is not an
// authenticated caller.
func TestWhoAmIForANamelessBearerIsNotAuthenticated(t *testing.T) {
	s := unidentifiedReadsServer(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+forgedToken(t, "alice@test.domain"))
	w := serveBounded(s, req, time.Second)

	var got WhoAmIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding %q: %v", w.Body.String(), err)
	}
	if got.Authenticated || got.User != "" {
		t.Errorf("whoami = %+v, want unauthenticated", got)
	}
}
