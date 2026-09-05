package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"
	"github.com/prometheus/client_golang/prometheus/testutil"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// TestOwnerFromActorHTTP covers the actor→Owner mapping the mirror
// constraint depends on: the authenticated actor is often qualified, a
// job's Owner attribute never is.
func TestOwnerFromActorHTTP(t *testing.T) {
	cases := map[string]string{
		"alice":            "alice",
		"alice@uid.domain": "alice",
		"":                 "",
	}
	for actor, want := range cases {
		if got := ownerFromActor(actor); got != want {
			t.Errorf("ownerFromActor(%q) = %q, want %q", actor, got, want)
		}
	}
}

// TestMirrorRoutingDisabledFallsThrough is the safety default: with no
// collector or no HTCondor config there is no mirror to route to, and
// both entry points must decline so the caller uses the schedd.
func TestMirrorRoutingDisabledFallsThrough(t *testing.T) {
	h := &Handler{dbMirror: dbmirror.NewLocator(nil, nil)}
	ctx := context.Background()

	if served, _ := h.jobsFromMirror(ctx, httptest.NewRecorder(), "true", nil, 50, "", "alice"); served {
		t.Error("jobs routing must decline when no mirror is configured")
	}
	if served, _ := h.historyFromMirror(ctx, httptest.NewRecorder(), "true", &htcondor.HistoryQueryOptions{Backwards: true}); served {
		t.Error("history routing must decline when no mirror is configured")
	}

	// A Handler that never got a locator at all (zero value) must not panic.
	var bare Handler
	if served, _ := bare.jobsFromMirror(ctx, httptest.NewRecorder(), "true", nil, 50, "", "alice"); served {
		t.Error("jobs routing must decline with no locator")
	}
}

// TestMirrorJobsRoutingRequiresAnOwner checks the confinement
// precondition: without an authenticated caller to scope to, the mirror
// is not used — its connection authenticates as the daemon, so an
// unconfined read there would not have the schedd's per-caller ACL
// behind it.
func TestMirrorJobsRoutingRequiresAnOwner(t *testing.T) {
	// Enabled locator (collector + config present); no connection is
	// made because the owner check comes first.
	h := &Handler{dbMirror: dbmirror.NewLocator(htcondor.NewCollector("collector.invalid"), config.NewEmpty())}
	if !h.dbMirror.Enabled() {
		t.Fatal("expected the locator to report enabled")
	}
	if served, _ := h.jobsFromMirror(context.Background(), httptest.NewRecorder(), "true", nil, 50, "", ""); served {
		t.Error("jobs routing must decline without an authenticated owner")
	}
}

// TestMirrorDeclineWritesNothing is what makes the schedd fallback safe:
// a routing decision that declines must leave the response untouched, or
// the caller would append a second body to a half-written one.
func TestMirrorDeclineWritesNothing(t *testing.T) {
	h := &Handler{dbMirror: dbmirror.NewLocator(nil, nil)}
	ctx := context.Background()

	rec := httptest.NewRecorder()
	if served, _ := h.jobsFromMirror(ctx, rec, "true", nil, 50, "", "alice"); served {
		t.Fatal("expected the jobs route to decline")
	}
	if rec.Body.Len() != 0 || rec.Flushed {
		t.Errorf("declining wrote %d bytes (flushed=%v); the schedd fallback would corrupt the response",
			rec.Body.Len(), rec.Flushed)
	}

	rec = httptest.NewRecorder()
	if served, _ := h.historyFromMirror(ctx, rec, "true", &htcondor.HistoryQueryOptions{Backwards: true}); served {
		t.Fatal("expected the history route to decline")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("declining wrote %d bytes", rec.Body.Len())
	}
}

// TestHistoryOwnerScopeEnforcement covers the scoping the archive
// endpoint applies before any routing decision: a browser session that
// is not an admin is confined to its own records regardless of the
// parameter, while a bearer-token caller (no session) keeps the
// unscoped behavior it has today.
func TestHistoryOwnerScopeEnforcement(t *testing.T) {
	server, err := NewServer(Config{
		ListenAddr:   "127.0.0.1:0",
		ScheddName:   "test",
		ScheddAddr:   "127.0.0.1:9618",
		SessionTTL:   time.Hour,
		OAuth2DBPath: t.TempDir() + "/t.db",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	sessionReq := func(user string, groups ...[]string) *http.Request {
		sid, _, err := server.sessionStore.Create(user, groups...)
		if err != nil {
			t.Fatalf("session create: %v", err)
		}
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/jobs/archive", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
		return r
	}

	t.Run("non-admin session is scoped even with owned_by_me=false", func(t *testing.T) {
		r := sessionReq("alice")
		r.URL.RawQuery = "owned_by_me=false"
		scoped, ok, err := server.historyOwnerScope(htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain"), r, "JobStatus == 5")
		if err != nil || !ok {
			t.Fatalf("expected the query to be scoped, got (%q, %v, %v)", scoped, ok, err)
		}
		if scopeAdmits(t, scoped, "bob") {
			t.Errorf("BYPASS: scope admits bob: %q", scoped)
		}
		if !scopeAdmits(t, scoped, "alice") {
			t.Errorf("owner wrongly excluded: %q", scoped)
		}
	})

	t.Run("admin session is not scoped", func(t *testing.T) {
		server.webuiAdminGroup = "condor-admins"
		r := sessionReq("root", []string{"condor-admins"})
		if _, ok, err := server.historyOwnerScope(htcondor.WithAuthenticatedUser(context.Background(), "root"), r, "JobStatus == 5"); ok || err != nil {
			t.Errorf("an admin session must not be forced into owner scope (ok=%v err=%v)", ok, err)
		}
	})

	// The archive page's Mine/Everyone selector is an admin opting IN to
	// the scoping they are not forced into. Without this the toggle would
	// render but change nothing.
	t.Run("admin session honors owned_by_me=true", func(t *testing.T) {
		server.webuiAdminGroup = "condor-admins"
		r := sessionReq("root", []string{"condor-admins"})
		r.URL.RawQuery = "owned_by_me=true"
		scoped, ok, err := server.historyOwnerScope(htcondor.WithAuthenticatedUser(context.Background(), "root@uid.domain"), r, "JobStatus == 5")
		if err != nil || !ok {
			t.Fatalf("an admin asking for their own records must be scoped, got (%q, %v, %v)", scoped, ok, err)
		}
		if scopeAdmits(t, scoped, "alice") {
			t.Errorf("scope admits another owner: %q", scoped)
		}
		if !scopeAdmits(t, scoped, "root") {
			t.Errorf("the admin's own records were excluded: %q", scoped)
		}
	})

	t.Run("bearer caller is not scoped by default", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/jobs/archive", nil)
		if _, ok, err := server.historyOwnerScope(htcondor.WithAuthenticatedUser(context.Background(), "alice"), r, "JobStatus == 5"); ok || err != nil {
			t.Errorf("a bearer-token caller must keep today's unscoped behavior by default (ok=%v err=%v)", ok, err)
		}
	})

	t.Run("bearer caller can opt in", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/jobs/archive?owned_by_me=true", nil)
		scoped, ok, err := server.historyOwnerScope(htcondor.WithAuthenticatedUser(context.Background(), "alice"), r, "")
		if err != nil || !ok {
			t.Fatalf("owned_by_me=true must scope the query, got (%q, %v, %v)", scoped, ok, err)
		}
		if scopeAdmits(t, scoped, "bob") {
			t.Errorf("BYPASS: scope admits bob: %q", scoped)
		}
	})
}

// TestStaleMirrorPageTokenIsRejected covers the failure mode that
// pagination across two backends makes possible: the mirror hands out a
// page token, then goes away (or falls behind, or compacts the scan the
// cursor names). The schedd cannot resume someone else's walk, and
// restarting from the top would re-serve rows the caller already has as
// if they were new — so the request must fail loudly instead.
func TestStaleMirrorPageTokenIsRejected(t *testing.T) {
	signingKeyPath := filepath.Join(t.TempDir(), "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("writing the signing key: %v", err)
	}

	// No collector, so no mirror: whatever issued this token, nothing
	// here can honor it.
	server, err := NewServer(Config{
		ScheddName:               "test-schedd",
		ScheddAddr:               "127.0.0.1:0",
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           signingKeyPath,
		TrustDomain:              "test.htcondor.org",
		UIDDomain:                "test.htcondor.org",
		OAuth2DBPath:             filepath.Join(t.TempDir(), "sessions.db"),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	token := dbmirror.EncodeCursor(dbrpc.SeqCursor{Shard: 1, Snapshot: 7, Seq: 3, Key: "12.0"})
	req := httptest.NewRequestWithContext(context.Background(), "GET",
		"/api/v1/jobs?page_token="+url.QueryEscape(token), nil)
	req.Header.Set("X-Test-User", "alice")
	rec := httptest.NewRecorder()
	server.handleListJobs(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	// The message has to tell the caller what to do, since the token
	// they hold will never work again.
	if !strings.Contains(rec.Body.String(), "without a page token") {
		t.Errorf("body does not say how to recover: %s", rec.Body.String())
	}
}

// TestMirrorRequiredFailsInsteadOfFallingBack is the point of
// HTTP_API_DBMIRROR_REQUIRED: the operator has said the access point
// must not absorb this load, so a read the mirror cannot serve has to
// fail loudly rather than quietly become schedd load — the failure mode
// the default best-effort path is designed to avoid.
func TestMirrorRequiredFailsInsteadOfFallingBack(t *testing.T) {
	h := &Handler{
		logger: testLogger(t),
		dbMirror: dbmirror.NewLocatorWithOptions(
			htcondor.NewCollector("collector.invalid"), config.NewEmpty(),
			dbmirror.Options{Required: true}),
	}
	if !h.dbMirror.Required() {
		t.Fatal("expected the locator to report required")
	}

	cases := []struct {
		name       string
		decision   dbmirror.Decision
		wantStatus int
	}{
		{
			// The mirror is behind or gone: retrying may work, and it is
			// the deployment's problem, not the caller's.
			name:       "unavailable is a 503",
			decision:   dbmirror.Decision{Reason: dbmirror.ReasonStale, Note: "mirror is stale"},
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			// No amount of waiting makes the mirror able to serve this
			// query, so the caller has to change it.
			name:       "query shape is a 400",
			decision:   dbmirror.Decision{Reason: dbmirror.ReasonUnsupportedQuery, Note: "query sets scan_limit"},
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if !h.mirrorRequiredError(rec, c.decision) {
				t.Fatal("expected the required-mirror path to write a response")
			}
			if rec.Code != c.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, c.wantStatus)
			}
			// The reason has to reach the caller; "service unavailable"
			// alone leaves an operator with nothing to act on.
			if !strings.Contains(rec.Body.String(), c.decision.Note) {
				t.Errorf("body does not carry the reason %q: %s", c.decision.Note, rec.Body.String())
			}
		})
	}

	// A served decision writes nothing: it is not an error.
	rec := httptest.NewRecorder()
	if h.mirrorRequiredError(rec, dbmirror.Decision{Use: true, Reason: dbmirror.ReasonServed}) {
		t.Error("a served decision must not be turned into an error")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("wrote a body for a served decision: %s", rec.Body.String())
	}
}

// TestMirrorNotRequiredStaysSilent is the default: a decline is a
// fallback, invisible to the caller. If this ever wrote a response the
// schedd path would append a second body to it.
func TestMirrorNotRequiredStaysSilent(t *testing.T) {
	h := &Handler{
		logger:   testLogger(t),
		dbMirror: dbmirror.NewLocator(htcondor.NewCollector("collector.invalid"), config.NewEmpty()),
	}
	rec := httptest.NewRecorder()
	if h.mirrorRequiredError(rec, dbmirror.Decision{Reason: dbmirror.ReasonStale, Note: "stale"}) {
		t.Fatal("best-effort routing must not turn a decline into an error")
	}
	if rec.Body.Len() != 0 || rec.Code != http.StatusOK {
		t.Errorf("wrote to the response: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

// TestMirrorDecisionsAreCounted checks the metric an operator watches to
// answer "is the integration working?". A decline that is not counted is
// indistinguishable from one that never happened.
func TestMirrorDecisionsAreCounted(t *testing.T) {
	h := &Handler{
		logger:           testLogger(t),
		httpMetricsState: newHTTPMetrics(),
		dbMirror:         dbmirror.NewLocator(nil, nil),
	}
	// Routing is not configured, so this declines before any I/O.
	if served, _ := h.jobsFromMirror(context.Background(), httptest.NewRecorder(), "true", nil, 50, "", "alice"); served {
		t.Fatal("expected the jobs route to decline")
	}

	got := testutil.ToFloat64(h.httpMetricsState.mirror.decisions.WithLabelValues(
		"jobs", "declined", string(dbmirror.ReasonNotConfigured)))
	if got != 1 {
		t.Errorf("decisions_total{table=jobs,decision=declined,reason=not_configured} = %v, want 1", got)
	}
}
