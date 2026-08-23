package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

	if h.jobsFromMirror(ctx, httptest.NewRecorder(), "true", nil, 50, "", "alice") {
		t.Error("jobs routing must decline when no mirror is configured")
	}
	if h.historyFromMirror(ctx, httptest.NewRecorder(), "true", &htcondor.HistoryQueryOptions{Backwards: true}) {
		t.Error("history routing must decline when no mirror is configured")
	}

	// A Handler that never got a locator at all (zero value) must not panic.
	var bare Handler
	if bare.jobsFromMirror(ctx, httptest.NewRecorder(), "true", nil, 50, "", "alice") {
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
	if h.jobsFromMirror(context.Background(), httptest.NewRecorder(), "true", nil, 50, "", "") {
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
	if h.jobsFromMirror(ctx, rec, "true", nil, 50, "", "alice") {
		t.Fatal("expected the jobs route to decline")
	}
	if rec.Body.Len() != 0 || rec.Flushed {
		t.Errorf("declining wrote %d bytes (flushed=%v); the schedd fallback would corrupt the response",
			rec.Body.Len(), rec.Flushed)
	}

	rec = httptest.NewRecorder()
	if h.historyFromMirror(ctx, rec, "true", &htcondor.HistoryQueryOptions{Backwards: true}) {
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
