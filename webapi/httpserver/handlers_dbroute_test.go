package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

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

	if _, _, ok := h.jobsFromMirror(ctx, "true", nil, 50, "", "alice"); ok {
		t.Error("jobs routing must decline when no mirror is configured")
	}
	if _, _, ok := h.historyFromMirror(ctx, "true", &htcondor.HistoryQueryOptions{Backwards: true}); ok {
		t.Error("history routing must decline when no mirror is configured")
	}

	// A Handler that never got a locator at all (zero value) must not panic.
	var bare Handler
	if _, _, ok := bare.jobsFromMirror(ctx, "true", nil, 50, "", "alice"); ok {
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
	if _, _, ok := h.jobsFromMirror(context.Background(), "true", nil, 50, "", ""); ok {
		t.Error("jobs routing must decline without an authenticated owner")
	}
}

// TestWriteMirrorJobsShape pins the response a mirror-served job listing
// produces: the same envelope the streaming schedd path writes, plus the
// provenance fields, and never has_more (routing declines paginated or
// oversized results upstream).
func TestWriteMirrorJobsShape(t *testing.T) {
	h := &Handler{}
	ad := classad.New()
	ad.InsertAttr("ClusterId", 12)
	ad.InsertAttr("ProcId", 0)

	rec := httptest.NewRecorder()
	h.writeMirrorJobs(rec, []*classad.ClassAd{ad}, "[source: htcondordb mirror \"db\"]")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got struct {
		Jobs          []map[string]interface{} `json:"jobs"`
		TotalReturned int                      `json:"total_returned"`
		HasMore       bool                     `json:"has_more"`
		Source        string                   `json:"source"`
		SourceNote    string                   `json:"source_note"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not the documented shape: %v (%s)", err, rec.Body.String())
	}
	if len(got.Jobs) != 1 || got.TotalReturned != 1 {
		t.Errorf("jobs=%d total_returned=%d, want 1 and 1", len(got.Jobs), got.TotalReturned)
	}
	if got.HasMore {
		t.Error("has_more must be false on a mirror-served listing")
	}
	if got.Source != "htcondordb" || got.SourceNote == "" {
		t.Errorf("provenance missing: source=%q note=%q", got.Source, got.SourceNote)
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
