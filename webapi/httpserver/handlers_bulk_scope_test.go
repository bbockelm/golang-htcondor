package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestBulkOwnerScope covers the destructive bulk-endpoint owner scoping: a Web UI
// session that is not an admin is confined to its own jobs (and an injection
// constraint is rejected), while an admin session and a non-session API-token
// caller pass through unchanged (schedd ACL is their boundary).
func TestBulkOwnerScope(t *testing.T) {
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
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice")

	reqWithSession := func(user string, groups ...[]string) *http.Request {
		sid, _, err := server.sessionStore.Create(user, groups...)
		if err != nil {
			t.Fatalf("session create: %v", err)
		}
		r := httptest.NewRequestWithContext(context.Background(), "POST", "/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
		return r
	}

	t.Run("no session passes through (API token -> schedd ACL)", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), "POST", "/", nil)
		got, err := server.bulkOwnerScope(ctx, r, `JobStatus == 5`)
		if err != nil || got != `JobStatus == 5` {
			t.Errorf("got (%q, %v), want passthrough", got, err)
		}
	})

	t.Run("non-admin session is owner-scoped", func(t *testing.T) {
		r := reqWithSession("alice")
		scoped, err := server.bulkOwnerScope(ctx, r, `JobStatus == 5`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if scopeAdmits(t, scoped, "bob") {
			t.Errorf("BYPASS: non-admin scope admits bob: %q", scoped)
		}
		if !scopeAdmits(t, scoped, "alice") {
			t.Errorf("owner wrongly excluded: %q", scoped)
		}
	})

	t.Run("non-admin session rejects an injection constraint", func(t *testing.T) {
		r := reqWithSession("alice")
		if _, err := server.bulkOwnerScope(ctx, r, `true) || (true`); err == nil {
			t.Error("injection constraint must be rejected for a non-admin session")
		}
	})

	t.Run("admin session bypasses scoping", func(t *testing.T) {
		server.webuiAdminGroup = "condor-admins"
		r := reqWithSession("root", []string{"condor-admins"})
		got, err := server.bulkOwnerScope(ctx, r, `JobStatus == 5`)
		if err != nil || got != `JobStatus == 5` {
			t.Errorf("admin: got (%q, %v), want passthrough", got, err)
		}
	})
}

// TestJobOwnerScope covers the by-id endpoints' confinement. Every
// endpoint that addresses a job by cluster.proc — the ad, the sandbox,
// the log, the actions — routes through jobOwnerScope, so a non-admin
// browser session cannot reach another user's job by guessing its id.
// The listing endpoint has always enforced that; the by-id ones did not
// until this rule was applied to them.
func TestJobOwnerScope(t *testing.T) {
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
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")

	sessionReq := func(user string, groups ...[]string) *http.Request {
		sid, _, err := server.sessionStore.Create(user, groups...)
		if err != nil {
			t.Fatalf("session create: %v", err)
		}
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/jobs/7.0", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
		return r
	}

	t.Run("non-admin session is confined to its own job", func(t *testing.T) {
		scoped, err := server.jobOwnerScope(ctx, sessionReq("alice"), 7, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !scopeAdmitsJob(t, scoped, "alice", 7, 0) {
			t.Errorf("owner wrongly excluded from their own job: %q", scoped)
		}
		if scopeAdmitsJob(t, scoped, "bob", 7, 0) {
			t.Errorf("BYPASS: another user's job 7.0 is admitted: %q", scoped)
		}
		// The job id itself must still be part of the constraint.
		if scopeAdmitsJob(t, scoped, "alice", 8, 0) {
			t.Errorf("scope matches the wrong cluster: %q", scoped)
		}
		if scopeAdmitsJob(t, scoped, "alice", 7, 1) {
			t.Errorf("scope matches the wrong proc: %q", scoped)
		}
	})

	t.Run("qualified actor maps to the bare owner", func(t *testing.T) {
		// The actor is "alice@uid.domain"; a job's Owner is "alice".
		scoped, err := server.jobOwnerScope(ctx, sessionReq("alice"), 7, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !scopeAdmitsJob(t, scoped, "alice", 7, 0) {
			t.Errorf("qualified actor did not map to the bare owner: %q", scoped)
		}
	})

	t.Run("admin session is not confined", func(t *testing.T) {
		server.webuiAdminGroup = "condor-admins"
		scoped, err := server.jobOwnerScope(ctx, sessionReq("root", []string{"condor-admins"}), 7, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !scopeAdmitsJob(t, scoped, "bob", 7, 0) {
			t.Errorf("an admin must still reach another user's job: %q", scoped)
		}
	})

	t.Run("API-token caller keeps the schedd ACL as its boundary", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/jobs/7.0", nil)
		scoped, err := server.jobOwnerScope(ctx, r, 7, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !scopeAdmitsJob(t, scoped, "bob", 7, 0) {
			t.Errorf("a bearer caller must pass through unscoped, as on the bulk endpoints: %q", scoped)
		}
	})
}

// scopeAdmitsJob evaluates a scoped constraint against a job ad with the
// given owner and id, using the real ClassAd engine.
func scopeAdmitsJob(t *testing.T, scoped, owner string, cluster, proc int) bool {
	t.Helper()
	expr, err := classad.ParseExpr(scoped)
	if err != nil {
		t.Fatalf("scoped constraint did not parse: %q: %v", scoped, err)
	}
	ad := classad.New()
	ad.InsertAttrString("Owner", owner)
	ad.InsertAttr("ClusterId", int64(cluster))
	ad.InsertAttr("ProcId", int64(proc))
	b, _ := expr.Eval(ad).BoolValue()
	return b
}
