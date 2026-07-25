package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
