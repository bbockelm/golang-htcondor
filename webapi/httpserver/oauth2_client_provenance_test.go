package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newProvenanceServer builds a server with OAuth2 enabled so the client
// table and the usage recorder exist.
func newProvenanceServer(t *testing.T) (*Server, func(method, target, body string) *http.Request) {
	t.Helper()
	server, err := NewServer(Config{
		ListenAddr:   "127.0.0.1:0",
		ScheddName:   "test",
		ScheddAddr:   "127.0.0.1:9618",
		SessionTTL:   time.Hour,
		OAuth2DBPath: t.TempDir() + "/t.db",
		EnableMCP:    true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if server.oauth2Provider == nil {
		t.Fatal("expected the OAuth2 provider to be enabled")
	}
	server.webuiAdminGroup = "condor-admins"
	t.Cleanup(func() { server.clientUsage.Close() })

	return server, func(method, target, body string) *http.Request {
		sid, _, err := server.sessionStore.Create("root", []string{"condor-admins"})
		if err != nil {
			t.Fatalf("session create: %v", err)
		}
		var r *http.Request
		if body == "" {
			r = httptest.NewRequestWithContext(context.Background(), method, target, nil)
		} else {
			r = httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		}
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
		return r
	}
}

func insertClient(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `INSERT INTO oauth2_clients
		(id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
		VALUES (?, '', '[]', '[]', '[]', '[]', 0)`, id)
	if err != nil {
		t.Fatalf("insert client %s: %v", id, err)
	}
}

func listClients(t *testing.T, server *Server, req func(string, string, string) *http.Request) []AdminClient {
	t.Helper()
	rec := httptest.NewRecorder()
	server.handleAdminListClients(rec, req("GET", "/api/v1/admin/oauth2/clients", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Clients []AdminClient `json:"clients"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Clients
}

func findClient(t *testing.T, clients []AdminClient, id string) AdminClient {
	t.Helper()
	for _, c := range clients {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("client %s not in list of %d", id, len(clients))
	return AdminClient{}
}

// The name and origin have to survive the round trip to the admin list,
// or the whole feature is invisible.
func TestClientProvenanceRoundTrip(t *testing.T) {
	server, req := newProvenanceServer(t)
	db := server.oauth2Provider.GetStorage().GetDB()
	ctx := context.Background()

	insertClient(t, db, "client_1700000000000000000")
	if err := setClientProvenance(ctx, db, "client_1700000000000000000", "Claude", ClientOriginDynamic); err != nil {
		t.Fatalf("setClientProvenance: %v", err)
	}

	got := findClient(t, listClients(t, server, req), "client_1700000000000000000")
	if got.Name != "Claude" {
		t.Errorf("name = %q, want Claude", got.Name)
	}
	if got.Origin != string(ClientOriginDynamic) {
		t.Errorf("origin = %q, want dynamic", got.Origin)
	}
}

// A row that predates provenance tracking must report an EMPTY origin,
// not "not dynamic". The two are different claims and only one of them
// is true.
func TestClientProvenanceUnknownOrigin(t *testing.T) {
	server, req := newProvenanceServer(t)
	insertClient(t, server.oauth2Provider.GetStorage().GetDB(), "legacy-client")

	got := findClient(t, listClients(t, server, req), "legacy-client")
	if got.Origin != "" {
		t.Errorf("origin = %q, want empty for a row with no recorded origin", got.Origin)
	}
	if got.Name != "" || got.Notes != "" {
		t.Errorf("unexpected name/notes on a legacy row: %+v", got)
	}
	if got.LastUsedAt != nil {
		t.Errorf("last_used_at = %v, want absent for a never-used client", got.LastUsedAt)
	}
}

func TestClientNotesEditing(t *testing.T) {
	server, req := newProvenanceServer(t)
	insertClient(t, server.oauth2Provider.GetStorage().GetDB(), "abc")

	rec := httptest.NewRecorder()
	server.handleAdminUpdateClient(rec,
		req("PATCH", "/api/v1/admin/oauth2/clients/abc", `{"notes":"Ben's laptop, MCP"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: status %d, body %s", rec.Code, rec.Body.String())
	}

	got := findClient(t, listClients(t, server, req), "abc")
	if got.Notes != "Ben's laptop, MCP" {
		t.Errorf("notes = %q", got.Notes)
	}

	// Clearing is a legitimate edit, not a no-op to be ignored.
	rec = httptest.NewRecorder()
	server.handleAdminUpdateClient(rec, req("PATCH", "/api/v1/admin/oauth2/clients/abc", `{"notes":""}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("patch clear: status %d", rec.Code)
	}
	if n := findClient(t, listClients(t, server, req), "abc").Notes; n != "" {
		t.Errorf("notes after clear = %q, want empty", n)
	}
}

func TestClientNotesRejectsUnknownAndOversized(t *testing.T) {
	server, req := newProvenanceServer(t)

	rec := httptest.NewRecorder()
	server.handleAdminUpdateClient(rec,
		req("PATCH", "/api/v1/admin/oauth2/clients/nope", `{"notes":"hi"}`))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown client: status = %d, want 404", rec.Code)
	}

	insertClient(t, server.oauth2Provider.GetStorage().GetDB(), "abc")
	big, _ := json.Marshal(adminClientNotesRequest{Notes: strings.Repeat("x", maxClientNotesLen+1)})
	rec = httptest.NewRecorder()
	server.handleAdminUpdateClient(rec, req("PATCH", "/api/v1/admin/oauth2/clients/abc", string(big)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized notes: status = %d, want 400", rec.Code)
	}
}

func TestClientNotesRequiresAdmin(t *testing.T) {
	server, _ := newProvenanceServer(t)
	insertClient(t, server.oauth2Provider.GetStorage().GetDB(), "abc")

	sid, _, err := server.sessionStore.Create("alice", nil)
	if err != nil {
		t.Fatalf("session create: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), "PATCH",
		"/api/v1/admin/oauth2/clients/abc", strings.NewReader(`{"notes":"pwned"}`))
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec

	rec := httptest.NewRecorder()
	server.handleAdminUpdateClient(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	var notes string
	if err := server.oauth2Provider.GetStorage().GetDB().
		QueryRowContext(context.Background(), `SELECT notes FROM oauth2_clients WHERE id = 'abc'`).Scan(&notes); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if notes != "" {
		t.Errorf("BYPASS: a non-admin wrote notes: %q", notes)
	}
}

// Usage must actually reach the database, and the list endpoint must
// flush before reading or an admin would see a stale "never used" for a
// token issued seconds ago.
func TestClientUsageRecordedAndFlushedByList(t *testing.T) {
	server, req := newProvenanceServer(t)
	insertClient(t, server.oauth2Provider.GetStorage().GetDB(), "abc")

	before := time.Now().Add(-time.Second)
	server.clientUsage.Record("abc", "alice@example.edu", time.Now())

	// Deliberately NOT calling FlushNow here: handleAdminListClients is
	// supposed to do it.
	got := findClient(t, listClients(t, server, req), "abc")
	if got.LastUsedAt == nil {
		t.Fatal("last_used_at is absent; the list did not flush pending usage")
	}
	if got.LastUsedAt.Before(before) {
		t.Errorf("last_used_at = %v, want after %v", got.LastUsedAt, before)
	}
	if len(got.RecentUsers) != 1 || got.RecentUsers[0].Subject != "alice@example.edu" {
		t.Errorf("recent_users = %+v", got.RecentUsers)
	}
}

// The sample keeps the newest three DISTINCT subjects. Deduplicating is
// the point: three rows for one busy service account say less than one
// row each for three people.
func TestClientRecentUsersKeepsNewestDistinct(t *testing.T) {
	server, req := newProvenanceServer(t)
	insertClient(t, server.oauth2Provider.GetStorage().GetDB(), "abc")

	base := time.Now()
	for i, subject := range []string{"a", "b", "a", "c", "d"} {
		server.clientUsage.Record("abc", subject, base.Add(time.Duration(i)*time.Second))
	}
	server.clientUsage.FlushNow(context.Background())

	got := findClient(t, listClients(t, server, req), "abc")
	if len(got.RecentUsers) != maxRecentUsers {
		t.Fatalf("got %d users, want %d: %+v", len(got.RecentUsers), maxRecentUsers, got.RecentUsers)
	}
	want := []string{"d", "c", "a"}
	for i, w := range want {
		if got.RecentUsers[i].Subject != w {
			t.Errorf("user %d = %q, want %q (full: %+v)", i, got.RecentUsers[i].Subject, w, got.RecentUsers)
		}
	}
}

// The sample has to survive a restart: the first flush of a new process
// must merge with what is stored, not replace three known users with the
// one it just saw.
func TestClientRecentUsersSurviveRestart(t *testing.T) {
	server, req := newProvenanceServer(t)
	db := server.oauth2Provider.GetStorage().GetDB()
	insertClient(t, db, "abc")

	base := time.Now()
	server.clientUsage.Record("abc", "a", base)
	server.clientUsage.Record("abc", "b", base.Add(time.Second))
	server.clientUsage.FlushNow(context.Background())
	server.clientUsage.Close()

	// A fresh recorder over the same database, as a restart would build.
	server.clientUsage = newClientUsageRecorder(db, time.Hour)
	t.Cleanup(func() { server.clientUsage.Close() })
	server.clientUsage.Record("abc", "c", base.Add(2*time.Second))

	got := findClient(t, listClients(t, server, req), "abc")
	subjects := make([]string, 0, len(got.RecentUsers))
	for _, u := range got.RecentUsers {
		subjects = append(subjects, u.Subject)
	}
	if len(subjects) != 3 || subjects[0] != "c" {
		t.Fatalf("recent users after restart = %v, want c newest and the earlier two kept", subjects)
	}
	for _, want := range []string{"a", "b"} {
		found := false
		for _, s := range subjects {
			if s == want {
				found = true
			}
		}
		if !found {
			t.Errorf("subject %q was lost across the restart: %v", want, subjects)
		}
	}
}

// Debouncing is the whole point of the recorder: a client refreshing on
// a timer must not produce a write per refresh.
func TestClientUsageDebouncesWrites(t *testing.T) {
	server, _ := newProvenanceServer(t)
	db := server.oauth2Provider.GetStorage().GetDB()
	insertClient(t, db, "abc")

	// A long interval means the background loop will not fire during the
	// test; every write below has to come from an explicit flush.
	server.clientUsage.Close()
	server.clientUsage = newClientUsageRecorder(db, time.Hour)
	t.Cleanup(func() { server.clientUsage.Close() })

	base := time.Now()
	for i := 0; i < 50; i++ {
		server.clientUsage.Record("abc", "alice", base.Add(time.Duration(i)*time.Millisecond))
	}

	// Nothing written yet.
	var lastUsed sql.NullTime
	if err := db.QueryRowContext(context.Background(), `SELECT last_used_at FROM oauth2_clients WHERE id='abc'`).Scan(&lastUsed); err != nil {
		t.Fatalf("read: %v", err)
	}
	if lastUsed.Valid {
		t.Error("50 records wrote through before any flush; the debounce is not coalescing")
	}

	server.clientUsage.FlushNow(context.Background())
	if err := db.QueryRowContext(context.Background(), `SELECT last_used_at FROM oauth2_clients WHERE id='abc'`).Scan(&lastUsed); err != nil {
		t.Fatalf("read after flush: %v", err)
	}
	if !lastUsed.Valid {
		t.Fatal("flush wrote nothing")
	}
}

// A client deleted between issuing a token and the flush must not wedge
// the recorder into retrying forever.
func TestClientUsageForgetsDeletedClient(t *testing.T) {
	server, _ := newProvenanceServer(t)
	server.clientUsage.Record("gone", "alice", time.Now())
	server.clientUsage.FlushNow(context.Background())

	server.clientUsage.mu.Lock()
	pending := len(server.clientUsage.pending)
	server.clientUsage.mu.Unlock()
	if pending != 0 {
		t.Errorf("pending = %d, want 0; a deleted client should be dropped, not retried", pending)
	}
}

func TestMergeRecentUsers(t *testing.T) {
	now := time.Now()
	u := func(s string) clientUse { return clientUse{Subject: s, At: now} }

	got := mergeRecentUsers([]clientUse{u("b"), u("c")}, u("a"))
	if len(got) != 3 || got[0].Subject != "a" {
		t.Fatalf("newest must lead: %+v", got)
	}

	// A repeat subject moves to the front rather than appearing twice.
	got = mergeRecentUsers([]clientUse{u("a"), u("b")}, u("b"))
	if len(got) != 2 || got[0].Subject != "b" || got[1].Subject != "a" {
		t.Fatalf("repeat should move to front without duplicating: %+v", got)
	}

	// The cap holds.
	got = mergeRecentUsers([]clientUse{u("b"), u("c"), u("d")}, u("a"))
	if len(got) != maxRecentUsers {
		t.Fatalf("got %d, want cap %d: %+v", len(got), maxRecentUsers, got)
	}
}

// A nil recorder is the OAuth2-disabled case and must be inert rather
// than a panic on the token path.
func TestNilClientUsageRecorderIsInert(_ *testing.T) {
	var r *clientUsageRecorder
	r.Record("abc", "alice", time.Now())
	r.FlushNow(context.Background())
	r.Close()

	noDB := newClientUsageRecorder(nil, time.Millisecond)
	noDB.Record("abc", "alice", time.Now())
	noDB.FlushNow(context.Background())
	noDB.Close()
}
