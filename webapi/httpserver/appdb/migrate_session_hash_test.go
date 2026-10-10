package appdb

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

// Browser and IdP sessions written before session IDs were hashed hold
// raw cookie values. The upgrade drops them (users sign in again) rather than
// keeping sessions whose cookie values may already have been read.
func TestSessionHashMigrationDropsRawSessions(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	goose.SetBaseFS(migrationFS)
	goose.SetTableName("htcondor_api_db_version")
	goose.SetLogger(quietLogger{})
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.UpToContext(ctx, db, "migrations", 17); err != nil {
		t.Fatalf("migrate to 0017: %v", err)
	}
	tables := []struct{ name, seed, count string }{
		{"http_sessions",
			`INSERT INTO http_sessions (session_id, username, created_at, expires_at) VALUES ('raw-cookie-value', 'alice', CURRENT_TIMESTAMP, datetime('now', '+1 day'))`,
			`SELECT COUNT(*) FROM http_sessions`},
		{"idp_sessions",
			`INSERT INTO idp_sessions (session_id, username, created_at, expires_at) VALUES ('raw-cookie-value', 'alice', CURRENT_TIMESTAMP, datetime('now', '+1 day'))`,
			`SELECT COUNT(*) FROM idp_sessions`},
	}
	for _, tb := range tables {
		if _, err := db.ExecContext(ctx, tb.seed); err != nil {
			t.Fatalf("seed %s: %v", tb.name, err)
		}
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatalf("migrate to head: %v", err)
	}
	for _, tb := range tables {
		var n int
		if err := db.QueryRowContext(ctx, tb.count).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tb.name, err)
		}
		if n != 0 {
			t.Errorf("%s has %d rows after upgrade, want 0", tb.name, n)
		}
	}
}
