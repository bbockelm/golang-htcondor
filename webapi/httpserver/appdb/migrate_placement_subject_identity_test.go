package appdb

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

// The placementd bound of an OAuth2 subject is kept per sign-in identity:
// the upgrade keeps the existing rows, and afterwards a second identity of
// the same account gets a row of its own instead of replacing the first.
func TestPlacementSubjectBoundIsPerIdentity(t *testing.T) {
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
	if err := goose.UpToContext(ctx, db, "migrations", 26); err != nil {
		t.Fatalf("migrate to 0026: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO placement_oauth_subjects
		(subject, identity, authorizations, project, mapping_expires_at, updated_at)
		VALUES ('alice@ap.example', 'alice@idp.example', '["READ"]', 'ProjA', 0, 1)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatalf("migrate to head: %v", err)
	}

	var authz, project string
	if err := db.QueryRowContext(ctx, `SELECT authorizations, project FROM placement_oauth_subjects
		WHERE subject = 'alice@ap.example' AND identity = 'alice@idp.example'`).Scan(&authz, &project); err != nil {
		t.Fatalf("the existing row did not survive the upgrade: %v", err)
	}
	if authz != `["READ"]` || project != "ProjA" {
		t.Errorf("existing row = %q %q", authz, project)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO placement_oauth_subjects
		(subject, identity, authorizations, project, mapping_expires_at, updated_at)
		VALUES ('alice@ap.example', 'carol@idp.example', '["READ","WRITE"]', 'ProjC', 0, 2)`); err != nil {
		t.Fatalf("a second identity of the account: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO placement_oauth_subjects
		(subject, identity, authorizations, project, mapping_expires_at, updated_at)
		VALUES ('alice@ap.example', 'carol@idp.example', '[]', '', 0, 3)`); err == nil {
		t.Error("a second row for the same subject and identity was accepted")
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM placement_oauth_subjects WHERE subject = 'alice@ap.example'`).Scan(&n); err != nil || n != 2 {
		t.Errorf("rows for the account = %d %v, want 2", n, err)
	}
}
