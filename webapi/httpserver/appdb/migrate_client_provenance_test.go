package appdb

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

// The provenance migration adds columns to a table that already has rows
// on every existing deployment, and backfills one of them from the id
// format. A fresh-database test would never exercise that: it is the
// UPGRADE that can go wrong, so this test stops at the previous
// migration, seeds the rows an existing install would have, and then
// migrates the rest of the way.
func TestClientProvenanceMigrationBackfill(t *testing.T) {
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

	// Stop just before the provenance migration.
	if err := goose.UpToContext(ctx, db, "migrations", 4); err != nil {
		t.Fatalf("migrate to 0004: %v", err)
	}

	// Rows as an existing install would have them, including ids chosen
	// to catch a backfill predicate that is too loose.
	ids := []string{
		"client_1700000000000000000", // what our register handler generates
		"client_1",                   // same shape, short
		"swagger-client",             // the one this server seeds
		"clientX1700000000",          // LIKE's "_" wildcard would match this
		"client_abc",                 // underscore but not digits
		"some-hand-made-client",
	}
	for _, id := range ids {
		if _, err := db.ExecContext(ctx, `INSERT INTO oauth2_clients
			(id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
			VALUES (?, '', '[]', '[]', '[]', '[]', 0)`, id); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatalf("migrate to head: %v", err)
	}

	want := map[string]string{
		"client_1700000000000000000": "dynamic",
		"client_1":                   "dynamic",
		"swagger-client":             "seeded",
		// Not our generated format: the answer is unknown, and claiming
		// otherwise would be a guess dressed as a fact.
		"clientX1700000000":     "",
		"client_abc":            "",
		"some-hand-made-client": "",
	}
	for id, wantOrigin := range want {
		var origin, name, notes, recentUsers string
		var lastUsed sql.NullTime
		err := db.QueryRowContext(ctx,
			`SELECT origin, client_name, notes, last_used_at, recent_users
			 FROM oauth2_clients WHERE id = ?`, id).
			Scan(&origin, &name, &notes, &lastUsed, &recentUsers)
		if err != nil {
			t.Fatalf("read back %s: %v", id, err)
		}
		if origin != wantOrigin {
			t.Errorf("%s: origin = %q, want %q", id, origin, wantOrigin)
		}
		// The other new columns must be usable defaults, not NULLs that
		// would break the admin list's scan.
		if name != "" || notes != "" || recentUsers != "" {
			t.Errorf("%s: expected empty defaults, got name=%q notes=%q recent=%q",
				id, name, notes, recentUsers)
		}
		if lastUsed.Valid {
			t.Errorf("%s: last_used_at should start NULL, got %v", id, lastUsed.Time)
		}
	}
}

// Migrating an empty database to head must work too -- that is every
// fresh install -- and the down migration has to actually reverse.
func TestClientProvenanceMigrationIsReversible(t *testing.T) {
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
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	if err := goose.DownContext(ctx, db, "migrations"); err != nil {
		t.Fatalf("migrate down: %v", err)
	}

	// The columns should be gone; selecting one must error.
	var origin string
	err = db.QueryRowContext(ctx, `SELECT origin FROM oauth2_clients LIMIT 1`).Scan(&origin)
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		t.Errorf("origin column still present after down migration (err=%v)", err)
	}

	// And up again, so a down/up cycle is not a one-way door.
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
}
