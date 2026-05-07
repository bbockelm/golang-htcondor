// Package appdb owns the single SQLite database the HTTP API server
// uses for OAuth2/MCP storage, the embedded IDP, browser sessions, and
// user-saved batch-submission templates. Previously each subsystem
// opened its own SQLite file under LOCAL_DIR, but that meant adding a
// new feature (templates) silently failed the whole server when its
// directory wasn't writable, while the OAuth2 DB worked fine. Folding
// them all into one file removes that asymmetry.
//
// Schema evolution is managed with pressly/goose against the embedded
// migration files in the migrations/ subdirectory. Add a new
// numbered file with the standard goose `-- +goose Up` header and
// Migrate() will pick it up at next startup.
package appdb

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/glebarez/sqlite" // SQLite driver (pure Go, no CGO)
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Open opens (or creates) the SQLite database at path and returns a
// *sql.DB ready for the various storage layers to share. The file is
// not migrated yet — the caller must call Migrate before using it.
//
// We pin max-open to 1: SQLite serializes writes anyway, and the
// schema-create step relies on serial DDL to avoid the "database is
// locked" symptom that pops up under concurrent writers.
//
// Open does an eager writability check on the parent directory and
// (when the file already exists) on the file itself. SQLite's pure-Go
// driver returns the cryptic "out of memory (14)" for any open
// failure, including "permission denied" and "directory doesn't
// exist" — which on a misconfigured deployment looks like an
// allocator problem but is really a filesystem ACL issue. By
// probing here we surface a real "directory not writable" error
// before sql.Open lazily tries to write.
func Open(path string) (*sql.DB, error) {
	if err := checkPathWritable(path); err != nil {
		return nil, fmt.Errorf("appdb: open %s: %w", path, err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("appdb: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// checkPathWritable verifies (a) the parent directory exists and is
// writable, (b) when the DB file is already there, that we can open
// it for writing. Returns errors with operator-actionable text —
// "parent directory %s does not exist", "parent directory %s is not
// writable (mode %#o, uid=%d)", etc. — to replace SQLite's
// notoriously misleading "out of memory (14)" on permission denials.
func checkPathWritable(path string) error {
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("parent directory %s does not exist; create it (e.g. mkdir -p %s) and ensure the daemon user can write to it", parent, parent)
	}
	if err != nil {
		return fmt.Errorf("stat parent directory %s: %w", parent, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("parent path %s is not a directory", parent)
	}

	// Probe write access. We can't trust mode bits alone — the
	// effective uid/gid + mount options (read-only bind mount, …)
	// matter too. Creating a temp file in the directory exercises
	// every layer.
	probe, err := os.CreateTemp(parent, ".appdb-writable-probe-*")
	if err != nil {
		return fmt.Errorf("parent directory %s is not writable by the daemon user: %w; ensure HTTP_API_DB_PATH points at a directory the running uid can write to", parent, err)
	}
	probeName := probe.Name()
	_ = probe.Close()
	_ = os.Remove(probeName)

	// If the DB file already exists, ensure we can open it for
	// writing — covers the case of a leftover file owned by a
	// different uid in the same writable directory.
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // path is operator-controlled DB location
		if err != nil {
			return fmt.Errorf("existing database file %s is not writable by the daemon user: %w", path, err)
		}
		_ = f.Close()
	}
	return nil
}

// Migrate runs all pending goose migrations bundled in the migrations/
// subdirectory. Idempotent; safe to call on every startup. Returns an
// error if any migration fails — the caller should refuse to start the
// server in that case rather than serve a partially-migrated DB.
//
// Goose's default logger writes to log.Default(). We route it through
// a Writer that drops everything; the API server's structured logger
// reports the migration outcome via its own log line in NewHandler.
func Migrate(ctx context.Context, db *sql.DB) error {
	goose.SetBaseFS(migrationFS)
	goose.SetTableName("htcondor_api_db_version")
	goose.SetLogger(quietLogger{})
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("appdb: set dialect: %w", err)
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		return fmt.Errorf("appdb: migrate: %w", err)
	}
	return nil
}

// quietLogger satisfies goose.Logger but drops everything. Keeps the
// "goose: successfully migrated…" line off stderr in production where
// the structured logger is the source of truth.
type quietLogger struct{}

func (quietLogger) Fatal(_ ...any)            {}
func (quietLogger) Fatalf(_ string, _ ...any) {}
func (quietLogger) Print(_ ...any)            {}
func (quietLogger) Println(_ ...any)          {}
func (quietLogger) Printf(_ string, _ ...any) {}
