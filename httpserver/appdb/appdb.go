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
	"fmt"

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
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("appdb: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
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
