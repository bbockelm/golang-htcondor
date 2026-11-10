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

	"github.com/bbockelm/golang-htcondor/internal/privatefile"
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
//
// The database holds browser session keys, OAuth2/IDP signing keys and
// upstream refresh tokens (in plaintext unless HTTP_API_KEK_FILE is
// set), so Open also makes the file and any existing sidecars mode
// 0600 before SQLite sees them; see restrictFileMode.
func Open(path string) (*sql.DB, error) {
	return OpenWithWarnings(path, nil)
}

// WarnFunc receives a message and slog-style key/value pairs.
type WarnFunc func(msg string, args ...any)

// OpenWithWarnings is Open, reporting permission problems that do not
// prevent startup -- a database file that had to be tightened, a
// world-writable parent directory -- through warn. A nil warn drops
// them.
func OpenWithWarnings(path string, warn WarnFunc) (*sql.DB, error) {
	if warn == nil {
		warn = func(string, ...any) {}
	}
	if err := checkPathWritable(path); err != nil {
		return nil, fmt.Errorf("appdb: open %s: %w", path, err)
	}
	if err := restrictFileMode(path, warn); err != nil {
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

// restrictFileMode makes the database file and its existing sidecars
// mode 0600. SQLite creates sidecars with the database file's own
// permissions, so creating the file 0600 here keeps the ones it creates
// later private too; without this SQLite creates the file under the
// process umask (0644 under condor_master).
//
// A file that was group- or world-accessible is tightened with a
// warning, since its contents may already have been read. Open refuses
// only when a file is still world-accessible afterwards (the chmod
// failed, e.g. a file owned by another uid), matching the KEK and SSH
// host-key loaders' refusal of world-accessible secrets; a failure that
// leaves only group bits is a warning.
//
// A world-writable parent directory is a warning, not a refusal: it is
// not the default layout, and refusing would turn an operator's
// unusual-but-working setup into an outage. World-readable directories
// (the default 0755 LOCAL_DIR/lib/condor) are not flagged; with the
// file 0600 they expose only its name.
func restrictFileMode(path string, warn WarnFunc) error {
	files := privatefile.SQLiteFiles(path)
	loose := map[string]os.FileMode{}
	for _, p := range files {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
			loose[p] = fi.Mode().Perm()
		}
	}

	if chmodErr := privatefile.EnsureSQLite(path, 0o600); chmodErr != nil {
		for _, p := range files {
			if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o007 != 0 {
				return fmt.Errorf("database file %s is world-accessible (mode %#o) and could not be restricted to 0600: %w; chown it to the daemon user or chmod 0600 it", p, fi.Mode().Perm(), chmodErr)
			}
		}
		warn("could not restrict application database permissions to 0600", "path", path, "err", chmodErr)
	}
	for _, p := range files {
		perm, ok := loose[p]
		if !ok {
			continue
		}
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 == 0 {
			warn("tightened application database file mode to 0600; it was readable by other local users, so consider rotating the keys it holds",
				"path", p, "previous_mode", fmt.Sprintf("%#o", perm))
		}
	}

	parent := filepath.Dir(path)
	if fi, err := os.Stat(parent); err == nil && fi.Mode().Perm()&0o002 != 0 {
		warn("application database directory is world-writable; other local users can replace or remove the database",
			"dir", parent, "mode", fmt.Sprintf("%#o", fi.Mode().Perm()))
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
