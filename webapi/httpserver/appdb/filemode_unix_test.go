//go:build unix

package appdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestOpenRestrictsFileMode verifies the application database and its
// sidecars are created 0600 under condor_master's umask of 022 (without
// the fix SQLite creates them 0644), and that a pre-existing looser
// database and sidecar are tightened, with a warning, on reopen.
//
// The umask is process-global, so this test must not run in parallel
// with other file-creating tests.
func TestOpenRestrictsFileMode(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "app.db")

	var warnings []string
	warn := func(msg string, args ...any) {
		warnings = append(warnings, fmt.Sprintln(append([]any{msg}, args...)...))
	}

	db, err := OpenWithWarnings(path, warn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// The server uses the default rollback journal; switch to WAL so a
	// write leaves -wal and -shm on disk to inspect. SQLite gives both
	// the database file's mode.
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode=WAL`); err != nil {
		t.Fatalf("WAL: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO http_sessions (session_id, username, created_at, expires_at) VALUES ('k', 'u', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %#o, want 0600", p, perm)
		}
	}
	if len(warnings) != 0 {
		t.Errorf("fresh database produced warnings: %q", warnings)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// A database and sidecar left loose by an earlier version are
	// tightened on the next open, and the operator is told.
	for _, p := range []string{path, path + "-wal"} {
		if _, err := os.Stat(p); err != nil {
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatalf("create %s: %v", p, err)
			}
		}
		if err := os.Chmod(p, 0o644); err != nil { //nolint:gosec // G302: deliberately loosening to test tightening
			t.Fatal(err)
		}
	}
	db, err = OpenWithWarnings(path, warn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()
	for _, p := range []string{path, path + "-wal"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("reopen left %s at %#o, want 0600", p, perm)
		}
		found := false
		for _, w := range warnings {
			if strings.Contains(w, "tightened") && strings.Contains(w, p+" ") {
				found = true
			}
		}
		if !found {
			t.Errorf("no tightening warning for %s; warnings: %q", p, warnings)
		}
	}
}

// TestOpenWarnsWorldWritableDir verifies a world-writable parent
// directory is reported but does not stop the database from opening.
func TestOpenWarnsWorldWritableDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // G302: deliberately world-writable for the test
		t.Fatal(err)
	}
	var warnings []string
	db, err := OpenWithWarnings(filepath.Join(dir, "app.db"), func(msg string, _ ...any) { warnings = append(warnings, msg) })
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = db.Close()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "world-writable") {
		t.Fatalf("warnings = %q, want one world-writable warning", warnings)
	}
}
