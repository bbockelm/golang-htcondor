package httpserver

import (
	"context"
	"database/sql"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
)

// newTestDB opens a fresh unified application DB at dbPath, runs the
// goose migrations, and registers a t.Cleanup to close it. Use this
// in tests that previously called NewOAuth2Storage(path) /
// NewIDPStorage(path) directly — those constructors now want a
// *sql.DB whose schema is already in place.
//
// Pass an in-tempdir path so the file is cleaned up by t.TempDir's
// own teardown.
func newTestDB(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := appdb.Open(dbPath)
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	if err := appdb.Migrate(context.Background(), db); err != nil {
		_ = db.Close()
		t.Fatalf("appdb.Migrate: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
