package appdb

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

// A service key must still be a service key after a downgrade and a
// re-upgrade.
//
// 0030's down migration rebuilds api_keys to drop the columns SQLite
// cannot DROP, so anything the rebuild forgets is lost without a word.
// The loss is quiet in the worst way: a service key demoted to an
// ordinary key keeps authenticating, and its entitlement lapses an hour
// later for reasons nothing connects to the rollback.
func TestServiceKeySurvivesDownAndUp(t *testing.T) {
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
		t.Fatalf("up: %v", err)
	}

	if _, err := db.ExecContext(ctx,
		`INSERT INTO api_keys (key_id, secret_hash, name, scopes_json, creator, service)
		 VALUES ('svc000000001','h','automation','["ap:read"]','alice',1),
		        ('ord000000001','h','mine','["metrics"]','alice',0)`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	if err := goose.DownToContext(ctx, db, "migrations", 29); err != nil {
		t.Fatalf("down to 0029: %v", err)
	}
	// The keys themselves must survive the rollback: a downgrade that
	// logs everybody's automation out is worse than the bug it rolls
	// back.
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_keys`).Scan(&n); err != nil {
		t.Fatalf("count after down: %v", err)
	}
	if n != 2 {
		t.Fatalf("api_keys lost rows on downgrade: %d of 2 remain", n)
	}

	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	var service int
	if err := db.QueryRowContext(ctx,
		`SELECT service FROM api_keys WHERE key_id='svc000000001'`).Scan(&service); err != nil {
		t.Fatalf("select: %v", err)
	}
	if service != 1 {
		t.Errorf("service=%d after down+up: the key was silently demoted to an ordinary key, "+
			"so its entitlement will lapse once the staleness window passes", service)
	}
}
