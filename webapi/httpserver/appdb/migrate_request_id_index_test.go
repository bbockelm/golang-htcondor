package appdb

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// Revocation and the parent-grant liveness check look tokens up by
// request_id; the upgrade indexes it so neither scans the table.
func TestTokenRequestIDIsIndexed(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	for _, table := range []string{"oauth2_access_tokens", "oauth2_refresh_tokens", "idp_access_tokens", "idp_refresh_tokens"} {
		rows, err := db.QueryContext(ctx, "EXPLAIN QUERY PLAN SELECT signature FROM "+table+" WHERE request_id = ?", "r") //nolint:gosec // G202: table is from this test's own literals
		if err != nil {
			t.Fatalf("%s: explain: %v", table, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatalf("%s: scan plan: %v", table, err)
			}
			plan = append(plan, detail)
		}
		_ = rows.Close()
		joined := strings.Join(plan, "; ")
		if !strings.Contains(joined, "USING INDEX") || !strings.Contains(joined, "request_id") {
			t.Errorf("%s: a request_id lookup does not use an index: %s", table, joined)
		}
	}
}
