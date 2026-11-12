// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/siteapps"
)

// auditDB opens a migrated application database.
func auditDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := appdb.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// incarnations reads an app's records oldest first.
func incarnations(t *testing.T, db *sql.DB, appID string) []struct {
	Digest, Groups string
	First, Last    int64
	Version        string
	DigestDeclared int
} {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `
		SELECT digest, app_groups, first_seen, last_seen, version, digest_declared
		  FROM site_app_incarnations WHERE app_id = ? ORDER BY id`, appID)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []struct {
		Digest, Groups string
		First, Last    int64
		Version        string
		DigestDeclared int
	}
	for rows.Next() {
		var r struct {
			Digest, Groups string
			First, Last    int64
			Version        string
			DigestDeclared int
		}
		if err := rows.Scan(&r.Digest, &r.Groups, &r.First, &r.Last, &r.Version, &r.DigestDeclared); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

func observe(t *testing.T, r *siteapps.SQLRecorder, at time.Time, apps ...siteapps.Incarnation) {
	t.Helper()
	if err := r.Observe(context.Background(), at, apps); err != nil {
		t.Fatalf("observe: %v", err)
	}
}

// A scan that finds nothing changed extends the open record rather than
// writing another one. Without this the table grows by one row per app
// per reload interval, which is tens of thousands of rows a year saying
// the same thing.
func TestUnchangedAppExtendsOneRecord(t *testing.T) {
	db := auditDB(t)
	rec := siteapps.NewSQLRecorder(db)
	app := siteapps.Incarnation{
		AppID: "cryoem", Digest: "aaa", BundleKind: "zip", SizeBytes: 10,
		Version: "1.0.0", Groups: []string{"smith_lab"}, Origin: "HTTP_API_SITE_APP_CRYOEM_GROUPS",
	}

	base := time.Unix(1_700_000_000, 0)
	observe(t, rec, base, app)
	observe(t, rec, base.Add(time.Minute), app)
	observe(t, rec, base.Add(2*time.Minute), app)

	got := incarnations(t, db, "cryoem")
	if len(got) != 1 {
		t.Fatalf("records = %d, want 1 extended record: %+v", len(got), got)
	}
	if got[0].First != base.Unix() {
		t.Errorf("first_seen = %d, want the first sighting %d", got[0].First, base.Unix())
	}
	if want := base.Add(2 * time.Minute).Unix(); got[0].Last != want {
		t.Errorf("last_seen = %d, want the latest sighting %d", got[0].Last, want)
	}
}

// A replaced bundle is a new record, and the old one keeps the
// last_seen it had: that is what says when it stopped being served.
func TestReplacedBundleOpensANewRecord(t *testing.T) {
	db := auditDB(t)
	rec := siteapps.NewSQLRecorder(db)
	v1 := siteapps.Incarnation{AppID: "cryoem", Digest: "aaa", BundleKind: "zip", Version: "1.0.0", Groups: []string{"smith_lab"}}
	v2 := v1
	v2.Digest, v2.Version = "bbb", "2.0.0"

	base := time.Unix(1_700_000_000, 0)
	observe(t, rec, base, v1)
	observe(t, rec, base.Add(time.Minute), v1)
	observe(t, rec, base.Add(2*time.Minute), v2)

	got := incarnations(t, db, "cryoem")
	if len(got) != 2 {
		t.Fatalf("records = %d, want 2: %+v", len(got), got)
	}
	if got[0].Last != base.Add(time.Minute).Unix() {
		t.Errorf("the replaced record's last_seen moved to %d; it must say when it stopped", got[0].Last)
	}
	if got[1].Digest != "bbb" || got[1].Version != "2.0.0" {
		t.Errorf("new record = %+v, want the replacement's digest and version", got[1])
	}
	if got[1].First != base.Add(2*time.Minute).Unix() {
		t.Errorf("new record first_seen = %d, want when it appeared", got[1].First)
	}
}

// Rolling back to a bundle that ran before is a third record, not a
// reopening of the first. The first record is a statement about a
// period, and stretching it over the gap would make it false.
func TestRevertingOpensAThirdRecord(t *testing.T) {
	db := auditDB(t)
	rec := siteapps.NewSQLRecorder(db)
	v1 := siteapps.Incarnation{AppID: "cryoem", Digest: "aaa", BundleKind: "zip", Groups: []string{"smith_lab"}}
	v2 := v1
	v2.Digest = "bbb"

	base := time.Unix(1_700_000_000, 0)
	observe(t, rec, base, v1)
	observe(t, rec, base.Add(time.Minute), v2)
	observe(t, rec, base.Add(2*time.Minute), v1)

	got := incarnations(t, db, "cryoem")
	if len(got) != 3 {
		t.Fatalf("records = %d, want 3: %+v", len(got), got)
	}
	if got[0].Digest != "aaa" || got[1].Digest != "bbb" || got[2].Digest != "aaa" {
		t.Errorf("digests = %q/%q/%q, want aaa, bbb, aaa", got[0].Digest, got[1].Digest, got[2].Digest)
	}
}

// The policy is part of what a record states, so a group change opens a
// new one even though the artifact is identical. "Who could see this in
// October?" is the question the audit trail exists for, and the
// configuration it was read from is not versioned.
func TestPolicyChangeOpensANewRecord(t *testing.T) {
	db := auditDB(t)
	rec := siteapps.NewSQLRecorder(db)
	before := siteapps.Incarnation{AppID: "cryoem", Digest: "aaa", BundleKind: "zip", Groups: []string{"smith_lab"}}
	after := before
	after.Groups = []string{"smith_lab", "jones_lab"}

	base := time.Unix(1_700_000_000, 0)
	observe(t, rec, base, before)
	observe(t, rec, base.Add(time.Minute), after)

	got := incarnations(t, db, "cryoem")
	if len(got) != 2 {
		t.Fatalf("records = %d, want 2: %+v", len(got), got)
	}
	if got[0].Groups != "smith_lab" || got[1].Groups != "smith_lab,jones_lab" {
		t.Errorf("groups = %q then %q, want the widening recorded", got[0].Groups, got[1].Groups)
	}
}

// An app that stops being served is simply not mentioned again. Its
// record keeps its last_seen, which is how the trail says when it went
// away -- there is no tombstone to write.
func TestWithdrawnAppKeepsItsLastSeen(t *testing.T) {
	db := auditDB(t)
	rec := siteapps.NewSQLRecorder(db)
	gone := siteapps.Incarnation{AppID: "gone", Digest: "aaa", BundleKind: "zip", Groups: []string{"lab"}}
	stays := siteapps.Incarnation{AppID: "stays", Digest: "bbb", BundleKind: "zip", Groups: []string{"lab"}}

	base := time.Unix(1_700_000_000, 0)
	observe(t, rec, base, gone, stays)
	observe(t, rec, base.Add(time.Minute), stays)

	got := incarnations(t, db, "gone")
	if len(got) != 1 {
		t.Fatalf("records = %d, want 1: %+v", len(got), got)
	}
	if got[0].Last != base.Unix() {
		t.Errorf("last_seen = %d, want the last time it was actually served %d", got[0].Last, base.Unix())
	}
}

// An unverified bundle is recorded as such. The digest is the bytes we
// found; digest_declared says whether anybody vouched for them, and
// collapsing the two would lose the difference.
func TestAttestationIsRecordedSeparatelyFromTheDigest(t *testing.T) {
	db := auditDB(t)
	rec := siteapps.NewSQLRecorder(db)
	base := time.Unix(1_700_000_000, 0)
	observe(t, rec, base, siteapps.Incarnation{
		AppID: "cryoem", Digest: "aaa", BundleKind: "zip", Groups: []string{"lab"}, DigestKnown: false,
	})
	observe(t, rec, base.Add(time.Minute), siteapps.Incarnation{
		AppID: "cryoem", Digest: "aaa", BundleKind: "zip", Groups: []string{"lab"}, DigestKnown: true,
	})

	got := incarnations(t, db, "cryoem")
	if len(got) != 2 {
		t.Fatalf("records = %d, want 2 -- gaining a .sha256 is a change worth recording: %+v", len(got), got)
	}
	if got[0].DigestDeclared != 0 || got[1].DigestDeclared != 1 {
		t.Errorf("digest_declared = %d then %d, want 0 then 1", got[0].DigestDeclared, got[1].DigestDeclared)
	}
}
