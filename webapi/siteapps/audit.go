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

package siteapps

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// What this access point has served, and when.
//
// The configuration says what an operator intends. This says what the
// server did, which is a different question and the only one an audit
// can ask about the past: a configuration file describes now, and a
// bundle replaced in place leaves nothing behind at all.
//
// A record is an INCARNATION -- one app, served from one artifact,
// under one policy, over a period. A scan that finds everything
// unchanged extends the open record rather than writing a new one, so
// this costs a handful of rows per app per year instead of one per
// scan.

// Incarnation is one app as a scan observed it.
type Incarnation struct {
	AppID       string
	Digest      string
	BundleKind  string // "zip" or "directory"
	SizeBytes   int64
	DigestKnown bool   // a .sha256 sidecar was present and matched
	Version     string // the bundle's own labels
	Revision    string
	Name        string
	Description string
	Icon        string
	Groups      []string
	Home        bool
	Origin      string // where the policy came from
}

// sameAs reports whether two observations describe the same
// incarnation, i.e. whether the later one extends the earlier record
// rather than starting a new one.
//
// Everything compared here is either the artifact or the policy. The
// name and description are derived from those two, so they cannot
// differ without one of these differing, and comparing them as well
// would only add ways to split a record for no reason.
func (i Incarnation) sameAs(o Incarnation) bool {
	return i.AppID == o.AppID &&
		i.Digest == o.Digest &&
		i.BundleKind == o.BundleKind &&
		i.SizeBytes == o.SizeBytes &&
		i.DigestKnown == o.DigestKnown &&
		i.Version == o.Version &&
		i.Revision == o.Revision &&
		i.Home == o.Home &&
		i.Origin == o.Origin &&
		strings.Join(i.Groups, ",") == strings.Join(o.Groups, ",")
}

// Recorder keeps the record of what was served.
//
// An interface so the library can be built without a database -- the
// demo server and most tests have none -- and so recording cannot
// become a reason a scan fails. A nil Recorder records nothing.
type Recorder interface {
	// Observe notes that these apps were being served at this moment.
	Observe(ctx context.Context, at time.Time, apps []Incarnation) error
}

// SQLRecorder writes incarnations to the application database.
type SQLRecorder struct{ db *sql.DB }

// NewSQLRecorder returns a recorder over db, or nil when db is nil.
func NewSQLRecorder(db *sql.DB) *SQLRecorder {
	if db == nil {
		return nil
	}
	return &SQLRecorder{db: db}
}

// Observe implements Recorder.
//
// For each app: if the newest record for it describes the same
// incarnation, its last_seen moves forward; otherwise a new record
// opens. An app that has stopped being served is simply not mentioned,
// and its record keeps the last_seen it had -- which is what says when
// it stopped.
func (r *SQLRecorder) Observe(ctx context.Context, at time.Time, apps []Incarnation) error {
	if r == nil || r.db == nil || len(apps) == 0 {
		return nil
	}
	now := at.Unix()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("site app audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, app := range apps {
		cur, id, err := newestIncarnation(ctx, tx, app.AppID)
		if err != nil {
			return err
		}
		if id != 0 && cur.sameAs(app) {
			if _, err := tx.ExecContext(ctx,
				`UPDATE site_app_incarnations SET last_seen = ? WHERE id = ?`, now, id); err != nil {
				return fmt.Errorf("site app audit: extend %q: %w", app.AppID, err)
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO site_app_incarnations
				(app_id, digest, bundle_kind, size_bytes, digest_declared,
				 version, revision, name, description, icon,
				 app_groups, home, policy_origin, first_seen, last_seen)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			app.AppID, app.Digest, app.BundleKind, app.SizeBytes, boolToInt(app.DigestKnown),
			app.Version, app.Revision, app.Name, app.Description, app.Icon,
			strings.Join(app.Groups, ","), boolToInt(app.Home), app.Origin, now, now,
		); err != nil {
			return fmt.Errorf("site app audit: record %q: %w", app.AppID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("site app audit: commit: %w", err)
	}
	return nil
}

// newestIncarnation reads the most recent record for an app, and its
// row id. A zero id means there is none.
func newestIncarnation(ctx context.Context, tx *sql.Tx, appID string) (Incarnation, int64, error) {
	var (
		inc            Incarnation
		id             int64
		groups         string
		home, declared int
	)
	err := tx.QueryRowContext(ctx, `
		SELECT id, app_id, digest, bundle_kind, size_bytes, digest_declared,
		       version, revision, name, description, icon,
		       app_groups, home, policy_origin
		  FROM site_app_incarnations
		 WHERE app_id = ?
		 ORDER BY last_seen DESC, id DESC
		 LIMIT 1`, appID).
		Scan(&id, &inc.AppID, &inc.Digest, &inc.BundleKind, &inc.SizeBytes, &declared,
			&inc.Version, &inc.Revision, &inc.Name, &inc.Description, &inc.Icon,
			&groups, &home, &inc.Origin)
	switch {
	case err == sql.ErrNoRows:
		return Incarnation{}, 0, nil
	case err != nil:
		return Incarnation{}, 0, fmt.Errorf("site app audit: read %q: %w", appID, err)
	}
	inc.Home = home != 0
	inc.DigestKnown = declared != 0
	if groups != "" {
		inc.Groups = strings.Split(groups, ",")
	}
	return inc, id, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Record is one incarnation as the audit trail holds it.
type Record struct {
	Incarnation
	FirstSeen time.Time
	LastSeen  time.Time
}

// History returns an app's incarnations, most recent first.
//
// A free function over *sql.DB rather than a method on SQLRecorder:
// reading the trail is something the administrator's pages do, and
// they have the database without having the recorder the scan writes
// through.
func History(ctx context.Context, db *sql.DB, appID string) ([]Record, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT digest, bundle_kind, size_bytes, digest_declared,
		       version, revision, name, description, icon,
		       app_groups, home, policy_origin, first_seen, last_seen
		  FROM site_app_incarnations
		 WHERE app_id = ?
		 ORDER BY first_seen DESC, id DESC`, appID)
	if err != nil {
		return nil, fmt.Errorf("site app history %q: %w", appID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []Record
	for rows.Next() {
		var (
			r              Record
			groups         string
			home, declared int
			first, last    int64
		)
		if err := rows.Scan(&r.Digest, &r.BundleKind, &r.SizeBytes, &declared,
			&r.Version, &r.Revision, &r.Name, &r.Description, &r.Icon,
			&groups, &home, &r.Origin, &first, &last); err != nil {
			return nil, fmt.Errorf("site app history %q: %w", appID, err)
		}
		r.AppID, r.Home, r.DigestKnown = appID, home != 0, declared != 0
		r.Groups = ParseGroupList(groups)
		r.FirstSeen, r.LastSeen = time.Unix(first, 0), time.Unix(last, 0)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("site app history %q: %w", appID, err)
	}
	return out, nil
}
