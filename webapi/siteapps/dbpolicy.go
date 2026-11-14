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
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Policy an administrator set through the web interface.
//
// The configuration remains the authority. This exists because an
// access point is not always provisioned by configuration management,
// and because the person who should decide whether a lab's app is
// published is not always the person with root on the access point.

// Upload is one administrator-published app.
type Upload struct {
	AppID       string
	Groups      []string
	Home        bool
	Enabled     bool
	Name        string
	Description string
	Icon        string
	UploadedBy  string
	UploadedAt  time.Time
	Digest      string
	SizeBytes   int64

	// SourceRepo, SourceRef and SourceAsset are where the bundle came
	// from, for one the server fetched rather than one handed over as
	// bytes. Empty for an uploaded file: nothing about it says where
	// it was built.
	//
	// SourceRef is the tag that was resolved, never the word
	// "latest" -- a row saying "latest" would compare equal to every
	// future release, and the update check would never fire.
	SourceRepo  string
	SourceRef   string
	SourceAsset string
}

// DBPolicy reads policy from the uploads table.
//
// The table is small -- one row per uploaded app -- and read on every
// rescan, so it is kept in memory and refreshed by Refresh rather than
// queried per lookup. Policy lookups happen inside a scan that is
// already holding the library's lock; going to the database there would
// put a query on that path for every bundle in the directory.
type DBPolicy struct {
	db   *sql.DB
	snap atomic.Pointer[map[string]Policy]
}

// NewDBPolicy returns a source over db, or nil when db is nil.
func NewDBPolicy(db *sql.DB) *DBPolicy {
	if db == nil {
		return nil
	}
	p := &DBPolicy{db: db}
	empty := map[string]Policy{}
	p.snap.Store(&empty)
	return p
}

// Refresh re-reads the table. Called before a scan.
//
// On failure the previous snapshot is kept and the error returned: an
// unreadable database must not silently withdraw every uploaded app,
// which would take a lab's interface down over a transient fault.
func (p *DBPolicy) Refresh(ctx context.Context) error {
	if p == nil || p.db == nil {
		return nil
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT app_id, app_groups, home, enabled, name, description, icon
		  FROM site_app_uploads`)
	if err != nil {
		return fmt.Errorf("site app uploads: %w", err)
	}
	defer func() { _ = rows.Close() }()

	next := map[string]Policy{}
	for rows.Next() {
		var (
			id, groups, name, desc, icon string
			home, enabled                int
		)
		if err := rows.Scan(&id, &groups, &home, &enabled, &name, &desc, &icon); err != nil {
			return fmt.Errorf("site app uploads: %w", err)
		}
		h, e := home != 0, enabled != 0
		next[id] = Policy{
			Groups:      ParseGroupList(groups),
			Home:        &h,
			Enabled:     &e,
			Name:        name,
			Description: desc,
			Icon:        icon,
			Origin:      OriginUpload,
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("site app uploads: %w", err)
	}
	p.snap.Store(&next)
	return nil
}

// OriginUpload marks a policy an administrator set through the web
// interface, as against one read from the configuration.
const OriginUpload = "uploaded through the web interface"

// Policy implements PolicySource.
func (p *DBPolicy) Policy(id string) (Policy, bool) {
	if p == nil {
		return Policy{}, false
	}
	m := p.snap.Load()
	if m == nil {
		return Policy{}, false
	}
	pol, ok := (*m)[id]
	if !ok || len(pol.Groups) == 0 {
		return Policy{}, false
	}
	return pol, true
}

// DeclaredIDs implements PolicySource, in the macro spelling the
// loader compares against so that a chained source's answers are
// comparable with the configuration's.
func (p *DBPolicy) DeclaredIDs() []string {
	if p == nil {
		return nil
	}
	m := p.snap.Load()
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(*m))
	for id, pol := range *m {
		if len(pol.Groups) > 0 {
			out = append(out, MacroID(id))
		}
	}
	sort.Strings(out)
	return out
}

// Chain is several policy sources consulted in order: the first that
// declares an app decides it, entirely.
//
// The order is the precedence, and the only order used puts the
// configuration first. An uploaded policy for an id the configuration
// names is not merged with it and does not override it -- it is not
// consulted at all. Merging would mean an administrator could widen
// the groups on an app the operator had scoped, which is exactly what
// keeping policy in the configuration is for; and the upload path
// refuses such an id outright so that the situation is reported rather
// than silently ignored here.
type Chain []PolicySource

// Policy implements PolicySource.
func (c Chain) Policy(id string) (Policy, bool) {
	for _, s := range c {
		if s == nil {
			continue
		}
		if p, ok := s.Policy(id); ok {
			return p, true
		}
	}
	return Policy{}, false
}

// Refresh re-reads every member that has something to re-read.
//
// Without this the loader's refresh hook finds a Chain, which has no
// Refresh of its own, and the database-backed member inside it is
// never read: uploads would be accepted, written and recorded, and
// then never published, with nothing in the log to say why. The hook
// looks at the source it was given, and in every real deployment that
// source is this type.
func (c Chain) Refresh(ctx context.Context) error {
	var firstErr error
	for _, s := range c {
		r, ok := s.(interface{ Refresh(context.Context) error })
		if !ok {
			continue
		}
		if err := r.Refresh(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// DeclaredIDs implements PolicySource: the union, deduplicated.
func (c Chain) DeclaredIDs() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range c {
		if s == nil {
			continue
		}
		for _, id := range s.DeclaredIDs() {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}

// UploadStore reads and writes administrator-published apps.
type UploadStore struct{ db *sql.DB }

// NewUploadStore returns a store over db, or nil when db is nil.
func NewUploadStore(db *sql.DB) *UploadStore {
	if db == nil {
		return nil
	}
	return &UploadStore{db: db}
}

// Put records an uploaded app's policy, replacing any previous one.
func (s *UploadStore) Put(ctx context.Context, u Upload) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("no database is configured to record uploaded apps")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO site_app_uploads
			(app_id, app_groups, home, enabled, name, description, icon,
			 uploaded_by, uploaded_at, digest, size_bytes,
			 source_repo, source_ref, source_asset)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(app_id) DO UPDATE SET
			app_groups=excluded.app_groups, home=excluded.home, enabled=excluded.enabled,
			name=excluded.name, description=excluded.description, icon=excluded.icon,
			uploaded_by=excluded.uploaded_by, uploaded_at=excluded.uploaded_at,
			digest=excluded.digest, size_bytes=excluded.size_bytes,
			source_repo=excluded.source_repo, source_ref=excluded.source_ref,
			source_asset=excluded.source_asset`,
		u.AppID, strings.Join(u.Groups, ","), boolToInt(u.Home), boolToInt(u.Enabled),
		u.Name, u.Description, u.Icon, u.UploadedBy, u.UploadedAt.Unix(), u.Digest, u.SizeBytes,
		u.SourceRepo, u.SourceRef, u.SourceAsset)
	if err != nil {
		return fmt.Errorf("record uploaded app %q: %w", u.AppID, err)
	}
	return nil
}

// Get returns one uploaded app's record, and whether there is one.
//
// A row apiece rather than List plus a scan by the caller: the config
// editor reads one app, and the settings it does not change have to be
// carried across from the row that is already there.
func (s *UploadStore) Get(ctx context.Context, id string) (Upload, bool, error) {
	if s == nil || s.db == nil {
		return Upload{}, false, nil
	}
	var (
		u             Upload
		groups        string
		home, enabled int
		at            int64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT app_id, app_groups, home, enabled, name, description, icon,
		       uploaded_by, uploaded_at, digest, size_bytes,
		       source_repo, source_ref, source_asset
		  FROM site_app_uploads WHERE app_id = ?`, id).
		Scan(&u.AppID, &groups, &home, &enabled, &u.Name, &u.Description, &u.Icon,
			&u.UploadedBy, &at, &u.Digest, &u.SizeBytes,
			&u.SourceRepo, &u.SourceRef, &u.SourceAsset)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Upload{}, false, nil
	case err != nil:
		return Upload{}, false, fmt.Errorf("read uploaded app %q: %w", id, err)
	}
	u.Groups, u.Home, u.Enabled, u.UploadedAt = ParseGroupList(groups), home != 0, enabled != 0, time.Unix(at, 0)
	return u, true, nil
}

// Delete forgets an uploaded app's policy. It does not remove the
// bundle; the caller does that, and does it second, so a failure
// leaves a bundle nothing publishes rather than a published bundle
// nobody has a record of.
func (s *UploadStore) Delete(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM site_app_uploads WHERE app_id = ?`, id); err != nil {
		return fmt.Errorf("forget uploaded app %q: %w", id, err)
	}
	return nil
}

// List returns every uploaded app, by id.
func (s *UploadStore) List(ctx context.Context) ([]Upload, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT app_id, app_groups, home, enabled, name, description, icon,
		       uploaded_by, uploaded_at, digest, size_bytes,
		       source_repo, source_ref, source_asset
		  FROM site_app_uploads ORDER BY app_id`)
	if err != nil {
		return nil, fmt.Errorf("list uploaded apps: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Upload
	for rows.Next() {
		var (
			u             Upload
			groups        string
			home, enabled int
			at            int64
		)
		if err := rows.Scan(&u.AppID, &groups, &home, &enabled, &u.Name, &u.Description, &u.Icon,
			&u.UploadedBy, &at, &u.Digest, &u.SizeBytes,
			&u.SourceRepo, &u.SourceRef, &u.SourceAsset); err != nil {
			return nil, fmt.Errorf("list uploaded apps: %w", err)
		}
		u.Groups, u.Home, u.Enabled, u.UploadedAt = ParseGroupList(groups), home != 0, enabled != 0, time.Unix(at, 0)
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list uploaded apps: %w", err)
	}
	return out, nil
}
