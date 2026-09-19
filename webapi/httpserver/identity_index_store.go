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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bbockelm/golang-htcondor/idmap"
)

// identityIndexStore keeps the last complete GECOS index in the
// application database so a restarted daemon can answer from it while the
// directory is still unreadable.
//
// See migrations/0008_identity_index.sql for why this exists and why it
// is only ever a cache.
type identityIndexStore struct {
	db *sql.DB
}

func newIdentityIndexStore(db *sql.DB) *identityIndexStore {
	if db == nil {
		return nil
	}
	return &identityIndexStore{db: db}
}

// Load returns the saved index, and whether there was one.
//
// A row that cannot be decoded is reported as absent rather than as an
// error: the daemon's job is to start, and an unreadable cache costs a
// slower first few minutes, not a failure.
func (s *identityIndexStore) Load(ctx context.Context) (idmap.Snapshot, bool, error) {
	if s == nil || s.db == nil {
		return idmap.Snapshot{}, false, nil
	}
	var blob string
	err := s.db.QueryRowContext(ctx,
		`SELECT snapshot FROM identity_index WHERE id = 1`).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return idmap.Snapshot{}, false, nil
	}
	if err != nil {
		return idmap.Snapshot{}, false, fmt.Errorf("reading the saved account index: %w", err)
	}

	var snap idmap.Snapshot
	if err := json.Unmarshal([]byte(blob), &snap); err != nil {
		return idmap.Snapshot{}, false, fmt.Errorf("decoding the saved account index: %w", err)
	}
	if len(snap.ByGecos) == 0 {
		return idmap.Snapshot{}, false, nil
	}
	return snap, true, nil
}

// Save replaces the stored index.
func (s *identityIndexStore) Save(ctx context.Context, snap idmap.Snapshot) error {
	if s == nil || s.db == nil {
		return nil
	}
	blob, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("encoding the account index: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO identity_index (id, snapshot, built_at, updated_at)
		 VALUES (1, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   snapshot = excluded.snapshot,
		   built_at = excluded.built_at,
		   updated_at = excluded.updated_at`,
		string(blob), snap.BuiltAt, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("saving the account index: %w", err)
	}
	return nil
}
