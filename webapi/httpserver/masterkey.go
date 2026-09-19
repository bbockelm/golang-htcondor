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
	"errors"
	"fmt"
	"time"

	"github.com/PelicanPlatform/classad/collections/crypt"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// identityCookieInfo is the HKDF label that derives the identity cookie's
// signing key from the master key.
//
// Distinct from every other label (classad's DataInfo / BackupInfo, the
// session cache's "session cache") so the derived keys stay independent:
// the same master protects several purposes without any of them being able
// to forge another's.
const identityCookieInfo = "htcondor-api-identity-cookie-v1"

// signingKEKs reads the pool signing keys as key-encryption keys.
//
// htcondor.LoadSigningKeys owns the details -- the 0xdeadbeef unscramble,
// the root reads through droppriv for 0600 root-owned files, skipping keys
// this daemon cannot read -- and is the same source the CCB session cache
// and classad's encryption at rest use.
func signingKEKs(cfg *config.Config) ([]crypt.KEK, error) {
	if cfg == nil {
		return nil, nil
	}
	raw, err := htcondor.LoadSigningKeys(cfg)
	if err != nil {
		return nil, fmt.Errorf("loading pool signing keys: %w", err)
	}
	keks := make([]crypt.KEK, 0, len(raw))
	for id, material := range raw {
		keks = append(keks, crypt.KEK{ID: id, Material: material})
	}
	return keks, nil
}

// openOrCreateMaster recovers the application master key, minting one on
// first use, and adds a wrapping for any signing key not yet represented.
//
// Returns (nil, nil) when there are no signing keys: the deployment has
// nothing to key an envelope with, and the caller must do without whatever
// the master would have protected rather than inventing a key that any
// reader of the database could also derive.
func openOrCreateMaster(ctx context.Context, db *sql.DB, keks []crypt.KEK) ([]byte, error) {
	if db == nil || len(keks) == 0 {
		return nil, nil
	}

	rows, err := loadMasterKeyRows(ctx, db)
	if err != nil {
		return nil, err
	}

	var master []byte
	switch {
	case len(rows) == 0:
		if master, err = crypt.NewMaster(); err != nil {
			return nil, fmt.Errorf("generating the master key: %w", err)
		}
	default:
		master, err = crypt.OpenMaster(rows, keks)
		if errors.Is(err, crypt.ErrNoKey) {
			// Refuse rather than mint a replacement. A new master would
			// silently invalidate everything the old one protects, and the
			// likely cause is a misconfigured SEC_PASSWORD_DIRECTORY --
			// which is recoverable, unlike the data.
			return nil, fmt.Errorf("the stored master key cannot be opened by any available signing key "+
				"(check SEC_PASSWORD_DIRECTORY): %w", err)
		}
		if err != nil {
			return nil, fmt.Errorf("opening the master key: %w", err)
		}
	}

	// Rotation: wrap the master under any key that has no row yet, so a
	// newly added signing key can open the database and an old one can
	// later be withdrawn.
	have := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		have[r.KeyID] = struct{}{}
	}
	for _, k := range keks {
		if _, ok := have[k.ID]; ok {
			continue
		}
		row, err := crypt.WrapMaster(master, k)
		if err != nil {
			return nil, fmt.Errorf("wrapping the master key under %q: %w", k.ID, err)
		}
		if err := saveMasterKeyRow(ctx, db, row); err != nil {
			return nil, err
		}
	}
	return master, nil
}

func loadMasterKeyRows(ctx context.Context, db *sql.DB) ([]crypt.MasterKeyRow, error) {
	rows, err := db.QueryContext(ctx, `SELECT key_id, salt, nonce, wrapped FROM master_keys`)
	if err != nil {
		return nil, fmt.Errorf("reading master keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []crypt.MasterKeyRow
	for rows.Next() {
		var r crypt.MasterKeyRow
		if err := rows.Scan(&r.KeyID, &r.Salt, &r.Nonce, &r.Wrapped); err != nil {
			return nil, fmt.Errorf("reading a master key row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading master keys: %w", err)
	}
	return out, nil
}

func saveMasterKeyRow(ctx context.Context, db *sql.DB, r crypt.MasterKeyRow) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO master_keys (key_id, salt, nonce, wrapped, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(key_id) DO NOTHING`,
		r.KeyID, r.Salt, r.Nonce, r.Wrapped, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("saving the master key wrapping for %q: %w", r.KeyID, err)
	}
	return nil
}
