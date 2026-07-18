package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// apiKeyRow is the on-the-wire shape after a SELECT — every field
// the auth handler / admin endpoints care about. We don't expose the
// secret_hash through any HTTP surface; it stays inside this file
// so a future refactor can't accidentally serialize it.
type apiKeyRow struct {
	KeyID      string
	SecretHash string
	Name       string
	Scopes     []string
	Creator    string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	DeletedAt  *time.Time
	LastUsedAt *time.Time
}

// apiKeyStore wraps the api_keys table. The Handler holds one and
// closes over it; we keep the type small (no internal state, just a
// DB handle) so it's easy to fake for tests.
type apiKeyStore struct {
	db *sql.DB
}

// errAPIKeyNotFound is the "this key_id does not exist OR has been
// soft-deleted OR has expired" sentinel. Callers use errors.Is to
// distinguish from real DB errors. We deliberately don't reveal the
// reason to the caller — leaking "this id existed once" to an
// attacker who's enumerating ids is needless detail.
var errAPIKeyNotFound = errors.New("api key not found, expired, or revoked")

// LookupActive resolves a key_id to its active row. Returns
// errAPIKeyNotFound for missing / soft-deleted / expired rows.
// Hot-path: the auth handler calls this on every request that
// presents a Bearer token starting with htca-v1-.
func (s *apiKeyStore) LookupActive(ctx context.Context, keyID string) (*apiKeyRow, error) {
	row := &apiKeyRow{}
	var scopesJSON string
	var expiresAt, deletedAt, lastUsedAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT key_id, secret_hash, name, scopes_json, creator,
		        created_at, expires_at, deleted_at, last_used_at
		   FROM api_keys
		  WHERE key_id = ?`,
		keyID,
	).Scan(
		&row.KeyID, &row.SecretHash, &row.Name, &scopesJSON, &row.Creator,
		&row.CreatedAt, &expiresAt, &deletedAt, &lastUsedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errAPIKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("api_keys lookup: %w", err)
	}
	// Soft-delete and expiry are checked here, not in SQL, so the
	// error surface for "expired" matches the surface for "missing"
	// — auth handlers should not differentiate.
	if deletedAt.Valid {
		return nil, errAPIKeyNotFound
	}
	if expiresAt.Valid && !expiresAt.Time.After(time.Now()) {
		return nil, errAPIKeyNotFound
	}
	if scopesJSON != "" {
		if err := json.Unmarshal([]byte(scopesJSON), &row.Scopes); err != nil {
			return nil, fmt.Errorf("api_keys malformed scopes_json for %s: %w", keyID, err)
		}
	}
	if expiresAt.Valid {
		row.ExpiresAt = &expiresAt.Time
	}
	if lastUsedAt.Valid {
		row.LastUsedAt = &lastUsedAt.Time
	}
	return row, nil
}

// Insert persists a freshly-minted key. The caller has already
// computed the secret hash via apikey.Mint; we just store it.
// Returns the row's created_at as a courtesy (for the create-key
// response). No retry on conflict — key_id collisions are 1-in-2^48,
// not something to engineer for.
func (s *apiKeyStore) Insert(ctx context.Context, keyID, secretHash, name, creator string, scopes []string, expiresAt *time.Time) (time.Time, error) {
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return time.Time{}, fmt.Errorf("api_keys marshal scopes: %w", err)
	}
	now := time.Now().UTC()
	var exp sql.NullTime
	if expiresAt != nil {
		exp = sql.NullTime{Time: *expiresAt, Valid: true}
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO api_keys (key_id, secret_hash, name, scopes_json, creator, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		keyID, secretHash, name, string(scopesJSON), creator, now, exp,
	)
	if err != nil {
		return time.Time{}, fmt.Errorf("api_keys insert: %w", err)
	}
	return now, nil
}

// ListByCreator returns the creator's keys, including soft-deleted
// ones (the admin UI shows them with a strikethrough so a
// freshly-deleted key remains visible for "I just clicked delete by
// mistake — restore?" recovery). Sort by created_at DESC so the
// admin sees their newest first.
//
// We DO NOT return secret_hash. The DTO returned is safe to JSON-
// encode straight to the admin's browser.
func (s *apiKeyStore) ListByCreator(ctx context.Context, creator string) ([]apiKeyRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT key_id, secret_hash, name, scopes_json, creator,
		        created_at, expires_at, deleted_at, last_used_at
		   FROM api_keys
		  WHERE creator = ?
		  ORDER BY created_at DESC`,
		creator,
	)
	if err != nil {
		return nil, fmt.Errorf("api_keys list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []apiKeyRow
	for rows.Next() {
		var r apiKeyRow
		var scopesJSON string
		var expiresAt, deletedAt, lastUsedAt sql.NullTime
		if err := rows.Scan(
			&r.KeyID, &r.SecretHash, &r.Name, &scopesJSON, &r.Creator,
			&r.CreatedAt, &expiresAt, &deletedAt, &lastUsedAt,
		); err != nil {
			return nil, fmt.Errorf("api_keys scan: %w", err)
		}
		if scopesJSON != "" {
			_ = json.Unmarshal([]byte(scopesJSON), &r.Scopes)
		}
		if expiresAt.Valid {
			r.ExpiresAt = &expiresAt.Time
		}
		if deletedAt.Valid {
			r.DeletedAt = &deletedAt.Time
		}
		if lastUsedAt.Valid {
			r.LastUsedAt = &lastUsedAt.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SoftDelete tombstones a key. The row stays in place for forensic
// audit; only the deleted_at column changes. Returns errAPIKeyNotFound
// if the row isn't owned by `creator` or is already deleted —
// admins can only delete their own keys.
//
// Why scope to creator: an admin who has been compromised can already
// mint keys; preventing them from deleting OTHER admins' keys is a
// separation-of-duties win. (A future "super-admin" role could relax
// this.)
func (s *apiKeyStore) SoftDelete(ctx context.Context, keyID, creator string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_keys
		    SET deleted_at = ?
		  WHERE key_id = ?
		    AND creator = ?
		    AND deleted_at IS NULL`,
		time.Now().UTC(), keyID, creator,
	)
	if err != nil {
		return fmt.Errorf("api_keys soft-delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("api_keys soft-delete rowsaffected: %w", err)
	}
	if n == 0 {
		return errAPIKeyNotFound
	}
	return nil
}

// TouchLastUsed best-effort updates the last_used_at column. Errors
// are swallowed (logged at the caller if at all): a slow or failed
// last_used_at write should not deny auth on a valid key. A future
// optimization can defer this to a background batched writer.
func (s *apiKeyStore) TouchLastUsed(ctx context.Context, keyID string) {
	_, _ = s.db.ExecContext(ctx,
		`UPDATE api_keys SET last_used_at = ? WHERE key_id = ?`,
		time.Now().UTC(), keyID,
	)
}
