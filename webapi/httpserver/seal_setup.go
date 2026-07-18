package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb/seal"
)

// setupSealer reads the master KEK from kekFile, derives a per-DB
// KEK using HKDF + a salt persisted in `kek_metadata`, and returns a
// ready-to-use Sealer plus a count of plaintext rows it migrated to
// ciphertext. When kekFile is empty, encryption is disabled — a nil
// Sealer is returned and any rows already in encrypted form will fail
// to decrypt later (the storage helpers surface a clear error).
//
// Idempotent: repeated startups with the same KEK produce the same
// derived key (the salt is stable in the DB), and rows that are
// already sealed are detected by their non-null DEK column and left
// alone.
func setupSealer(ctx context.Context, db *sql.DB, kekFile string, logger *logging.Logger) (*seal.Sealer, int, error) {
	if kekFile == "" {
		return nil, 0, nil
	}

	master, err := seal.LoadMasterKEKFromFile(kekFile)
	if err != nil {
		return nil, 0, fmt.Errorf("load master KEK: %w", err)
	}
	defer zero(master) // wipe master from memory once derivation is done

	salt, err := loadOrCreateKEKSalt(ctx, db)
	if err != nil {
		return nil, 0, fmt.Errorf("kek_metadata salt: %w", err)
	}

	dbKey, err := seal.DeriveDBKey(master, salt)
	if err != nil {
		return nil, 0, fmt.Errorf("derive DB key: %w", err)
	}
	defer zero(dbKey) // copied into the AEAD inside seal.New

	sealer, err := seal.New(dbKey)
	if err != nil {
		return nil, 0, fmt.Errorf("construct sealer: %w", err)
	}

	// Encrypt any plaintext rows. If a row is already sealed under a
	// DIFFERENT KEK (e.g. operator swapped the file), this will surface
	// a "KEK mismatch?" error from sealer.Open; we don't try to
	// recover — the operator has to either restore the original KEK
	// or wipe the rows.
	migrated, err := backfillSealedColumns(ctx, db, sealer, logger)
	if err != nil {
		return nil, 0, fmt.Errorf("backfill: %w", err)
	}
	return sealer, migrated, nil
}

// loadOrCreateKEKSalt reads the per-DB salt from kek_metadata. If
// the row doesn't exist (migration 0002 just created the table on
// first startup with KEK enabled), generate a fresh 32-byte salt and
// persist it. The salt is non-secret on its own — it just binds the
// derived DB key to this specific DB instance.
func loadOrCreateKEKSalt(ctx context.Context, db *sql.DB) ([]byte, error) {
	var salt []byte
	err := db.QueryRowContext(ctx, `SELECT salt FROM kek_metadata WHERE id = 1`).Scan(&salt)
	if err == nil && len(salt) > 0 {
		return salt, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	// First-use path: generate + persist.
	salt, err = seal.NewSalt()
	if err != nil {
		return nil, err
	}
	_, err = db.ExecContext(ctx, `INSERT OR REPLACE INTO kek_metadata (id, salt) VALUES (1, ?)`, salt)
	if err != nil {
		return nil, fmt.Errorf("persist salt: %w", err)
	}
	return salt, nil
}

// sealableRow is a tuple of (table, data column, dek column). Listed
// here so adding a new sealed column is one line plus a small storage
// edit; the backfill walker doesn't need per-table specialization.
type sealableRow struct {
	table   string
	dataCol string
	dekCol  string
}

var sealableRows = []sealableRow{
	{"oauth2_rsa_keys", "private_key_pem", "private_key_pem_dek"},
	{"oauth2_hmac_secrets", "secret", "secret_dek"},
	{"idp_rsa_keys", "private_key_pem", "private_key_pem_dek"},
	{"idp_hmac_secrets", "secret", "secret_dek"},
}

// backfillSealedColumns walks every (table, col, dek) tuple in
// sealableRows and re-encrypts any row where data IS NOT NULL and
// dek IS NULL. Each row is its own transaction-free UPDATE — these
// tables are at-most-one-row (CHECK id = 1) and only written at
// startup, so concurrency isn't a concern.
//
// Returns the number of rows actually re-encrypted so the caller can
// log how much work the migration did.
func backfillSealedColumns(ctx context.Context, db *sql.DB, sealer *seal.Sealer, logger *logging.Logger) (int, error) {
	migrated := 0
	for _, r := range sealableRows {
		// Use a parameterless query — table/col names are constants
		// from sealableRows, so concatenating them into the SQL is
		// safe (no user input).
		//nolint:gosec // identifiers are compile-time constants
		query := fmt.Sprintf(
			`SELECT id, %s FROM %s WHERE %s IS NOT NULL AND (%s IS NULL OR length(%s) = 0)`,
			r.dataCol, r.table, r.dataCol, r.dekCol, r.dekCol,
		)
		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			return migrated, fmt.Errorf("scan %s: %w", r.table, err)
		}
		// Collect into memory; the tables are tiny (one row each).
		type pending struct {
			id   int
			data []byte
		}
		var todo []pending
		for rows.Next() {
			var p pending
			if err := rows.Scan(&p.id, &p.data); err != nil {
				_ = rows.Close()
				return migrated, fmt.Errorf("scan %s row: %w", r.table, err)
			}
			todo = append(todo, p)
		}
		if err := rows.Close(); err != nil {
			return migrated, err
		}
		if err := rows.Err(); err != nil {
			return migrated, err
		}

		for _, p := range todo {
			data, dek, err := sealer.Seal(p.data)
			if err != nil {
				return migrated, fmt.Errorf("seal %s id=%d: %w", r.table, p.id, err)
			}
			//nolint:gosec // identifiers are compile-time constants
			updateQ := fmt.Sprintf(
				`UPDATE %s SET %s = ?, %s = ? WHERE id = ?`,
				r.table, r.dataCol, r.dekCol,
			)
			if _, err := db.ExecContext(ctx, updateQ, data, dek, p.id); err != nil {
				return migrated, fmt.Errorf("update %s id=%d: %w", r.table, p.id, err)
			}
			migrated++
			if logger != nil {
				logger.Info(logging.DestinationHTTP,
					"Encrypted plaintext secret row",
					"table", r.table, "id", p.id,
				)
			}
		}
	}
	return migrated, nil
}

// zero overwrites b with random noise then zeros, then re-randomizes
// once more. Reduces the chance that a long-lived process retains the
// master KEK in resident memory after we're done deriving from it.
// Best-effort: the Go runtime doesn't guarantee no copies were made
// (the slice may have been moved by the GC), but the symbolic intent
// is clear and this is the standard idiom in the stdlib.
func zero(b []byte) {
	if len(b) == 0 {
		return
	}
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = 0
	}
}
