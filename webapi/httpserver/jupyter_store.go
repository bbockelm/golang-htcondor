package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb/seal"
	"github.com/bbockelm/golang-htcondor/webapi/jupytertunnel"
)

// jupyterStore is the durable half of the JupyterLab session registry.
//
// The in-memory registry holds what cannot be written down -- the live yamux
// tunnel -- and this holds what must outlive the process: the signing secret,
// and which token each session will accept next.
//
// Nothing secret goes on the job ad. An ad is readable by any pool user, so
// the ad carries only the session's identity and this carries the credential,
// sealed under the same KEK as every other long-lived secret.
type jupyterStore struct {
	db     *sql.DB
	sealer *seal.Sealer
}

func newJupyterStore(db *sql.DB, sealer *seal.Sealer) *jupyterStore {
	if db == nil {
		return nil
	}
	return &jupyterStore{db: db, sealer: sealer}
}

// SigningSecret returns the registry's token-signing secret, creating it on
// first use.
//
// Durable because it is what makes a token outlive the process that minted
// it. A per-process secret is why every session died on restart: the job was
// still running and the helper still had its token, and nothing left could
// verify it.
func (s *jupyterStore) SigningSecret(ctx context.Context) ([]byte, error) {
	if s == nil {
		return nil, errors.New("jupyter: no application database configured")
	}
	if secret, err := s.loadSecret(ctx); err == nil {
		return secret, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("jupyter: generating the signing secret: %w", err)
	}
	stored, dek := secret, []byte(nil)
	if s.sealer != nil {
		var err error
		if stored, dek, err = s.sealer.Seal(secret); err != nil {
			return nil, fmt.Errorf("jupyter: sealing the signing secret: %w", err)
		}
	}
	// INSERT OR IGNORE, then read back: two servers sharing a database must
	// end up on the same secret, and the loser of the race has to adopt the
	// winner's rather than carry on with the one it generated.
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO jupyter_signing_secret (id, secret, secret_dek, created_at) VALUES (1, ?, ?, ?)`,
		stored, dek, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("jupyter: storing the signing secret: %w", err)
	}
	return s.loadSecret(ctx)
}

func (s *jupyterStore) loadSecret(ctx context.Context) ([]byte, error) {
	var stored, dek []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT secret, secret_dek FROM jupyter_signing_secret WHERE id = 1`).Scan(&stored, &dek)
	if err != nil {
		return nil, err
	}
	if len(dek) == 0 {
		return stored, nil
	}
	if s.sealer == nil {
		// The secret was written by a server with a KEK and this one has
		// none. Opening it is impossible; saying so beats handing back
		// ciphertext and failing every token verification with a puzzle.
		return nil, errors.New("jupyter: the signing secret is sealed but no KEK is configured (HTTP_API_KEK_FILE)")
	}
	plain, err := s.sealer.Open(stored, dek)
	if err != nil {
		return nil, fmt.Errorf("jupyter: unsealing the signing secret: %w", err)
	}
	return plain, nil
}

// jupyterSessionRow is one session's durable state.
type jupyterSessionRow struct {
	InstanceID string
	Owner      string
	ClusterID  int
	ProcID     int
	NextNonce  []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Put records a session, replacing any row with the same id.
func (s *jupyterStore) Put(ctx context.Context, row jupyterSessionRow) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO jupyter_sessions
		    (instance_id, owner, cluster_id, proc_id, next_nonce, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(instance_id) DO UPDATE SET
		    owner = excluded.owner,
		    cluster_id = excluded.cluster_id,
		    proc_id = excluded.proc_id,
		    next_nonce = excluded.next_nonce,
		    expires_at = excluded.expires_at`,
		row.InstanceID, row.Owner, row.ClusterID, row.ProcID,
		row.NextNonce, row.CreatedAt.UTC(), row.ExpiresAt.UTC())
	return err
}

// RollNonce records the token a session will accept next.
//
// The write is conditional on the nonce being rolled from: two helpers
// racing a redial, or a replay of the token just spent, must not both
// succeed. The caller treats "no rows" as a rejected connection.
func (s *jupyterStore) RollNonce(ctx context.Context, instanceID string, from, to []byte) (bool, error) {
	if s == nil {
		return false, errors.New("jupyter: no application database configured")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE jupyter_sessions SET next_nonce = ? WHERE instance_id = ? AND next_nonce = ?`,
		to, instanceID, from)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Get reads one session.
func (s *jupyterStore) Get(ctx context.Context, instanceID string) (jupyterSessionRow, error) {
	var row jupyterSessionRow
	if s == nil {
		return row, sql.ErrNoRows
	}
	err := s.db.QueryRowContext(ctx, `
		SELECT instance_id, owner, cluster_id, proc_id, next_nonce, created_at, expires_at
		  FROM jupyter_sessions WHERE instance_id = ?`, instanceID).
		Scan(&row.InstanceID, &row.Owner, &row.ClusterID, &row.ProcID,
			&row.NextNonce, &row.CreatedAt, &row.ExpiresAt)
	return row, err
}

// Live lists the sessions that have not expired, for re-adoption at startup.
func (s *jupyterStore) Live(ctx context.Context, now time.Time) ([]jupyterSessionRow, error) {
	if s == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT instance_id, owner, cluster_id, proc_id, next_nonce, created_at, expires_at
		  FROM jupyter_sessions WHERE expires_at > ? ORDER BY created_at`, now.UTC())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []jupyterSessionRow
	for rows.Next() {
		var row jupyterSessionRow
		if err := rows.Scan(&row.InstanceID, &row.Owner, &row.ClusterID, &row.ProcID,
			&row.NextNonce, &row.CreatedAt, &row.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// Delete removes one session.
func (s *jupyterStore) Delete(ctx context.Context, instanceID string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM jupyter_sessions WHERE instance_id = ?`, instanceID)
	return err
}

// DeleteExpired drops rows past their ceiling and reports how many went.
//
// Without it the table is append-only: a session whose job ended leaves its
// row behind, and nothing else deletes it, so the credential store grows for
// the life of the deployment.
func (s *jupyterStore) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	if s == nil {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM jupyter_sessions WHERE expires_at <= ?`, now.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// compile-time assertion that the store satisfies what the registry needs.
var _ jupytertunnel.NonceRoller = (*jupyterStore)(nil)
