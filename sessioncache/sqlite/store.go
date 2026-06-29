// Package sqlite provides an encrypted-at-rest SQLite implementation of
// sessioncache.SessionStore. Session records are encrypted with a data
// encryption key (DEK) that is itself wrapped by each available HTCondor signing
// key (see envelope.go), so a stolen database is useless without a signing key.
package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/gob"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"

	"github.com/bbockelm/golang-htcondor/sessioncache"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" database/sql driver
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// store is an encrypted SQLite sessioncache.SessionStore.
type store struct {
	db  *sql.DB
	log *slog.Logger

	mu  sync.Mutex
	env *envelope
	// fingerprints tracks the last-persisted content hash per session id so Save
	// can write only changed/removed rows (O(churn) instead of O(N)).
	fingerprints map[string]uint64
}

// Open opens (creating if needed) the encrypted session database at path. keys
// are the available signing keys used to wrap/unwrap the DEK; at least one is
// required (the cache cannot be encrypted without a key). On an existing
// database whose DEK cannot be recovered from any available key, the store
// re-initializes with a fresh DEK and discards the unreadable sessions (clients
// re-authenticate) rather than failing to start.
func Open(path string, keys []SigningKey, log *slog.Logger) (sessioncache.SessionStore, error) {
	if log == nil {
		log = slog.Default()
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("sessioncache: persistence requires at least one signing key (SEC_PASSWORD_DIRECTORY)")
	}
	// _txlock=immediate makes BeginTx start a write transaction up front (BEGIN
	// IMMEDIATE) rather than a deferred read that upgrades to write on the first
	// write statement. With a single shared connection, deferring the upgrade can
	// deadlock; taking the write lock at BEGIN avoids that. busy_timeout guards
	// transient locks; WAL + NORMAL trade an fsync per commit for a single fsync
	// at checkpoint while remaining crash-safe.
	dsn := fmt.Sprintf("file:%s?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening session db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	s := &store{db: db, log: log, fingerprints: map[string]uint64{}}
	if err := s.initEnvelope(keys); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// migrate applies the embedded goose migrations, creating/evolving the schema.
// It is idempotent (goose records applied versions in its own table).
func migrate(db *sql.DB) error {
	goose.SetBaseFS(migrationFS)
	goose.SetTableName("session_cache_db_version")
	goose.SetLogger(quietLogger{})
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("sessioncache: set migration dialect: %w", err)
	}
	if err := goose.UpContext(context.Background(), db, "migrations"); err != nil {
		return fmt.Errorf("sessioncache: migrate schema: %w", err)
	}
	return nil
}

// quietLogger satisfies goose.Logger but drops goose's chatter; the daemon's
// own logging reports outcomes.
type quietLogger struct{}

func (quietLogger) Fatalf(format string, v ...any) { panic(fmt.Sprintf(format, v...)) }
func (quietLogger) Printf(string, ...any)          {}

// initEnvelope recovers or creates the DEK and ensures every available signing
// key has a wrapping row (supporting rotation).
func (s *store) initEnvelope(keys []SigningKey) error {
	ctx := context.Background()
	rows, err := s.loadMasterKeyRows(ctx)
	if err != nil {
		return err
	}

	if len(rows) == 0 {
		env, err := newEnvelope()
		if err != nil {
			return err
		}
		s.env = env
		return s.wrapForKeys(ctx, keys, nil)
	}

	env, err := openEnvelope(rows, keys)
	if err != nil {
		// The session cache is advisory: if no available signing key can recover
		// the master key (keys rotated away, tampering), flush the cache and
		// re-initialize with a fresh master key rather than failing startup. The
		// only cost is that cached sessions are discarded and clients re-auth.
		s.log.Warn("session cache: cannot recover the master key from any available signing key; flushing the cache and re-initializing")
		if _, err := s.db.ExecContext(ctx, `DELETE FROM session`); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM master_key`); err != nil {
			return err
		}
		fresh, err := newEnvelope()
		if err != nil {
			return err
		}
		s.env = fresh
		return s.wrapForKeys(ctx, keys, nil)
	}

	s.env = env
	return s.wrapForKeys(ctx, keys, existingKeyIDs(rows))
}

func (s *store) wrapForKeys(ctx context.Context, keys []SigningKey, have map[string]bool) error {
	for _, k := range keys {
		if have[k.ID] {
			continue
		}
		row, err := s.env.wrapFor(k)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR REPLACE INTO master_key (key_id, salt, nonce, wrapped) VALUES (?, ?, ?, ?)`,
			row.KeyID, row.Salt, row.Nonce, row.Wrapped); err != nil {
			return fmt.Errorf("writing master key row: %w", err)
		}
	}
	return nil
}

func (s *store) loadMasterKeyRows(ctx context.Context) ([]masterKeyRow, error) {
	rs, err := s.db.QueryContext(ctx, `SELECT key_id, salt, nonce, wrapped FROM master_key`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rs.Close() }()
	var out []masterKeyRow
	for rs.Next() {
		var r masterKeyRow
		if err := rs.Scan(&r.KeyID, &r.Salt, &r.Nonce, &r.Wrapped); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

func existingKeyIDs(rows []masterKeyRow) map[string]bool {
	m := make(map[string]bool, len(rows))
	for _, r := range rows {
		m[r.KeyID] = true
	}
	return m
}

// Load returns all non-expired session records and primes the fingerprint map
// so the first post-restore Save writes only genuine changes.
func (s *store) Load(ctx context.Context) ([]sessioncache.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := s.db.QueryContext(ctx, `SELECT id, expiration, nonce, ciphertext FROM session`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rs.Close() }()

	now := time.Now()
	var out []sessioncache.SessionRecord
	for rs.Next() {
		var id string
		var exp int64
		var nonce, ct []byte
		if err := rs.Scan(&id, &exp, &nonce, &ct); err != nil {
			return nil, err
		}
		if exp != 0 && now.After(time.Unix(exp, 0)) {
			continue // do not restore expired sessions
		}
		plain, err := s.env.open(nonce, ct)
		if err != nil {
			s.log.Warn("session cache: failed to decrypt a session record; skipping", "id", id)
			continue
		}
		var rec sessioncache.SessionRecord
		if err := gob.NewDecoder(bytes.NewReader(plain)).Decode(&rec); err != nil {
			s.log.Warn("session cache: failed to decode a session record; skipping", "id", id, "error", err)
			continue
		}
		s.fingerprints[id] = fingerprint(plain)
		out = append(out, rec)
	}
	return out, rs.Err()
}

// Save persists recs incrementally: it encodes each record, writes only those
// whose content changed since the last Save, deletes records no longer present,
// and skips the transaction entirely when nothing changed. This makes
// steady-state cost proportional to churn rather than total cache size.
func (s *store) Save(ctx context.Context, recs []sessioncache.SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	type upsert struct {
		id    string
		exp   int64
		plain []byte
	}
	var changed []upsert
	newFP := make(map[string]uint64, len(recs))
	for _, rec := range recs {
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(rec); err != nil {
			return fmt.Errorf("encoding session %s: %w", rec.ID, err)
		}
		plain := buf.Bytes()
		fp := fingerprint(plain)
		newFP[rec.ID] = fp
		if old, ok := s.fingerprints[rec.ID]; !ok || old != fp {
			var exp int64
			if !rec.Expiration.IsZero() {
				exp = rec.Expiration.Unix()
			}
			changed = append(changed, upsert{id: rec.ID, exp: exp, plain: plain})
		}
	}
	var removed []string
	for id := range s.fingerprints {
		if _, ok := newFP[id]; !ok {
			removed = append(removed, id)
		}
	}
	if len(changed) == 0 && len(removed) == 0 {
		return nil // nothing to do
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, u := range changed {
		nonce, ct, err := s.env.seal(u.plain)
		if err != nil {
			return fmt.Errorf("encrypting session %s: %w", u.id, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO session (id, expiration, nonce, ciphertext) VALUES (?, ?, ?, ?)`,
			u.id, u.exp, nonce, ct); err != nil {
			return fmt.Errorf("writing session %s: %w", u.id, err)
		}
	}
	for _, id := range removed {
		if _, err := tx.ExecContext(ctx, `DELETE FROM session WHERE id = ?`, id); err != nil {
			return fmt.Errorf("deleting session %s: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.fingerprints = newFP
	return nil
}

func (s *store) Close() error {
	return s.db.Close()
}

// fingerprint is a cheap content hash of a serialized record, used for change
// detection (not security).
func fingerprint(b []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return h.Sum64()
}
