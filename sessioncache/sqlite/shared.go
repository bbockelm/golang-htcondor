package sqlite

import (
	"database/sql"
	"fmt"

	"github.com/bbockelm/golang-htcondor/sessioncache"
)

// SharedStore is implemented by the SQLite session store so other subsystems
// can persist their own tables in the same physical database file, encrypted at
// rest under the same data-encryption key (DEK) that protects the session
// cache. Obtain it by type-asserting the SessionStore returned by Open:
//
//	ss, _ := sqlite.Open(path, keys, log)
//	if shared, ok := ss.(sqlite.SharedStore); ok { ... }
//
// The caller may create and use its own tables on SharedDB (use a distinct
// table name) and Seal/Unseal opaque blobs with the same DEK, so a single
// stolen database file remains uniformly useless without a signing key.
type SharedStore interface {
	sessioncache.SessionStore

	// SharedDB returns the store's underlying *sql.DB. It is a single-connection
	// WAL handle shared with the session cache; callers must NOT close it (the
	// SessionStore's Close owns the database lifecycle).
	SharedDB() *sql.DB

	// Seal encrypts plaintext with the store's DEK and returns an opaque blob
	// (nonce||ciphertext) safe to persist. Unseal reverses it.
	Seal(plaintext []byte) ([]byte, error)
	Unseal(blob []byte) ([]byte, error)
}

// SharedDB returns the underlying database handle (see SharedStore).
func (s *store) SharedDB() *sql.DB { return s.db }

// Seal encrypts plaintext under the session DEK, returning nonce||ciphertext.
func (s *store) Seal(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	env := s.env
	s.mu.Unlock()
	if env == nil {
		return nil, fmt.Errorf("sessioncache: store not initialized")
	}
	nonce, ciphertext, err := env.seal(plaintext)
	if err != nil {
		return nil, err
	}
	// nonce is a fixed nonceSize prefix; Unseal splits on it.
	return append(nonce, ciphertext...), nil
}

// Unseal reverses Seal, decrypting a nonce||ciphertext blob under the DEK.
func (s *store) Unseal(blob []byte) ([]byte, error) {
	s.mu.Lock()
	env := s.env
	s.mu.Unlock()
	if env == nil {
		return nil, fmt.Errorf("sessioncache: store not initialized")
	}
	if len(blob) < nonceSize {
		return nil, fmt.Errorf("sessioncache: sealed blob too short (%d bytes)", len(blob))
	}
	return env.open(blob[:nonceSize], blob[nonceSize:])
}
