package sessioncache

import (
	"fmt"
	"log/slog"
	"sync"
)

// SigningKey is one HTCondor pool signing key, used as a key-encryption key
// for a persistent session store.
//
// It lives here rather than in a particular store's package so that a caller
// can load the keys without naming a storage backend. sessioncache/sqlite
// aliases this type, so existing code that writes sqlite.SigningKey is
// unaffected.
type SigningKey struct {
	ID       string
	Material []byte
}

// OpenOptions is everything a session store needs to open itself.
type OpenOptions struct {
	// Path is where the store keeps its data. Its meaning is the backend's;
	// for SQLite it is the database file.
	Path string
	// Keys encrypt the store at rest. A backend that cannot encrypt must
	// refuse rather than ignore them.
	Keys []SigningKey
	Log  *slog.Logger
}

// Opener opens a persistent session store.
type Opener func(OpenOptions) (SessionStore, error)

var (
	openerMu   sync.RWMutex
	openerName string
	opener     Opener
)

// RegisterDefaultOpener names the store that SEC_PERSIST_SESSIONS gets.
//
// A backend package calls this from init(), so linking the package is what
// makes the backend available -- the database/sql pattern. There is one slot
// rather than a map because a daemon persists its sessions one way; two
// registrations mean two backends were linked and nothing can say which the
// administrator meant, so it panics at init rather than choosing.
func RegisterDefaultOpener(name string, o Opener) {
	openerMu.Lock()
	defer openerMu.Unlock()
	if opener != nil && openerName != name {
		panic(fmt.Sprintf("sessioncache: two session stores registered (%s and %s); link only one", openerName, name))
	}
	openerName, opener = name, o
}

// OpenDefault opens the registered store.
//
// The error when nothing is registered is deliberately specific: a binary
// built without a store is a build-time choice, and an administrator who set
// SEC_PERSIST_SESSIONS needs to be told that rather than left to wonder why
// their sessions do not survive a restart. Callers must treat it as fatal --
// running without the persistence that was asked for is the one outcome this
// design exists to prevent.
func OpenDefault(opts OpenOptions) (SessionStore, error) {
	openerMu.RLock()
	o := opener
	openerMu.RUnlock()
	if o == nil {
		return nil, fmt.Errorf("sessioncache: no session store is linked into this binary " +
			"(it was built with -tags condor_nosqlite, or never imported a store package); " +
			"either rebuild without that tag or turn SEC_PERSIST_SESSIONS off")
	}
	return o(opts)
}

// DefaultOpenerName is the registered store's name, or "" when none is
// linked. It is for a daemon that wants to log what it is persisting with.
func DefaultOpenerName() string {
	openerMu.RLock()
	defer openerMu.RUnlock()
	return openerName
}
