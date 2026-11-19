//go:build !condor_nosqlite

package daemon

// SQLite is the default session store: linking it here means every existing
// consumer of this package keeps SEC_PERSIST_SESSIONS working with no import,
// no go.mod change and no behaviour change.
//
// Building with -tags condor_nosqlite leaves it out, which drops the whole
// modernc.org SQLite engine and pressly/goose -- about 4.3 MB of binary that
// a daemon never configured for session persistence does not use. See
// sessionstore_nosqlite.go.

import (
	// Imported for its init(), which registers the store with sessioncache.
	// This package calls sessioncache.OpenDefault and names no backend, so
	// this import is the only thing that makes SQLite the default one.
	_ "github.com/bbockelm/golang-htcondor/sessioncache/sqlite"
)
