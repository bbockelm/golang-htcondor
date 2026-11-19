package sqlite

import (
	"github.com/bbockelm/golang-htcondor/sessioncache"
)

// Linking this package makes SQLite the session store that
// SEC_PERSIST_SESSIONS uses -- the database/sql pattern, so a binary chooses
// its backend by what it imports rather than by a flag threaded through every
// call site.
//
// daemon blank-imports this package unless built with -tags condor_nosqlite,
// so an ordinary daemon needs no import of its own and behaves exactly as it
// did before the registry existed.
func init() {
	sessioncache.RegisterDefaultOpener("sqlite", func(opts sessioncache.OpenOptions) (sessioncache.SessionStore, error) {
		return Open(opts.Path, opts.Keys, opts.Log)
	})
}
