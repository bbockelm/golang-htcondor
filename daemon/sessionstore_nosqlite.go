//go:build condor_nosqlite

package daemon

// No session store is linked into this build.
//
// SEC_PERSIST_SESSIONS then fails loudly at startup rather than running
// without the persistence it asked for: sessionPersistenceFromConfig calls
// sessioncache.OpenDefault, which has nothing registered, and ServeListeners
// refuses to start. A binary that wants persistence in a condor_nosqlite
// build can still have it by importing a store package itself -- the
// registration is what matters, not the tag.
