package daemon

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/sessioncache"
	"github.com/bbockelm/golang-htcondor/sessioncache/sqlite"
)

// defaultSessionSnapshotInterval is how often the session cache is persisted
// when no interval is configured.
const defaultSessionSnapshotInterval = 30 * time.Second

// EnableSessionPersistence turns on persistence of the CEDAR security session
// cache so clients can resume sessions across a restart. It restores the store's
// records into the cache immediately and arranges for Serve to snapshot the
// cache periodically (interval, or 30s if <= 0) and once more on shutdown.
//
// Call it after New and before Serve. Crucially, open the store *after* New
// (which is where the daemon drops privileges) so the database file is owned by
// the dropped-to service account rather than root. The caller retains ownership
// of the store and must Close it (after Serve returns).
func (d *Daemon) EnableSessionPersistence(store sessioncache.SessionStore, interval time.Duration) error {
	d.sessionStore = store
	d.sessionInterval = interval
	return d.restoreSessions()
}

// restoreSessions loads persisted sessions into the global CEDAR session cache,
// before the daemon serves, so the first request can resume an existing session.
func (d *Daemon) restoreSessions() error {
	n, err := sessioncache.Restore(context.Background(), d.sessionStore, security.GetSessionCache(),
		func(rec sessioncache.SessionRecord, err error) {
			d.log.Warn(logging.DestinationGeneral, "session cache: skipping unrestorable record", "id", rec.ID, "error", err)
		})
	if err != nil {
		return err
	}
	if n > 0 {
		d.log.Info(logging.DestinationGeneral, "session cache restored", "count", n)
	}
	return nil
}

// sessionSnapshotLoop periodically persists the session cache until ctx is
// cancelled. It does not close the store; the final snapshot and Close are
// handled in Serve / by the caller so they complete deterministically.
func (d *Daemon) sessionSnapshotLoop(ctx context.Context) {
	interval := d.sessionInterval
	if interval <= 0 {
		interval = defaultSessionSnapshotInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := d.snapshotSessions(ctx); err != nil {
				d.log.Warn(logging.DestinationGeneral, "session cache: snapshot failed", "error", err)
			}
		}
	}
}

// finalSessionSnapshot takes a last, bounded snapshot during shutdown.
func (d *Daemon) finalSessionSnapshot() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.snapshotSessions(ctx); err != nil {
		d.log.Warn(logging.DestinationGeneral, "session cache: final snapshot failed", "error", err)
	}
}

func (d *Daemon) snapshotSessions(ctx context.Context) error {
	recs := sessioncache.Snapshot(security.GetSessionCache())
	return d.sessionStore.Save(ctx, recs)
}

// SessionDBFileName is the default session-database file name for a daemon:
// "sessions_<subsystem>[_<local-name>].db", lower-cased. The common "sessions_"
// PREFIX gives administrators one glob for every daemon's session database --
// e.g. a VALID_SPOOL_FILES exclusion of "sessions_*" -- while the subsystem
// (plus any local-name) keeps the name per-daemon: several daemons, or several
// instances of one under distinct local-names, may share a SPOOL, and two
// daemons writing one session database would corrupt each other's caches.
func SessionDBFileName(subsys, localName string) string {
	name := "sessions_" + strings.ToLower(subsys)
	if localName != "" {
		name += "_" + strings.ToLower(localName)
	}
	return name + ".db"
}

// autoSessionPersistence is the zero-wiring default every daemon gets from
// Serve: persist the CEDAR session cache whenever the deployment makes that
// possible, so clients resume sessions across a restart instead of landing on
// SID_NOT_FOUND and re-authenticating in a thundering herd.
//
// Policy, per the <SUBSYS>_PERSIST_SESSIONS knob:
//   - unset (the default): AUTO -- enable when SPOOL is configured and pool
//     signing keys are available (they encrypt the database at rest); log and
//     continue unpersisted when either is missing.
//   - false: off.
//   - true: required -- a missing prerequisite is a fatal misconfiguration,
//     never a silent fallback (in particular, never a plaintext session store).
//
// <SUBSYS>_SESSION_CACHE_FILE overrides the default
// $(SPOOL)/SessionDBFileName(...) path; <SUBSYS>_SESSION_SNAPSHOT_INTERVAL
// (seconds) the snapshot cadence. A binary that already called
// EnableSessionPersistence itself keeps its own arrangement (this is a no-op).
// Returns a closer for the store (nil when not enabled).
func (d *Daemon) autoSessionPersistence() (func(), error) {
	if d.sessionStore != nil {
		return nil, nil // the binary wired persistence itself
	}
	cfg := d.Config()

	required := false
	if v, ok := cfg.Get(d.subsys + "_PERSIST_SESSIONS"); ok && strings.TrimSpace(v) != "" {
		on := configTruthy(v)
		if !on {
			return nil, nil
		}
		required = true
	}
	// skip: in AUTO mode a missing prerequisite just logs; when the knob demands
	// persistence it is fatal.
	skip := func(format string, args ...any) (func(), error) {
		if required {
			return nil, fmt.Errorf("daemon: "+d.subsys+"_PERSIST_SESSIONS is set but "+format, args...)
		}
		d.log.Info(logging.DestinationGeneral, "session persistence not enabled: "+fmt.Sprintf(format, args...))
		return nil, nil
	}

	dbPath := ""
	if v, ok := cfg.Get(d.subsys + "_SESSION_CACHE_FILE"); ok {
		dbPath = strings.TrimSpace(v)
	}
	if dbPath == "" {
		spool, ok := cfg.Get("SPOOL")
		if !ok || strings.TrimSpace(spool) == "" {
			return skip("no SPOOL (nor %s_SESSION_CACHE_FILE) is configured", d.subsys)
		}
		dbPath = filepath.Join(strings.TrimSpace(spool), SessionDBFileName(d.subsys, d.localName))
	}

	// The pool signing key(s) encrypt the database at rest; they are root-owned
	// 0600 files read back as root via droppriv.
	rawKeys, err := htcondor.LoadSigningKeys(cfg)
	if err != nil {
		return skip("loading pool signing keys failed: %v", err)
	}
	if len(rawKeys) == 0 {
		return skip("no pool signing keys are available (set SEC_PASSWORD_DIRECTORY); the session database cannot be encrypted without one")
	}
	keys := make([]sqlite.SigningKey, 0, len(rawKeys))
	for id, material := range rawKeys {
		keys = append(keys, sqlite.SigningKey{ID: id, Material: material})
	}

	store, err := sqlite.Open(dbPath, keys, d.Slog())
	if err != nil {
		return skip("opening %s failed: %v", dbPath, err)
	}

	interval := time.Duration(0)
	if v, ok := cfg.Get(d.subsys + "_SESSION_SNAPSHOT_INTERVAL"); ok {
		if secs, perr := strconv.Atoi(strings.TrimSpace(v)); perr == nil && secs > 0 {
			interval = time.Duration(secs) * time.Second
		}
	}
	if err := d.EnableSessionPersistence(store, interval); err != nil {
		_ = store.Close()
		return skip("restoring persisted sessions from %s failed: %v", dbPath, err)
	}
	d.log.Info(logging.DestinationGeneral, "session persistence enabled",
		"path", dbPath, "signing_keys", len(keys))
	return func() { _ = store.Close() }, nil
}

// configTruthy interprets an HTCondor boolean knob value.
func configTruthy(v string) bool {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "TRUE", "YES", "1", "T", "ON":
		return true
	}
	return false
}
