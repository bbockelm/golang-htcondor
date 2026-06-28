package daemon

import (
	"context"
	"time"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/sessioncache"
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
