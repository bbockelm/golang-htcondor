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

// restoreSessions loads persisted sessions into the global CEDAR session cache.
// It runs during New, before the daemon serves, so the first request can resume
// an existing session.
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
