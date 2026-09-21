package daemon

import (
	"log/slog"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Slog returns a *slog.Logger that forwards into the daemon's HTCondor logger
// (at DestinationGeneral). This lets components written against the standard
// library's slog (a common case) log through the daemon's configured log file,
// levels, and rotation without depending on the htcondor logging API directly.
func (d *Daemon) Slog() *slog.Logger {
	return d.log.Slog(logging.DestinationGeneral)
}
