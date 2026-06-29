package daemon

import (
	"fmt"
	"os"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/droppriv"
)

// dropResult reports the outcome of an attempted privilege drop so New can log
// it once the daemon logger exists (the drop itself must run before the logger
// is built, so the dropped-to user owns the log file).
type dropResult struct {
	dropped  bool
	uid, gid uint32
	note     string // advisory to log (e.g. running as root with the drop disabled)
}

// maybeDropPrivileges drops the process's effective uid/gid to the condor user
// when the process is running as root. condor_master runs as root and starts its
// managed daemons as root, expecting each daemon to drop to the condor user
// itself (HTCondor's set_priv model) — so under the master this is where the drop
// happens, not a no-op. When the process is already non-root (started directly as
// an unprivileged user), there is nothing to drop and this returns immediately.
//
// Because running as root would otherwise create root-owned files the daemon
// cannot later access as condor, the drop is the default when root: it happens
// unless DROP_PRIVILEGES is explicitly set to a false value. The target identity
// follows CONDOR_USER / CONDOR_IDS (via droppriv.ConfigFromHTCondor). The drop
// uses seteuid/setegid (HTCondor's reversible set_priv model).
//
// A target user that cannot be resolved is fatal: continuing as root would
// create files with the wrong ownership/permissions, so the daemon refuses to
// start rather than silently run privileged. A failed drop syscall is likewise
// fatal.
//
// It must be called before the daemon opens any file it will own (the log file,
// the session database, ...) so those files belong to the dropped-to user.
func maybeDropPrivileges(cfg *config.Config) (dropResult, error) {
	if os.Geteuid() != 0 {
		return dropResult{}, nil
	}

	// Running as root. Drop by default; honor an explicit DROP_PRIVILEGES=false
	// as an operator opt-out (e.g. a daemon that must retain root).
	conf := droppriv.ConfigFromHTCondor(cfg)
	if raw, ok := cfg.Get("DROP_PRIVILEGES"); ok && !conf.Enabled {
		return dropResult{note: fmt.Sprintf("running as root with DROP_PRIVILEGES=%q; not dropping privileges", raw)}, nil
	}
	conf.Enabled = true

	mgr, err := droppriv.NewManager(conf)
	if err != nil {
		return dropResult{}, fmt.Errorf("cannot resolve the user to drop privileges to (set CONDOR_USER/CONDOR_IDS or create the condor user; refusing to run as root): %w", err)
	}
	if err := mgr.Start(); err != nil {
		return dropResult{}, fmt.Errorf("dropping privileges: %w", err)
	}
	//nolint:gosec // G115: system uid/gid are small non-negative ints on Linux/macOS
	return dropResult{dropped: true, uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}, nil
}
