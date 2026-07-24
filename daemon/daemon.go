// Package daemon provides the common bootstrap for an HTCondor daemon written
// in Go: configuration + HTCondor-compatible logging, condor_master integration
// (DC_SET_READY readiness and the DC_CHILDALIVE keepalive loop), shared-port
// listener adoption from CONDOR_INHERIT, and a graceful run loop driven by
// SIGTERM/SIGINT (terminate) and SIGHUP (reconfigure).
//
// It is the reusable extraction of the daemon glue first written for
// htcondor-api. Build a Daemon with New, obtain a command-socket listener with
// Listener, then hand it to Serve along with whatever you want to run on it
// (a CEDAR command server, an http.Server, ...). The daemon owns the lifecycle;
// the caller owns the protocol.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bbockelm/cedar/addresses"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/sessioncache"
)

// Options configures a Daemon.
type Options struct {
	// Subsys is the HTCondor subsystem/daemon name, e.g. "CCB". It selects the
	// per-daemon log knobs (<Subsys>_LOG, MAX_<Subsys>_LOG, <Subsys>_DEBUG) and
	// names the address file (<Subsys>_ADDRESS_FILE).
	Subsys string

	// LocalName is the daemon's HTCondor local-name (-local-name), when running
	// as a named instance of the subsystem. It scopes the default session-
	// database file name (see SessionDBFileName), so several instances sharing
	// a SPOOL keep separate session caches.
	LocalName string

	// Config is the HTCondor configuration. If nil, it is loaded from
	// CONDOR_CONFIG.
	Config *config.Config

	// Logger is the daemon logger. If nil, it is built from Config via
	// logging.FromConfigWithDaemon(Subsys, Config).
	Logger *logging.Logger

	// ShutdownGrace bounds how long Serve waits for the served handler to stop
	// after a termination signal before returning anyway (default 15s).
	ShutdownGrace time.Duration
}

// Daemon is an HTCondor daemon bootstrap. It is safe to construct once and use
// from a single Run/Serve call.
type Daemon struct {
	subsys    string
	localName string
	// cfg is swapped atomically on SIGHUP reconfigure; readers (Config) load it
	// without locking, so a reconfigure never races a concurrent reader.
	cfg   atomic.Pointer[config.Config]
	log   *logging.Logger
	grace time.Duration

	master *htcondor.Master // nil when running standalone

	sessionStore    sessioncache.SessionStore // nil unless session persistence enabled
	sessionInterval time.Duration

	shutdownCh   chan struct{} // closed by Shutdown to request a graceful stop
	shutdownOnce sync.Once

	mu               sync.Mutex
	sharedPortName   string // shared-port "sock" id, set by Listener when adopted
	adoptedInherited bool   // Listener returned an inherited socket (shared-port or #119), not the fallback
	stopAlive        func()
	onReconfig       []func(*config.Config)

	// startTime is the daemon's construction time (DaemonStartTime); lastReconfig is the last
	// SIGHUP reconfigure (DaemonLastReconfigTime), 0 until the first. Both feed PublishAd.
	startTime    time.Time
	lastReconfig atomic.Int64
}

// New constructs a Daemon: it loads configuration and logging, and — when
// running under condor_master — connects to the master for readiness and
// keepalive signaling. Failure to reach the master is logged but not fatal:
// condor_master's own hang detection will eventually act, and a transient
// master glitch should not prevent the daemon from starting.
func New(opts Options) (*Daemon, error) {
	if opts.Subsys == "" {
		return nil, fmt.Errorf("daemon: Subsys is required")
	}

	cfg := opts.Config
	if cfg == nil {
		var err error
		cfg, err = config.New()
		if err != nil {
			return nil, fmt.Errorf("daemon: loading config: %w", err)
		}
	}

	// Drop privileges (if running as root and DROP_PRIVILEGES is enabled) before
	// building the logger or opening any other owned resource, so they belong to
	// the dropped-to user. The outcome is logged once the logger exists.
	drop, err := maybeDropPrivileges(cfg)
	if err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}

	logger := opts.Logger
	if logger == nil {
		var err error
		logger, err = logging.FromConfigWithDaemon(opts.Subsys, cfg)
		if err != nil {
			return nil, fmt.Errorf("daemon: building logger: %w", err)
		}
	}
	switch {
	case drop.dropped:
		logger.Info(logging.DestinationGeneral, "dropped privileges", "euid", drop.uid, "egid", drop.gid)
	case drop.note != "":
		logger.Warn(logging.DestinationGeneral, drop.note)
	}

	grace := opts.ShutdownGrace
	if grace == 0 {
		grace = 15 * time.Second
	}

	d := &Daemon{
		subsys:     opts.Subsys,
		localName:  opts.LocalName,
		log:        logger,
		grace:      grace,
		shutdownCh: make(chan struct{}),
		startTime:  time.Now(),
	}
	d.cfg.Store(cfg)

	logEnvDiagnostic(logger)
	if UnderCondorMaster() {
		master, err := htcondor.MasterFromEnv()
		if err != nil {
			logger.Warn(logging.DestinationGeneral, "running under condor_master but master env unusable; readiness/keepalive disabled", "error", err)
		} else {
			d.master = master
			logger.Info(logging.DestinationGeneral, "detected condor_master parent",
				"parent_pid", master.ParentPID(), "master_addr", master.Address())
		}
	}

	return d, nil
}

// Subsys returns the daemon's subsystem name.
func (d *Daemon) Subsys() string { return d.subsys }

// Config returns the daemon's configuration.
func (d *Daemon) Config() *config.Config { return d.cfg.Load() }

// Logger returns the daemon's logger.
func (d *Daemon) Logger() *logging.Logger { return d.log }

// UnderMaster reports whether the daemon is running under condor_master with a
// usable master connection (readiness/keepalive available).
func (d *Daemon) UnderMaster() bool { return d.master != nil }

// Master returns the condor_master client, or nil when running standalone.
func (d *Daemon) Master() *htcondor.Master { return d.master }

// OnReconfig registers a callback invoked (with freshly reloaded config) when
// the daemon receives SIGHUP.
func (d *Daemon) OnReconfig(fn func(*config.Config)) {
	d.mu.Lock()
	d.onReconfig = append(d.onReconfig, fn)
	d.mu.Unlock()
}

// Listener resolves the command-socket listener. Under condor_master with
// shared port on, it adopts the inherited shared-port fd from CONDOR_INHERIT.
// Otherwise (or when no shared-port token was passed) it calls fallback to bind
// a normal listener.
func (d *Daemon) Listener(fallback func() (net.Listener, error)) (net.Listener, error) {
	spln, endpoint, err := resolveSharedPortListener(d.log)
	if err != nil {
		return nil, err
	}
	if spln != nil {
		d.mu.Lock()
		d.sharedPortName = endpoint
		d.adoptedInherited = true
		d.mu.Unlock()
		return spln, nil
	}
	// Non-shared-port under condor_master: adopt the command socket the master pre-created
	// and inherited to us, rather than binding our own (which would EADDRINUSE against the
	// master's already-bound port). See issue #119.
	if iln := resolveInheritedListener(d.log); iln != nil {
		d.mu.Lock()
		d.adoptedInherited = true
		d.mu.Unlock()
		return iln, nil
	}
	if fallback == nil {
		return nil, fmt.Errorf("daemon: no shared-port listener inherited and no fallback provided")
	}
	return fallback()
}

// AdoptedInheritedListener reports whether Listener returned a socket inherited from
// condor_master (a shared-port endpoint or a pre-created command socket, issue #119)
// rather than the caller's fallback bind. It lets a daemon that also wants its own
// directly-dialable port (e.g. a CCB advertising a public address) decide whether to bind
// that extra listener: under the master the inherited socket is the managed command port,
// so the explicit -listen port is an *additional* listener; standalone, the fallback already
// bound -listen, so binding it again would collide. Valid only after Listener has been called.
func (d *Daemon) AdoptedInheritedListener() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.adoptedInherited
}

// SharedPortName returns the shared-port "sock" id this daemon listens on (the
// inherited endpoint name), or "" when not running behind shared port. Valid
// only after Listener has been called.
func (d *Daemon) SharedPortName() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sharedPortName
}

// AdvertisedSinful derives this daemon's externally reachable command address
// when it is running behind shared port: the shared-port server's host:port
// (taken from the inherited master command address, which shares the shared-port
// server's TCP endpoint) with this daemon's "sock" id. It returns ("", false)
// when not behind shared port, or when the master address is unavailable or
// unparseable.
//
// This assumes the common deployment where the daemon's shared-port server is
// the same one fronting condor_master (USE_SHARED_PORT with the master's
// shared_port). If a separate routable address is required (e.g.
// TCP_FORWARDING_HOST), supply it explicitly rather than relying on this.
func (d *Daemon) AdvertisedSinful() (string, bool) {
	sock := d.SharedPortName()
	if sock == "" || d.master == nil {
		return "", false
	}
	return deriveAdvertisedSinful(d.master.Address(), sock)
}

// deriveAdvertisedSinful builds "<host:port?sock=sock>" from a shared-port
// server command address and a sock id. Returns ("", false) if serverAddr has no
// usable host:port or sock is empty.
func deriveAdvertisedSinful(serverAddr, sock string) (string, bool) {
	if sock == "" {
		return "", false
	}
	info, err := addresses.ParseSinful(serverAddr)
	if err != nil || info.Host == "" || info.Port == "" {
		return "", false
	}
	return fmt.Sprintf("%s:%s?sock=%s", info.Host, info.Port, sock), true
}

// Serve runs the daemon lifecycle. It starts serve(ctx, ln) in the background,
// notifies condor_master that initialization is complete (DC_SET_READY), runs
// the keepalive loop (DC_CHILDALIVE), and blocks until:
//
//   - serve returns (its error is returned), or
//   - ctx is cancelled, or
//   - a termination signal (SIGTERM/SIGINT) arrives — Serve cancels the served
//     handler, waits up to ShutdownGrace for it to stop, and returns nil.
//
// SIGHUP reloads the configuration and invokes any OnReconfig callbacks.
//
// serve must honor ctx cancellation (return promptly once ctx is done); a
// cedar/server Server.Serve and a wrapped http.Server both satisfy this.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener, serve func(context.Context, net.Listener) error) error {
	return d.ServeListeners(ctx, serve, ln)
}

// ServeListeners is Serve generalized to more than one listener: it runs serve(ctx, ln)
// concurrently on each listener, all sharing the same handler, and returns when the first
// serve loop errors, when ctx is cancelled, or on a termination signal (draining every serve
// loop within ShutdownGrace on the graceful paths). Use it when a daemon must accept on
// several sockets at once — e.g. a CCB that inherits its managed command socket from
// condor_master AND binds its own directly-dialable public port. serve must be safe to run
// concurrently across listeners (a cedar/server Server is: its Serve is a stateless
// accept-loop over a shared dispatcher). Requires at least one listener.
func (d *Daemon) ServeListeners(ctx context.Context, serve func(context.Context, net.Listener) error, lns ...net.Listener) error {
	if len(lns) == 0 {
		return fmt.Errorf("daemon: ServeListeners requires at least one listener")
	}

	// Single-knob session persistence (SEC_PERSIST_SESSIONS, default off):
	// restore/persist the CEDAR session cache without any per-binary wiring (see
	// sessionPersistenceFromConfig). Runs before the serve loops so the first
	// request can already resume a session.
	closeSessions, err := d.sessionPersistenceFromConfig()
	if err != nil {
		return err
	}
	if closeSessions != nil {
		defer closeSessions()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	serveErr := make(chan error, len(lns))
	for _, ln := range lns {
		ln := ln
		go func() { serveErr <- serve(ctx, ln) }()
	}

	d.signalReady(ctx)
	d.startKeepAlive(ctx)
	defer d.stopKeepAlive()

	// Parent-death monitor. A C++ DaemonCore daemon exits when its condor_master
	// parent vanishes; ours must too. If the master dies without gracefully
	// signaling us (a crash, or a test harness killing it), no SIGTERM is
	// delivered — we are silently reparented (to launchd on macOS, init/a
	// subreaper on Linux) and would otherwise spin forever. This monitor notices
	// the master is gone and drives the same graceful shutdown path as SIGTERM.
	// It runs ONLY under condor_master, where the contract "our parent pid
	// changing ⇒ the master exited" holds; a standalone daemon's parent is a
	// shell/test that may legitimately change, so the monitor is disabled there.
	// Complementary to keepalive: keepalive tells the master we are alive; this
	// notices the master dying.
	masterGoneCh := make(chan struct{})
	if d.UnderMaster() {
		originalPPID := d.master.ParentPID()
		if originalPPID <= 0 {
			originalPPID = os.Getppid()
		}
		stopMonitor := make(chan struct{})
		monitorDone := make(chan struct{})
		go d.masterMonitor(originalPPID, stopMonitor, monitorDone, masterGoneCh)
		// Stop the monitor on any Serve exit. This defer is registered after the
		// ctx cancel defer, so (LIFO) it runs first: we halt and join the monitor
		// goroutine before anything else tears down.
		defer func() {
			close(stopMonitor)
			<-monitorDone
		}()
	}

	// Session-cache persistence: snapshot periodically, and on shutdown stop the
	// loop, wait for it to exit, then take a final snapshot — so no snapshot can
	// race the caller's store Close.
	if d.sessionStore != nil {
		sctx, scancel := context.WithCancel(ctx)
		loopDone := make(chan struct{})
		go func() { defer close(loopDone); d.sessionSnapshotLoop(sctx) }()
		defer func() {
			scancel()
			<-loopDone
			d.finalSessionSnapshot()
		}()
	}

	for {
		select {
		case err := <-serveErr:
			// One serve loop exited (a listener failed). Cancel the rest, wait for them
			// within grace, and surface the first error.
			cancel()
			d.waitServe(serveErr, len(lns)-1)
			return err
		case <-ctx.Done():
			d.waitServe(serveErr, len(lns))
			return ctx.Err()
		case <-d.shutdownCh:
			// Shutdown() was called (e.g. by a DC_OFF command handler); treat it
			// like a termination signal: graceful, returns nil.
			d.log.Info(logging.DestinationGeneral, "shutdown requested; shutting down")
			cancel()
			d.waitServe(serveErr, len(lns))
			return nil
		case <-masterGoneCh:
			// The condor_master parent died without signaling us. Treat it like a
			// termination signal: graceful, returns nil. (The monitor already
			// logged the specifics.)
			cancel()
			d.waitServe(serveErr, len(lns))
			return nil
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				d.reconfigure()
			default: // SIGTERM / SIGINT
				d.log.Info(logging.DestinationGeneral, "received termination signal; shutting down", "signal", sig.String())
				cancel()
				d.waitServe(serveErr, len(lns))
				return nil
			}
		}
	}
}

// Shutdown requests a graceful stop of a running Serve: it cancels the served
// handler, waits up to ShutdownGrace, and makes Serve return nil. Safe to call
// from a command handler (e.g. DC_OFF) or any goroutine; idempotent and a no-op
// before Serve starts (the request is latched and observed once Serve runs).
func (d *Daemon) Shutdown() {
	d.shutdownOnce.Do(func() { close(d.shutdownCh) })
}

// Reconfigure reloads the configuration and runs OnReconfig callbacks, the same
// work SIGHUP triggers. Safe to call from a command handler (e.g. DC_RECONFIG).
func (d *Daemon) Reconfigure() {
	d.reconfigure()
}

// waitServe waits for n serve loops to finish, bounded (in total) by ShutdownGrace, so a
// hung handler cannot delay shutdown past the grace period regardless of listener count.
func (d *Daemon) waitServe(serveErr <-chan error, n int) {
	deadline := time.After(d.grace)
	for i := 0; i < n; i++ {
		select {
		case <-serveErr:
		case <-deadline:
			d.log.Warn(logging.DestinationGeneral, "served handler(s) did not stop within grace period",
				"grace", d.grace.String(), "pending", n-i)
			return
		}
	}
}

// reconfigure reloads config from CONDOR_CONFIG and runs OnReconfig callbacks.
func (d *Daemon) reconfigure() {
	d.log.Info(logging.DestinationGeneral, "received SIGHUP; reloading configuration")
	// Reload preserving the original options (subsystem/local name) so <SUBSYS>.PARAM
	// overrides still resolve after a reconfig; a bare config.New() would drop them.
	cfg, err := config.NewWithOptions(d.cfg.Load().Options())
	if err != nil {
		d.log.Warn(logging.DestinationGeneral, "reconfigure: reloading config failed; keeping current", "error", err)
		return
	}
	d.cfg.Store(cfg)
	d.lastReconfig.Store(time.Now().Unix())
	// Re-apply per-destination log levels from the reloaded config, so condor_reconfig
	// changes log verbosity on the running daemon (the levels are held in a live atomic
	// snapshot the installed handlers read).
	d.log.ApplyLevels(logging.ParseDestinationLevels(d.subsys, cfg), logging.DefaultDaemonLevel)
	d.mu.Lock()
	cbs := append([]func(*config.Config){}, d.onReconfig...)
	d.mu.Unlock()
	for _, fn := range cbs {
		fn(cfg)
	}
}

// signalReady tells the master initialization is complete. No-op when standalone.
func (d *Daemon) signalReady(ctx context.Context) {
	if d.master == nil {
		return
	}
	if err := d.master.SendReady(ctx, nil); err != nil {
		d.log.Warn(logging.DestinationGeneral, "DC_SET_READY failed", "error", err, "master_addr", d.master.Address())
		return
	}
	d.log.Info(logging.DestinationGeneral, "DC_SET_READY sent", "master_addr", d.master.Address())
}

// startKeepAlive begins the DC_CHILDALIVE loop. No-op when standalone.
func (d *Daemon) startKeepAlive(ctx context.Context) {
	if d.master == nil {
		return
	}
	stop, errs, err := d.master.StartKeepAlive(ctx, nil)
	if err != nil {
		d.log.Warn(logging.DestinationGeneral, "initial DC_CHILDALIVE failed; keepalive loop not started", "error", err)
		return
	}
	d.mu.Lock()
	d.stopAlive = stop
	d.mu.Unlock()
	go func() {
		for e := range errs {
			d.log.Warn(logging.DestinationGeneral, "DC_CHILDALIVE error", "error", e)
		}
	}()
}

// masterPollInterval is how often the parent-death monitor checks whether the
// condor_master parent is still alive. Small enough that tests don't wait long,
// but a poll (not a busy loop).
const masterPollInterval = 2 * time.Second

// masterMonitor polls for the condor_master parent dying and closes goneCh when
// it does, driving Serve down the graceful-shutdown path. originalPPID is our
// parent pid recorded at Serve start (the master pid). stop halts the loop
// (closed by Serve on exit); done is closed when the goroutine returns so Serve
// can join it. It runs only under condor_master; see the call site in Serve.
func (d *Daemon) masterMonitor(originalPPID int, stop <-chan struct{}, done chan<- struct{}, goneCh chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(masterPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			currentPPID := os.Getppid()
			if masterGone(originalPPID, currentPPID, func() bool { return pidAlive(originalPPID) }) {
				d.log.Info(logging.DestinationGeneral, "condor_master parent exited; shutting down",
					"master_pid", originalPPID, "current_ppid", currentPPID)
				close(goneCh)
				return
			}
		}
	}
}

// masterGone decides whether the condor_master parent has died, given the parent
// pid recorded at Serve start (originalPPID), the current parent pid, and a probe
// that reports whether the recorded master pid is still alive.
//
// The parent changing (currentPPID != originalPPID) is the primary, race-free
// signal: under condor_master the only way our parent pid changes is the master
// exiting and us being reparented (to launchd=1 on macOS, init/a subreaper on
// Linux). It is portable across those platforms and never has a false negative —
// once reparented, os.Getppid() no longer equals the master pid. We deliberately
// do NOT key on PPID==1, since a subreaper could adopt us to a non-1 pid.
//
// As a belt-and-suspenders secondary check, a recorded master pid that no longer
// exists (masterAlive false, i.e. kill(pid,0)→ESRCH) also means gone; this covers
// the (theoretical) case where reparenting hasn't yet updated PPID.
func masterGone(originalPPID, currentPPID int, masterAlive func() bool) bool {
	if currentPPID != originalPPID {
		return true
	}
	if masterAlive != nil && !masterAlive() {
		return true
	}
	return false
}

// pidAlive reports whether pid names a live process, via signal 0. ESRCH means
// gone; EPERM means it exists but we may not signal it (still alive).
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.EPERM)
}

// stopKeepAlive halts the keepalive loop. Idempotent.
func (d *Daemon) stopKeepAlive() {
	d.mu.Lock()
	stop := d.stopAlive
	d.stopAlive = nil
	d.mu.Unlock()
	if stop != nil {
		stop()
	}
}
