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
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bbockelm/cedar/addresses"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// Options configures a Daemon.
type Options struct {
	// Subsys is the HTCondor subsystem/daemon name, e.g. "CCB". It selects the
	// per-daemon log knobs (<Subsys>_LOG, MAX_<Subsys>_LOG, <Subsys>_DEBUG) and
	// names the address file (<Subsys>_ADDRESS_FILE).
	Subsys string

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
	subsys string
	cfg    *config.Config
	log    *logging.Logger
	grace  time.Duration

	master *htcondor.Master // nil when running standalone

	mu             sync.Mutex
	sharedPortName string // shared-port "sock" id, set by Listener when adopted
	stopAlive      func()
	onReconfig     []func(*config.Config)
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

	logger := opts.Logger
	if logger == nil {
		var err error
		logger, err = logging.FromConfigWithDaemon(opts.Subsys, cfg)
		if err != nil {
			return nil, fmt.Errorf("daemon: building logger: %w", err)
		}
	}

	grace := opts.ShutdownGrace
	if grace == 0 {
		grace = 15 * time.Second
	}

	d := &Daemon{
		subsys: opts.Subsys,
		cfg:    cfg,
		log:    logger,
		grace:  grace,
	}

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
func (d *Daemon) Config() *config.Config { return d.cfg }

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
		d.mu.Unlock()
		return spln, nil
	}
	if fallback == nil {
		return nil, fmt.Errorf("daemon: no shared-port listener inherited and no fallback provided")
	}
	return fallback()
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	serveErr := make(chan error, 1)
	go func() { serveErr <- serve(ctx, ln) }()

	d.signalReady(ctx)
	d.startKeepAlive(ctx)
	defer d.stopKeepAlive()

	for {
		select {
		case err := <-serveErr:
			return err
		case <-ctx.Done():
			d.waitServe(serveErr)
			return ctx.Err()
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				d.reconfigure()
			default: // SIGTERM / SIGINT
				d.log.Info(logging.DestinationGeneral, "received termination signal; shutting down", "signal", sig.String())
				cancel()
				d.waitServe(serveErr)
				return nil
			}
		}
	}
}

// waitServe waits for the served handler to finish, bounded by ShutdownGrace.
func (d *Daemon) waitServe(serveErr <-chan error) {
	select {
	case <-serveErr:
	case <-time.After(d.grace):
		d.log.Warn(logging.DestinationGeneral, "served handler did not stop within grace period", "grace", d.grace.String())
	}
}

// reconfigure reloads config from CONDOR_CONFIG and runs OnReconfig callbacks.
func (d *Daemon) reconfigure() {
	d.log.Info(logging.DestinationGeneral, "received SIGHUP; reloading configuration")
	cfg, err := config.New()
	if err != nil {
		d.log.Warn(logging.DestinationGeneral, "reconfigure: reloading config failed; keeping current", "error", err)
		return
	}
	d.mu.Lock()
	d.cfg = cfg
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
