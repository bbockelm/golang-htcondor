package main

// Daemon-mode bootstrap: when condor_master spawns htcondor-api as a
// managed daemon, it sets a few specific environment variables we use
// to wire up keepalive, ready notification, and (when the operator has
// configured shared_port HTTP forwarding) acceptance of forwarded HTTP
// connections via SCM_RIGHTS.
//
// Detection: presence of CONDOR_INHERIT means we're under condor_master.
// Anything else is "stand-alone" and we keep the existing
// runNormalMode / runDemoMode paths untouched.
//
// What we do under condor_master:
//
//   - Send DC_SET_READY once the HTTP listener is up so the master
//     knows initialization completed and can begin spawning peers
//     that depend on us.
//   - Run a DC_CHILDALIVE loop using whatever interval condor_master
//     gave us (or our default of 10 minutes / hang-timeout of 10m).
//   - If shared_port forwarding is configured (DAEMON_SOCKET_DIR plus
//     a forwarding ID either from the env or the config), bind a
//     sharedport.Listener at the right path and let http.Server.Serve
//     consume forwarded fds from it. This is in addition to or instead
//     of the regular TCP listener; we let the operator pick.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/sharedport"
)

// runUnderCondorMaster reports whether the process appears to have been
// spawned by condor_master. The signal is the CONDOR_INHERIT env var,
// which condor_master always populates for managed daemons (it carries
// the parent pid and the master's command address).
func runUnderCondorMaster() bool {
	return os.Getenv("CONDOR_INHERIT") != ""
}

// daemonHooks bundles the master-driven side-channels (keepalive +
// ready notification) so callers can defer Stop without bookkeeping.
type daemonHooks struct {
	master     *htcondor.Master
	stopAlive  func()
	stopAliveC <-chan error
	logger     *logging.Logger
}

// startDaemonHooks wires up master keepalive and ready notification.
// Returns a non-nil daemonHooks even when the master isn't reachable
// — failure to send the initial keepalive is logged but doesn't kill
// the daemon, on the theory that a transient master glitch shouldn't
// take the API server down. Persistent failures will eventually be
// surfaced via condor_master's own hang detection.
func startDaemonHooks(_ context.Context, logger *logging.Logger) (*daemonHooks, error) {
	master, err := htcondor.MasterFromEnv()
	if err != nil {
		return nil, fmt.Errorf("master env: %w", err)
	}
	logger.Info(logging.DestinationGeneral, "Detected condor_master parent",
		"parent_pid", master.ParentPID(), "master_addr", master.Address())

	hooks := &daemonHooks{
		master: master,
		logger: logger,
	}
	return hooks, nil
}

// SignalReady tells the master we've finished initialization. Safe to
// call multiple times; the master tolerates repeated DC_SET_READY.
func (h *daemonHooks) SignalReady(ctx context.Context) {
	if h == nil || h.master == nil {
		return
	}
	if err := h.master.SendReady(ctx, nil); err != nil {
		h.logger.Warn(logging.DestinationGeneral, "DC_SET_READY failed",
			"error", err, "master_addr", h.master.Address())
		return
	}
	h.logger.Info(logging.DestinationGeneral, "DC_SET_READY sent",
		"master_addr", h.master.Address())
}

// StartKeepAlive begins a DC_CHILDALIVE loop. Stop() the returned
// hooks (or cancel ctx) to halt it.
func (h *daemonHooks) StartKeepAlive(ctx context.Context) {
	if h == nil || h.master == nil {
		return
	}
	stop, errs, err := h.master.StartKeepAlive(ctx, nil)
	if err != nil {
		h.logger.Warn(logging.DestinationGeneral, "Initial DC_CHILDALIVE failed; loop not started",
			"error", err)
		return
	}
	h.stopAlive = stop
	h.stopAliveC = errs
	go func() {
		for e := range errs {
			h.logger.Warn(logging.DestinationGeneral, "DC_CHILDALIVE error", "error", e)
		}
	}()
}

// Stop tears down keepalive and ready loops. Idempotent.
func (h *daemonHooks) Stop() {
	if h == nil {
		return
	}
	if h.stopAlive != nil {
		h.stopAlive()
		h.stopAlive = nil
	}
}

// resolveSharedPortListener decides what UDS path to bind for
// shared_port HTTP forwarding, if any. Returns nil with no error when
// the operator hasn't configured forwarding.
//
// The forwarding ID is sourced (in order) from:
//
//  1. the explicit env var _HTCONDOR_API_SHARED_PORT_ID (test override)
//  2. the config knob HTTP_API_SHARED_PORT_ID
//  3. the well-known id "http_api" — only when the operator has put
//     HTTP_API in DAEMON_LIST and configured shared_port forwarding
//     in the standard way (SHARED_PORT_HTTP_FORWARDING_ID would be
//     "http_api" then, matching condor_shared_port's auto-discovery
//     in shared_port_server.cpp).
//
// DAEMON_SOCKET_DIR (the directory that holds the per-daemon UDSes)
// must be set in the HTCondor config for shared_port to know where
// to dial us. We mirror that path on the receive side.
func resolveSharedPortListener(cfg *config.Config, logger *logging.Logger) (*sharedport.Listener, error) {
	id := strings.TrimSpace(os.Getenv("_HTCONDOR_API_SHARED_PORT_ID"))
	if id == "" {
		if v, ok := cfg.Get("HTTP_API_SHARED_PORT_ID"); ok {
			id = strings.TrimSpace(v)
		}
	}
	if id == "" {
		// Auto-detect: if the operator added HTTP_API to DAEMON_LIST,
		// shared_port_server uses "http_api" as the forwarding id.
		// Match its convention.
		if list, ok := cfg.Get("DAEMON_LIST"); ok {
			for _, tok := range strings.FieldsFunc(list, func(r rune) bool {
				return r == ',' || r == ' ' || r == '\t'
			}) {
				if strings.EqualFold(strings.TrimSpace(tok), "HTTP_API") {
					id = "http_api"
					break
				}
			}
		}
	}
	if id == "" {
		return nil, nil
	}

	socketDir, ok := cfg.Get("DAEMON_SOCKET_DIR")
	if !ok || socketDir == "" {
		return nil, errors.New("HTTP_API shared-port forwarding requested but DAEMON_SOCKET_DIR is not configured")
	}
	socketPath := filepath.Join(socketDir, id)

	logf := func(format string, args ...any) {
		logger.Warn(logging.DestinationHTTP, "shared-port event", "msg", fmt.Sprintf(format, args...))
	}
	ln, err := sharedport.Listen(socketPath, sharedport.Options{
		HandshakeTimeout: 10 * time.Second,
		Logf:             logf,
	})
	if err != nil {
		return nil, fmt.Errorf("listen on shared-port endpoint %s: %w", socketPath, err)
	}
	logger.Info(logging.DestinationHTTP, "Accepting shared-port forwarded connections",
		"socket", socketPath, "id", id)
	return ln, nil
}
