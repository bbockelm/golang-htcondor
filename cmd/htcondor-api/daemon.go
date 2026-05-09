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
	"fmt"
	"log"
	"os"
	"strconv"
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

// logCondorEnvDiagnostic logs whether the daemon-core inheritance
// env vars condor_master uses are present, so an operator debugging
// a shared-port wiring problem can tell at a glance whether the
// master engaged the daemon-core code path.
//
// Critically: we do NOT log the env-var contents themselves. They
// carry secrets — CONDOR_PRIVATE_INHERIT holds the family-session
// key the master uses to authenticate this child to its peers, and
// CONDOR_INHERIT's SharedPort: token embeds the shared-port cookie
// (a long-lived per-master secret used for SCM_RIGHTS fd-pass auth).
// Even truncating "SharedPort:<...>" still leaks the cookie when it
// appears earlier in the string — and the master's command sinful,
// which we used to log, can include hostname / addrs / sock fields
// that some operators consider sensitive in shared-pool deployments.
//
// Presence + length is enough for the diagnostic ("is the master
// passing what we expect?") without spilling material into logs
// that may ship to a central aggregator. Use of stdlib log is
// intentional — runs before flag.Parse so even -h leaves a trace.
func logCondorEnvDiagnostic() {
	inherit := os.Getenv("CONDOR_INHERIT")
	private := os.Getenv("CONDOR_PRIVATE_INHERIT")
	parent := os.Getenv("CONDOR_PARENT_ID")
	if inherit == "" {
		log.Printf("daemon-core env: CONDOR_INHERIT not set; will run in standalone mode")
		return
	}
	// Probe the SharedPort: token without echoing its contents.
	hasSharedPort := strings.Contains(inherit, "SharedPort:")
	log.Printf("daemon-core env: CONDOR_INHERIT=%s CONDOR_PARENT_ID=%s CONDOR_PRIVATE_INHERIT=%s shared_port_token=%v",
		presenceString(inherit), presenceString(parent), presenceString(private), hasSharedPort)
}

func presenceString(v string) string {
	if v == "" {
		return "<unset>"
	}
	return fmt.Sprintf("<set, %d bytes>", len(v))
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

// resolveSharedPortListener returns a sharedport.Listener built from
// the listening UDS fd condor_master inherited to us via CONDOR_INHERIT.
// Returns (nil, nil) when no shared-port endpoint was passed — the
// caller should then fall back to its own TCP bind (or refuse, depending
// on policy).
//
// Architecture: when the master spawns us as a DaemonCore daemon
// (DC_DAEMON_LIST = +HTTP_API), it constructs a SharedPortEndpoint,
// calls CreateListener() on it (which binds a UDS at
// $(DAEMON_SOCKET_DIR)/<endpoint_name>), serializes the fd into
// CONDOR_INHERIT as a "SharedPort:<full_name>*<fd>*<state>*…" token,
// and includes the fd in the inheritFds[] passed to fork+exec. By
// the time our process starts, that listening fd is already open in
// our fd table. We just have to find the SharedPort: token and wrap
// the fd as a net.Listener.
//
// Why not bind our own UDS instead? The endpoint name has a master-pid
// suffix (e.g. "http_api_29_7856") that we can't predict ahead of time
// — and shared_port_server only forwards to endpoints the master told
// it about. So adopting the inherited fd is both correct and the only
// path that works without OOB coordination.
//
// CONDOR_INHERIT format ([daemon_core.cpp:9007 extractInheritedSocks](
// reference/htcondor/src/condor_daemon_core.V6/daemon_core.cpp)):
//
//	<ppid> <psinful> [1 <relisock>|2 <safesock>]... 0 [SharedPort:<...>] 0
//
// Tokens are space-separated; "0" is end-of-cedar-socks; remaining
// tokens are passed to the C++ "remaining items" loop, where the
// SharedPort:-prefixed entry is intercepted and used to deserialize a
// SharedPortEndpoint. We do the same: skip parent metadata, walk
// past the cedar-socks "0" terminator, and look for SharedPort:.
func resolveSharedPortListener(_ *config.Config, logger *logging.Logger) (*sharedport.Listener, error) {
	inherit := os.Getenv("CONDOR_INHERIT")
	if inherit == "" {
		return nil, nil
	}

	fd, fullName, ok := extractSharedPortFromInherit(inherit)
	if !ok {
		// Master didn't pass a SharedPort: token. Could be:
		//   - we're not running as a DC daemon (DC_DAEMON_LIST missing
		//     us — but in that case CONDOR_INHERIT itself would be
		//     unset, so we wouldn't be here)
		//   - shared_port is disabled at the master (USE_SHARED_PORT=
		//     false), in which case master would set up TCP command
		//     sockets via "1 <relisock>" entries and we'd need a
		//     different code path. Today our binary doesn't speak that
		//     model; falling back to a regular TCP bind is the right
		//     thing for now and matches the legacy non-DC behavior.
		logger.Warn(logging.DestinationHTTP,
			"CONDOR_INHERIT lacks SharedPort: token; falling back to standalone TCP bind",
			"hint", "ensure DC_DAEMON_LIST = +HTTP_API and USE_SHARED_PORT = true")
		return nil, nil
	}

	logf := func(format string, args ...any) {
		logger.Warn(logging.DestinationHTTP, "shared-port event", "msg", fmt.Sprintf(format, args...))
	}
	ln, err := sharedport.AdoptFD(uintptr(fd), sharedport.Options{
		HandshakeTimeout: 10 * time.Second,
		Logf:             logf,
	})
	if err != nil {
		return nil, fmt.Errorf("adopt inherited shared-port fd %d (endpoint %s): %w", fd, endpointBaseName(fullName), err)
	}
	// fullName is "<cookie>/<endpoint_name>". The cookie is a
	// long-lived per-master secret used to authenticate
	// SCM_RIGHTS fd-pass requests from shared_port_server, and
	// HttpApiLog is world-readable on stock HTCondor installs —
	// log only the endpoint basename so an unprivileged user
	// reading the log can't lift the cookie out.
	logger.Info(logging.DestinationHTTP, "Accepting shared-port forwarded connections",
		"endpoint", endpointBaseName(fullName), "inherited_fd", fd)
	return ln, nil
}

// endpointBaseName extracts the basename ("http_api") from a
// SharedPort full_name of the form "<cookie>/<endpoint_name>". When
// the input doesn't match that shape (rare malformed inputs), we
// return "<unknown>" — never the input verbatim — so a log-scrub
// regression doesn't fail open.
func endpointBaseName(fullName string) string {
	if i := strings.LastIndexByte(fullName, '/'); i >= 0 && i+1 < len(fullName) {
		return fullName[i+1:]
	}
	return "<unknown>"
}

// extractSharedPortFromInherit parses CONDOR_INHERIT and returns the
// inherited fd and full endpoint name from the SharedPort: token (if
// any). Returns ok=false when the token is absent or malformed.
//
// Format (per the C++ comment at daemon_core.cpp:9134-9143):
//
//	<ppid> <psinful> <inherit-list>... 0 <remaining-items>...
//
// One of the remaining items may be "SharedPort:<full_name>*<fd>*<...>"
// where the fields after `*` are the serialized ReliSock — see
// shared_port_endpoint.cpp:1221 (serialize) and sock.cpp:2310
// (Sock::serialize, which writes <fd>*<state>*<timeout>*… first).
func extractSharedPortFromInherit(inherit string) (fd int, fullName string, ok bool) {
	const prefix = "SharedPort:"
	for _, tok := range strings.Fields(inherit) {
		if !strings.HasPrefix(tok, prefix) {
			continue
		}
		// Strip prefix; the body is "<full_name>*<fd>*<rest>".
		body := tok[len(prefix):]
		i := strings.IndexByte(body, '*')
		if i < 0 {
			return 0, "", false
		}
		fullName = body[:i]
		rest := body[i+1:]
		j := strings.IndexByte(rest, '*')
		fdStr := rest
		if j >= 0 {
			fdStr = rest[:j]
		}
		n, err := strconv.Atoi(fdStr)
		if err != nil || n < 0 {
			return 0, "", false
		}
		return n, fullName, true
	}
	return 0, "", false
}
