package daemon

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/sharedport"
)

// UnderCondorMaster reports whether the process appears to have been spawned by
// condor_master. The signal is the CONDOR_INHERIT env var, which condor_master
// always populates for managed daemons (it carries the parent pid and the
// master's command address, and — when shared port is on — the inherited
// shared-port listener).
func UnderCondorMaster() bool {
	return os.Getenv("CONDOR_INHERIT") != ""
}

// presenceString reports whether an env var is set and its length, without
// echoing its (secret-bearing) contents.
func presenceString(v string) string {
	if v == "" {
		return "<unset>"
	}
	return fmt.Sprintf("<set, %d bytes>", len(v))
}

// logEnvDiagnostic logs whether the daemon-core inheritance env vars are
// present, so an operator debugging a shared-port wiring problem can tell at a
// glance whether the master engaged the daemon-core code path.
//
// We deliberately do NOT log the env-var contents. CONDOR_PRIVATE_INHERIT holds
// the family-session key the master uses to authenticate this child to its
// peers, and CONDOR_INHERIT's SharedPort: token embeds the shared-port cookie
// (a long-lived per-master secret used for SCM_RIGHTS fd-pass auth). Presence +
// length is enough for the diagnostic without spilling secrets into logs.
func logEnvDiagnostic(logger *logging.Logger) {
	inherit := os.Getenv("CONDOR_INHERIT")
	private := os.Getenv("CONDOR_PRIVATE_INHERIT")
	parent := os.Getenv("CONDOR_PARENT_ID")
	if inherit == "" {
		logger.Info(logging.DestinationGeneral, "daemon-core env: CONDOR_INHERIT not set; running standalone")
		return
	}
	hasSharedPort := strings.Contains(inherit, "SharedPort:")
	logger.Info(logging.DestinationGeneral, "daemon-core env",
		"CONDOR_INHERIT", presenceString(inherit),
		"CONDOR_PARENT_ID", presenceString(parent),
		"CONDOR_PRIVATE_INHERIT", presenceString(private),
		"shared_port_token", hasSharedPort)
}

// resolveSharedPortListener returns a sharedport.Listener built from the
// listening UDS fd condor_master inherited to us via CONDOR_INHERIT. Returns
// (nil, nil) when no shared-port endpoint was passed — the caller should then
// fall back to its own bind.
//
// When the master spawns us as a DaemonCore daemon with shared port on, it
// constructs a SharedPortEndpoint, binds a UDS at
// $(DAEMON_SOCKET_DIR)/<endpoint_name>, serializes the fd into CONDOR_INHERIT as
// a "SharedPort:<full_name>*<fd>*<state>*…" token, and passes the fd through
// fork+exec. By the time we start, that listening fd is already open; we just
// find the SharedPort: token and wrap the fd as a net.Listener.
func resolveSharedPortListener(logger *logging.Logger) (*sharedport.Listener, string, error) {
	inherit := os.Getenv("CONDOR_INHERIT")
	if inherit == "" {
		return nil, "", nil
	}

	fd, fullName, ok := extractSharedPortFromInherit(inherit)
	if !ok {
		logger.Warn(logging.DestinationGeneral,
			"CONDOR_INHERIT lacks SharedPort: token; falling back to standalone bind",
			"hint", "ensure DC_DAEMON_LIST includes this daemon and USE_SHARED_PORT = true")
		return nil, "", nil
	}

	logf := func(format string, args ...any) {
		logger.Warn(logging.DestinationGeneral, "shared-port event", "msg", fmt.Sprintf(format, args...))
	}
	//nolint:gosec // G115: fd is a small non-negative descriptor from the CONDOR_INHERIT SharedPort token
	ln, err := sharedport.AdoptFD(uintptr(fd), sharedport.Options{
		HandshakeTimeout: 10 * time.Second,
		Logf:             logf,
	})
	if err != nil {
		return nil, "", fmt.Errorf("adopt inherited shared-port fd %d (endpoint %s): %w", fd, endpointBaseName(fullName), err)
	}
	// fullName is "<cookie>/<endpoint_name>"; the endpoint name is also our
	// shared-port "sock" id. Log only the basename so an unprivileged reader of
	// the log can't lift the per-master cookie.
	endpoint := endpointBaseName(fullName)
	logger.Info(logging.DestinationGeneral, "accepting shared-port forwarded connections",
		"endpoint", endpoint, "inherited_fd", fd)
	return ln, endpoint, nil
}

// endpointBaseName extracts the basename ("ccb") from a SharedPort full_name of
// the form "<cookie>/<endpoint_name>". Malformed inputs return "<unknown>" —
// never the input verbatim — so a log-scrub regression doesn't leak the cookie.
func endpointBaseName(fullName string) string {
	if i := strings.LastIndexByte(fullName, '/'); i >= 0 && i+1 < len(fullName) {
		return fullName[i+1:]
	}
	return "<unknown>"
}

// extractSharedPortFromInherit parses CONDOR_INHERIT and returns the inherited
// fd and full endpoint name from the SharedPort: token (if any). Returns
// ok=false when the token is absent or malformed.
//
// Format (daemon_core.cpp extractInheritedSocks):
//
//	<ppid> <psinful> <inherit-list>... 0 <remaining-items>...
//
// One of the remaining items may be "SharedPort:<full_name>*<fd>*<...>" where
// the fields after `*` are the serialized ReliSock.
func extractSharedPortFromInherit(inherit string) (fd int, fullName string, ok bool) {
	const prefix = "SharedPort:"
	for _, tok := range strings.Fields(inherit) {
		if !strings.HasPrefix(tok, prefix) {
			continue
		}
		body := tok[len(prefix):]
		i := strings.IndexByte(body, '*')
		if i < 0 {
			return 0, "", false
		}
		fullName = body[:i]
		rest := body[i+1:]
		fdStr := rest
		if j := strings.IndexByte(rest, '*'); j >= 0 {
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

// resolveInheritedListener adopts the command-socket TCP listener that condor_master
// pre-created and passed down through CONDOR_INHERIT's inherit-list, which is how a daemon
// receives its command socket when USE_SHARED_PORT=False (there is no SharedPort: token
// then). Returns (nil, nil) when no adoptable inherited stream socket is present, so the
// caller falls back to a standalone bind. See issue #119.
func resolveInheritedListener(logger *logging.Logger) net.Listener {
	inherit := os.Getenv("CONDOR_INHERIT")
	if inherit == "" {
		return nil
	}
	fd, ok := extractInheritedCommandSocket(inherit)
	if !ok {
		return nil
	}
	//nolint:gosec // G115: fd is a small non-negative descriptor from the CONDOR_INHERIT inherit-list
	f := os.NewFile(uintptr(fd), "inherited-command-socket")
	if f == nil {
		return nil
	}
	ln, err := net.FileListener(f)
	_ = f.Close() // net.FileListener dup'd the fd; release our reference to the original
	if err != nil {
		// The inherited fd was not a stream listener (e.g. only a UDP SafeSock was passed,
		// or the fd is not adoptable): fall back to a standalone bind rather than fail.
		logger.Warn(logging.DestinationGeneral,
			"inherited command socket not adoptable; falling back to standalone bind",
			"fd", fd, "error", err.Error())
		return nil
	}
	logger.Info(logging.DestinationGeneral,
		"adopted inherited command socket from condor_master", "fd", fd, "addr", ln.Addr().String())
	return ln
}

// extractInheritedCommandSocket parses CONDOR_INHERIT's inherit-list -- the serialized
// command sockets before the "0" sentinel -- and returns the fd of the FIRST one: the
// ReliSock TCP command-port listener condor_master pre-created (it creates the stream
// ReliSock before the optional UDP SafeSock, so the first entry is the listener to adopt).
// Returns ok=false when the inherit-list is empty (the sentinel is first) or malformed.
//
// Format (daemon_core.cpp extractInheritedSocks):
//
//	<ppid> <psinful> <sock1> <sock2> ... 0 <remaining-items>...
//
// Each sockN is a serialized ReliSock/SafeSock, "<fd>*<state>*..." (the same encoding the
// SharedPort: token carries after its endpoint name).
func extractInheritedCommandSocket(inherit string) (fd int, ok bool) {
	fields := strings.Fields(inherit)
	if len(fields) < 3 {
		return 0, false // need at least ppid, psinful, and a sock or the "0" sentinel
	}
	first := fields[2] // the first inherit-list entry, or the sentinel if none
	if first == "0" {
		return 0, false // no inherited sockets
	}
	fdStr := first
	if i := strings.IndexByte(first, '*'); i >= 0 {
		fdStr = first[:i]
	}
	n, err := strconv.Atoi(fdStr)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
