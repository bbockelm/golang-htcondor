package daemon

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/sharedport"
)

// selfRegisterSharedPort binds this daemon's own named socket in the shared-port socket
// directory so the shared_port server routes forwarded connections to it. It is used when
// the daemon was NOT handed an inherited shared-port fd (started outside condor_master, or
// the master did not pass one) but shared port is in use -- rather than falling back to a
// standalone TCP bind that peers cannot reach through the shared port.
//
// This is the client-created-socket half of HTCondor's SharedPortEndpoint: bind a UDS at
// <DAEMON_SOCKET_DIR>/<sock>, and the shared_port server (which connects as root and tries
// the on-disk socket directory even on Linux) forwards accepted TCP connections to it via
// SCM_RIGHTS. The receive side is the same protocol sharedport.Listen already speaks for
// the inherited-fd case.
//
// It returns the listener, the chosen "sock" id, and the advertised sinful
// (host:port?sock=id) derived from the shared_port server's ad file. It returns
// (nil, "", "", nil) -- telling the caller to fall back to a standalone bind -- when
// self-registration does not apply: shared port disabled for this subsystem, no usable
// socket directory, or the shared_port server ad (hence a routable address) is
// unavailable. A hard bind failure is returned as an error.
func selfRegisterSharedPort(cfg *config.Config, subsys string, logger *logging.Logger) (*sharedport.Listener, string, string, error) {
	if cfg == nil || !sharedPortEnabled(cfg, subsys) {
		return nil, "", "", nil
	}
	socketDir := daemonSocketDir(cfg)
	if socketDir == "" {
		logger.Warn(logging.DestinationGeneral,
			"shared-port self-registration skipped: no DAEMON_SOCKET_DIR available; falling back to standalone bind")
		return nil, "", "", nil
	}
	serverAddr, err := sharedPortServerAddress(cfg)
	if err != nil {
		// Without the server's public address we can't advertise a reachable sinful, and
		// a socket nobody routes to is useless -- fall back to a standalone bind.
		logger.Warn(logging.DestinationGeneral,
			"shared-port self-registration skipped; falling back to standalone bind",
			"reason", err.Error())
		return nil, "", "", nil
	}
	sock := generateEndpointName(subsys)
	advertised, ok := deriveAdvertisedSinful(serverAddr, sock)
	if !ok {
		logger.Warn(logging.DestinationGeneral,
			"shared-port self-registration skipped: shared_port server address unusable; falling back to standalone bind",
			"server_address", serverAddr)
		return nil, "", "", nil
	}

	socketPath := filepath.Join(socketDir, sock)
	logf := func(format string, args ...any) {
		logger.Warn(logging.DestinationGeneral, "shared-port event", "msg", fmt.Sprintf(format, args...))
	}
	ln, err := sharedport.Listen(socketPath, sharedport.Options{
		HandshakeTimeout: 10 * time.Second,
		Logf:             logf,
	})
	if err != nil {
		return nil, "", "", fmt.Errorf("bind shared-port socket %s: %w", socketPath, err)
	}
	return ln, sock, advertised, nil
}

// sharedPortEnabled reports whether shared port is enabled for this subsystem:
// <SUBSYS>_USE_SHARED_PORT if set, else USE_SHARED_PORT (default true).
func sharedPortEnabled(cfg *config.Config, subsys string) bool {
	if subsys != "" {
		if v, ok := cfg.Get(strings.ToUpper(subsys) + "_USE_SHARED_PORT"); ok {
			return configTruthy(v)
		}
	}
	if v, ok := cfg.Get("USE_SHARED_PORT"); ok {
		return configTruthy(v)
	}
	return true
}

// daemonSocketDir resolves DAEMON_SOCKET_DIR, expanding the "auto" default to
// $(LOCK)/daemon_sock -- matching HTCondor's GetAltDaemonSocketDir on-disk directory,
// which the shared_port server always tries (even in the Linux abstract-socket default).
func daemonSocketDir(cfg *config.Config) string {
	if dir, ok := cfg.Get("DAEMON_SOCKET_DIR"); ok {
		if d := strings.TrimSpace(dir); d != "" && d != "auto" {
			return d
		}
	}
	lock, _ := cfg.Get("LOCK")
	if lock = strings.TrimSpace(lock); lock == "" {
		return ""
	}
	return filepath.Join(lock, "daemon_sock")
}

// sharedPortServerAddress reads the shared_port server's public sinful (the MyAddress
// attribute) from its ad file (SHARED_PORT_DAEMON_AD_FILE, default $(LOCK)/shared_port_ad),
// which the server writes on startup. That address fronts the shared port's TCP endpoint,
// so it is the host:port a peer dials to reach us via our sock id.
func sharedPortServerAddress(cfg *config.Config) (string, error) {
	adFile, _ := cfg.Get("SHARED_PORT_DAEMON_AD_FILE")
	adFile = strings.TrimSpace(adFile)
	if adFile == "" {
		return "", fmt.Errorf("SHARED_PORT_DAEMON_AD_FILE not configured")
	}
	data, err := os.ReadFile(adFile) //nolint:gosec // G304: operator-configured ad-file path from HTCondor config
	if err != nil {
		return "", fmt.Errorf("reading shared_port server ad %s: %w", adFile, err)
	}
	ad, err := classad.ParseOld(string(data))
	if err != nil {
		return "", fmt.Errorf("parsing shared_port server ad %s: %w", adFile, err)
	}
	addr, ok := ad.EvaluateAttrString("MyAddress")
	if !ok || strings.TrimSpace(addr) == "" {
		return "", fmt.Errorf("shared_port server ad %s has no MyAddress", adFile)
	}
	return strings.TrimSpace(addr), nil
}

// generateEndpointName builds a per-daemon shared-port socket id of the form
// <subsys>_<pid>_<rand4hex>, matching HTCondor's SharedPortEndpoint naming. The random
// tag guards against PID reuse; the subsystem is lower-cased. The result satisfies the
// server's socket-id charset ([A-Za-z0-9._-]) for any alphanumeric subsystem name.
func generateEndpointName(subsys string) string {
	name := strings.ToLower(strings.TrimSpace(subsys))
	if name == "" {
		name = "daemon"
	}
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand should never fail; fall back to a fixed tag rather than panic.
		b[0], b[1] = 0, 0
	}
	return fmt.Sprintf("%s_%d_%02x%02x", name, os.Getpid(), b[0], b[1])
}
