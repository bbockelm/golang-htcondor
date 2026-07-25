package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/sharedport"
)

func spConfig(t *testing.T, text string) *config.Config {
	t.Helper()
	cfg, err := config.NewFromReader(strings.NewReader(text))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func TestGenerateEndpointName(t *testing.T) {
	name := generateEndpointName("COLLECTOR")
	// <subsys-lower>_<pid>_<4hex>, and within the server's [A-Za-z0-9._-] charset.
	re := regexp.MustCompile(`^collector_[0-9]+_[0-9a-f]{4}$`)
	if !re.MatchString(name) {
		t.Errorf("generateEndpointName = %q, want match %s", name, re)
	}
	if !strings.HasPrefix(name, fmt.Sprintf("collector_%d_", os.Getpid())) {
		t.Errorf("name %q missing pid segment", name)
	}
	// Two calls differ in the random tag.
	first, second := generateEndpointName("X"), generateEndpointName("X")
	if first == second {
		t.Error("expected distinct random tags across calls")
	}
	// Empty subsystem falls back to a valid default.
	if got := generateEndpointName(""); !strings.HasPrefix(got, "daemon_") {
		t.Errorf("empty subsys = %q, want daemon_ prefix", got)
	}
}

func TestDaemonSocketDir(t *testing.T) {
	// "auto" (the default) -> $(LOCK)/daemon_sock.
	cfg := spConfig(t, "LOCK = /var/lock/condor\nDAEMON_SOCKET_DIR = auto\n")
	if got, want := daemonSocketDir(cfg), "/var/lock/condor/daemon_sock"; got != want {
		t.Errorf("auto: got %q want %q", got, want)
	}
	// Explicit directory wins.
	cfg = spConfig(t, "DAEMON_SOCKET_DIR = /run/condor/sock\n")
	if got := daemonSocketDir(cfg); got != "/run/condor/sock" {
		t.Errorf("explicit: got %q", got)
	}
}

func TestSharedPortEnabled(t *testing.T) {
	// Default is on.
	if !sharedPortEnabled(spConfig(t, ""), "COLLECTOR") {
		t.Error("default USE_SHARED_PORT should be enabled")
	}
	// Global off.
	if sharedPortEnabled(spConfig(t, "USE_SHARED_PORT = false\n"), "COLLECTOR") {
		t.Error("USE_SHARED_PORT=false should disable")
	}
	// Per-subsystem override beats the global.
	cfg := spConfig(t, "USE_SHARED_PORT = true\nHAD_USE_SHARED_PORT = false\n")
	if sharedPortEnabled(cfg, "HAD") {
		t.Error("HAD_USE_SHARED_PORT=false should disable for HAD")
	}
	if !sharedPortEnabled(cfg, "COLLECTOR") {
		t.Error("COLLECTOR should still follow the enabled global")
	}
}

func TestSharedPortServerAddress(t *testing.T) {
	dir := t.TempDir()
	adFile := filepath.Join(dir, "shared_port_ad")
	if err := os.WriteFile(adFile, []byte("MyType = \"shared_port\"\nMyAddress = \"<127.0.0.1:9618?addrs=127.0.0.1-9618&noUDP>\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := spConfig(t, "SHARED_PORT_DAEMON_AD_FILE = "+adFile+"\n")
	got, err := sharedPortServerAddress(cfg)
	if err != nil {
		t.Fatalf("sharedPortServerAddress: %v", err)
	}
	if got != "<127.0.0.1:9618?addrs=127.0.0.1-9618&noUDP>" {
		t.Errorf("MyAddress = %q", got)
	}
	// Missing ad file -> error.
	cfg = spConfig(t, "SHARED_PORT_DAEMON_AD_FILE = "+filepath.Join(dir, "absent")+"\n")
	if _, err := sharedPortServerAddress(cfg); err == nil {
		t.Error("missing ad file should error")
	}
}

// TestSelfRegisterSharedPort exercises the whole wiring: bind a UDS in the socket dir,
// derive a routable advertised sinful from the server ad, and actually receive a
// connection forwarded to that socket via the shared_port fd-pass protocol.
func TestSelfRegisterSharedPort(t *testing.T) {
	// A short base dir: the self-registered UDS path (<lock>/daemon_sock/<sock>) must fit
	// in sockaddr_un's ~104-char sun_path, which the default long temp dir would blow.
	lock := shortTempDir(t)
	adFile := filepath.Join(lock, "shared_port_ad")
	if err := os.WriteFile(adFile, []byte("MyAddress = \"<127.0.0.1:9618?addrs=127.0.0.1-9618&noUDP>\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := spConfig(t, "LOCK = "+lock+"\nUSE_SHARED_PORT = true\n")
	logger := newTestDaemon(t).Logger()

	ln, sock, advertised, err := selfRegisterSharedPort(cfg, "TESTD", logger)
	if err != nil {
		t.Fatalf("selfRegisterSharedPort: %v", err)
	}
	if ln == nil {
		t.Fatal("expected a self-registered listener")
	}
	defer func() { _ = ln.Close() }()

	if want := "127.0.0.1:9618?sock=" + sock; advertised != want {
		t.Errorf("advertised = %q, want %q", advertised, want)
	}
	socketPath := filepath.Join(lock, "daemon_sock", sock)
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("socket not bound at %s: %v", socketPath, err)
	}

	// Forward a connection to our socket the way the shared_port server would, and prove
	// Accept hands it back with the byte stream intact.
	clientFD, passFD := mustSocketpair(t)
	defer func() { _ = clientFD.Close() }()
	defer func() { _ = passFD.Close() }()

	udsConn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("dial uds: %v", err)
	}
	defer func() { _ = udsConn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sharedport.SendForwardedConn(ctx, udsConn.(*net.UnixConn), passFD.Fd()); err != nil {
		t.Fatalf("SendForwardedConn: %v", err)
	}

	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()
	select {
	case c := <-accepted:
		if c == nil {
			t.Fatal("Accept returned nil")
		}
		defer func() { _ = c.Close() }()
		const probe = "self-register-probe"
		if _, err := clientFD.Write([]byte(probe)); err != nil {
			t.Fatalf("client write: %v", err)
		}
		buf := make([]byte, len(probe))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(buf); err != nil || string(buf) != probe {
			t.Fatalf("forwarded read = %q, %v; want %q", buf, err, probe)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not return the forwarded connection")
	}
}

// TestSelfRegisterSharedPortSkips covers the fall-back-to-standalone cases: shared port
// disabled, and no shared_port server ad available.
func TestSelfRegisterSharedPortSkips(t *testing.T) {
	logger := newTestDaemon(t).Logger()

	// USE_SHARED_PORT off -> (nil, no error): caller falls back to a standalone bind.
	ln, _, _, err := selfRegisterSharedPort(spConfig(t, "USE_SHARED_PORT = false\n"), "TESTD", logger)
	if err != nil || ln != nil {
		t.Errorf("disabled: got ln=%v err=%v, want nil,nil", ln, err)
	}

	// Enabled but no server ad file -> (nil, no error): can't advertise, fall back.
	lock := t.TempDir()
	ln, _, _, err = selfRegisterSharedPort(spConfig(t, "LOCK = "+lock+"\nUSE_SHARED_PORT = true\n"), "TESTD", logger)
	if err != nil || ln != nil {
		t.Errorf("no server ad: got ln=%v err=%v, want nil,nil", ln, err)
	}
}

// shortTempDir makes a temp dir under /tmp (not the platform default, which on macOS is a
// long path) so a Unix-domain socket created beneath it stays within sun_path's limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sp")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// mustSocketpair returns a connected pair of stream sockets as *os.File values.
func mustSocketpair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	return os.NewFile(uintptr(fds[0]), "sp0"), os.NewFile(uintptr(fds[1]), "sp1")
}
