//go:build integration

package htcondor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSelfSignedCert generates an ECDSA self-signed certificate valid for
// 127.0.0.1/localhost, writes cert.pem + key.pem into dir, and returns their
// paths plus a CertPool that trusts it (for the client side of the test).
func writeSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "htcondor-api-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil { //nolint:gosec // test cert, world-readable is fine
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("append cert to pool")
	}
	return certPath, keyPath, pool
}

// TestHTCondorAPIServesTLSOverSharedPort stands up the real htcondor-api binary
// as a condor_master-managed daemon configured exactly like docs/server.md's
// 50-htcondor-api.conf (DC_DAEMON_LIST=+HTTP_API, a fixed -sock endpoint name,
// SHARED_PORT_HTTP_FORWARDING_ID), with TLS enabled. It then makes an HTTPS
// request to the pool's single shared port and asserts that condor_shared_port
// sniffed the TLS ClientHello, forwarded the connection to htcondor-api over the
// inherited shared-port endpoint, and that htcondor-api terminated TLS (with our
// cert) and answered /healthz.
func TestHTCondorAPIServesTLSOverSharedPort(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping condor_master integration test in -short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH")
	}

	// Everything the daemon and shared_port touch (the binary, Unix-domain
	// sockets, the DB,
	// the log, the TLS cert) lives under one short /tmp dir. The shared-port
	// UDS paths must stay under the OS sun_path limit (~104 bytes on macOS), and
	// t.TempDir()'s long /var/folders/... paths blow that budget, so we use a
	// short MkdirTemp dir and clean it up ourselves.
	workDir, err := os.MkdirTemp("/tmp", "htca") //nolint:usetesting // need a short path, not t.TempDir()'s long one
	if err != nil {
		t.Fatalf("mkdir workDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workDir) })
	sockDir := filepath.Join(workDir, "sock")
	if err := os.MkdirAll(sockDir, 0o700); err != nil {
		t.Fatalf("mkdir sockDir: %v", err)
	}

	// Build the real htcondor-api binary into the short work dir.
	bin := filepath.Join(workDir, "htcondor-api")
	// -buildvcs=false: CI checkouts can't always stamp VCS metadata.
	build := exec.Command("go", "build", "-buildvcs=false", "-o", bin, "./cmd/htcondor-api")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build htcondor-api: %v", err)
	}

	certPath, keyPath, caPool := writeSelfSignedCert(t, workDir)
	dbPath := filepath.Join(workDir, "htcondor-api.db")
	// Use an absolute HTTP_API_LOG: the Go config layer expands $(LOG) against
	// its compiled default (/var/log/condor), not the harness's LOG, so a
	// $(LOG)-relative path would send the daemon's log to an unwritable dir and
	// fall back to stdout. An absolute path is honored verbatim.
	daemonLog := filepath.Join(workDir, "HTTPApiLog")

	// The fixed endpoint name "http_api" ties three things together: the
	// master names HTTP_API's shared-port endpoint via -sock, shared_port
	// forwards HTTP/TLS to that name, and our daemon adopts that exact
	// inherited endpoint.
	const endpoint = "http_api"
	extraConfig := fmt.Sprintf(`
DAEMON_LIST = MASTER, COLLECTOR, SHARED_PORT, SCHEDD, HTTP_API
DC_DAEMON_LIST = +HTTP_API
DAEMON_SOCKET_DIR = %[1]s
SHARED_PORT_HTTP_FORWARDING_ID = %[2]s
SHARED_PORT_PORT = 0
SHARED_PORT_LOG = $(LOG)/SharedPortLog
SHARED_PORT_DEBUG = D_FULLDEBUG D_COMMAND
HTTP_API = %[3]s
HTTP_API_ARGS = -sock %[2]s
HTTP_API_LOG = %[7]s
HTTP_API_DEBUG = D_FULLDEBUG D_COMMAND
HTTP_API_TLS_CERT = %[4]s
HTTP_API_TLS_KEY = %[5]s
HTTP_API_DB_PATH = %[6]s
HTTP_API_LISTEN = 127.0.0.1:0
MASTER_DEBUG = D_FULLDEBUG D_COMMAND
`, sockDir, endpoint, bin, certPath, keyPath, dbPath, daemonLog)

	h := SetupCondorHarnessWithConfig(t, extraConfig)
	defer h.Shutdown()

	// 1. The daemon adopts the inherited shared-port endpoint (proves it is
	//    serving forwarded connections, not a private TCP bind).
	if !waitForLog(t, daemonLog, "accepting shared-port forwarded connections", 30*time.Second) {
		dumpDaemonLog(t, daemonLog)
		if b, err := os.ReadFile(filepath.Join(h.GetLogDir(), "MasterLog")); err == nil {
			t.Logf("=== MasterLog ===\n%s", b)
		}
		t.Fatal("htcondor-api did not adopt the inherited shared-port endpoint")
	}

	// 2. Discover the single shared-port TCP port.
	spAdPath := filepath.Join(h.GetLockDir(), "shared_port_ad")
	var spPort int
	if !assertEventually(30*time.Second, 250*time.Millisecond, func() bool {
		p, ok := readSharedPortPort(spAdPath)
		spPort = p
		return ok
	}) {
		t.Fatalf("shared_port_ad never appeared at %s", spAdPath)
	}
	target := fmt.Sprintf("127.0.0.1:%d", spPort)
	t.Logf("HTTPS via shared_port at %s (endpoint %q)", target, endpoint)

	// 3. Make an HTTPS request through the shared port. A successful TLS
	//    handshake against our CA proves shared_port forwarded the ClientHello
	//    and htcondor-api terminated TLS; a 200 /healthz proves the request
	//    reached the daemon.
	tlsCfg := &tls.Config{RootCAs: caPool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	var lastErr error
	var lastBody string
	ok := assertEventually(45*time.Second, 1*time.Second, func() bool {
		d := &net.Dialer{Timeout: 3 * time.Second}
		conn, err := tls.DialWithDialer(d, "tcp", target, tlsCfg)
		if err != nil {
			lastErr = err // includes handshake failures
			return false
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte("GET /healthz HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")); err != nil {
			lastErr = err
			return false
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil && n == 0 {
			lastErr = err
			return false
		}
		lastBody = string(buf[:n])
		if !strings.Contains(lastBody, "200") || !strings.Contains(lastBody, "ok") {
			lastErr = fmt.Errorf("unexpected response: %q", lastBody)
			return false
		}
		return true
	})
	if !ok {
		dumpDaemonLog(t, daemonLog)
		if spLog, err := os.ReadFile(filepath.Join(h.GetLogDir(), "SharedPortLog")); err == nil {
			t.Logf("=== SharedPortLog ===\n%s", spLog)
		}
		t.Fatalf("HTTPS /healthz over shared_port did not succeed; last error: %v, last body: %q", lastErr, lastBody)
	}
	t.Logf("HTTPS /healthz over shared_port succeeded: %q", strings.SplitN(lastBody, "\r\n", 2)[0])
}
