//go:build linux

package httpserver

import (
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/droppriv"
)

// The access-point case: the TLS key is root-owned under a directory the
// condor account cannot traverse, and the daemon serving HTTPS has
// dropped to that account.
//
// http.Server.ServeTLS(ln, certFile, keyFile) reads those paths itself,
// with a plain os.ReadFile, so it fails at startup with "permission
// denied" -- the same failure as the KEK and the token signing key.
//
// Requires root; skipped otherwise.
func TestServeTLSReadsARootOnlyKeyAfterDrop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root privileges")
	}

	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir, 0o600)
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: root-only is the fixture
		t.Fatal(err)
	}

	mgr, err := droppriv.NewManager(droppriv.Config{Enabled: true, CondorUser: "nobody"})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start (drop to nobody): %v", err)
	}
	defer func() { _ = mgr.Stop() }()

	// Precondition: the plain read really is denied.
	if _, err := os.ReadFile(keyPath); err == nil { //nolint:gosec // G304: test path
		t.Fatal("the TLS key was readable as nobody; the fixture proves nothing")
	}

	if _, err := loadKeyPairMaybeAsRoot(certPath, keyPath); err != nil {
		t.Fatalf("loadKeyPairMaybeAsRoot after drop: %v", err)
	}

	// And it actually serves: the certificate is installed on TLSConfig
	// rather than ServeTLS opening the (unreadable) files.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second}
	defer func() { _ = srv.Close() }()
	errCh := make(chan error, 1)
	go func() { errCh <- serveTLSWithCredentials(srv, ln, certPath, keyPath, nil, time.Minute) }()

	select {
	case err := <-errCh:
		t.Fatalf("serving stopped immediately: %v", err)
	case <-time.After(300 * time.Millisecond):
		// Still serving, which is the pass condition.
	}
}
