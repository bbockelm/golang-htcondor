package httpserver

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeKeyPairCN writes a self-signed pair with a given CommonName so a
// test can tell one generation of certificate from the next.
func writeKeyPairCN(t *testing.T, dir, cn string) (certPath, keyPath string) {
	t.Helper()
	return writeKeyPairNamed(t, dir, cn, "tls.crt", "tls.key")
}

func leafCN(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}
	return leaf.Subject.CommonName
}

// A renewed keypair takes effect without restarting: that is the whole
// point of reloading rather than reading once at startup.
func TestCertReloaderPicksUpARenewal(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPairCN(t, dir, "before")

	r, err := newCertReloader(certPath, keyPath, time.Minute, nil)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	got, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cn := leafCN(t, got); cn != "before" {
		t.Fatalf("serving %q, want before", cn)
	}

	// Renew both files, then let the interval elapse.
	writeKeyPairCN(t, dir, "after")
	r.now = func() time.Time { return time.Now().Add(2 * time.Minute) }

	got, err = r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cn := leafCN(t, got); cn != "after" {
		t.Errorf("serving %q after renewal, want after", cn)
	}
}

// The atomicity requirement: a renewal writes the certificate and the
// key separately, so a read can land between the two and see a new
// certificate with the old key. That pair must never be installed --
// every handshake using it would fail.
func TestCertReloaderRefusesAMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPairCN(t, dir, "before")

	r, err := newCertReloader(certPath, keyPath, time.Minute, nil)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	// A new certificate lands; its key has not been written yet, so the
	// old key is still on disk. This is exactly the mid-renewal window.
	newDir := t.TempDir()
	newCert, _ := writeKeyPairCN(t, newDir, "after")
	b, err := os.ReadFile(newCert) //nolint:gosec // G304: test path
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, b, 0o644); err != nil { //nolint:gosec // G306: a certificate is public
		t.Fatal(err)
	}

	r.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	got, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate returned an error instead of the working keypair: %v", err)
	}
	if cn := leafCN(t, got); cn != "before" {
		t.Errorf("serving %q; a certificate whose key does not match it must not be installed", cn)
	}

	// And once the matching key lands, the swap happens.
	newCert2, newKey2 := writeKeyPairCN(t, t.TempDir(), "complete")
	for _, f := range [][2]string{{newCert2, certPath}, {newKey2, keyPath}} {
		b, err := os.ReadFile(f[0]) //nolint:gosec // G304: test path
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f[1], b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r.now = func() time.Time { return time.Now().Add(4 * time.Minute) }
	got, err = r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cn := leafCN(t, got); cn != "complete" {
		t.Errorf("serving %q after a complete renewal, want complete", cn)
	}
}

// Truncated PEM -- the other half-written shape -- is likewise refused.
func TestCertReloaderRefusesATruncatedFile(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPairCN(t, dir, "before")

	r, err := newCertReloader(certPath, keyPath, time.Minute, nil)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	if err := os.WriteFile(keyPath, []byte("-----BEGIN EC PRIVATE KEY-----\nhalf"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return time.Now().Add(2 * time.Minute) }

	got, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate errored on a half-written key: %v", err)
	}
	if cn := leafCN(t, got); cn != "before" {
		t.Errorf("serving %q; a half-written key must not replace a working one", cn)
	}
}

// Unchanged files are not re-parsed into a new certificate; the reloader
// keeps serving the same object.
func TestCertReloaderKeepsTheSameCertificateWhenNothingChanged(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPairCN(t, dir, "steady")

	r, err := newCertReloader(certPath, keyPath, time.Minute, nil)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	first, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	second, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("the certificate was swapped although neither file changed")
	}
}

// Startup is the one place a bad keypair is fatal: a daemon that cannot
// serve HTTPS should say so rather than come up refusing connections.
func TestNewCertReloaderFailsOnAnUnreadableKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unreadable file cannot be produced")
	}
	dir := t.TempDir()
	certPath, keyPath := writeKeyPairCN(t, dir, "x")
	if err := os.Chmod(keyPath, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := newCertReloader(certPath, keyPath, time.Minute, nil); err == nil {
		t.Error("a reloader was built on an unreadable key")
	}
}

var _ = filepath.Join
