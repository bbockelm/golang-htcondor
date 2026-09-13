package httpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeKeyPair writes a self-signed cert/key pair and returns their paths.
func writeKeyPair(t *testing.T, dir string, keyMode os.FileMode) (certPath, keyPath string) {
	t.Helper()
	return writeKeyPairModed(t, dir, "localhost", "tls.crt", "tls.key", keyMode)
}

// writeKeyPairNamed writes a pair with a given CommonName and file names,
// 0600 on the key.
func writeKeyPairNamed(t *testing.T, dir, cn, certName, keyName string) (certPath, keyPath string) {
	t.Helper()
	return writeKeyPairModed(t, dir, cn, certName, keyName, 0o600)
}

func writeKeyPairModed(t *testing.T, dir, cn, certName, keyName string, keyMode os.FileMode) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, certName)
	keyPath = filepath.Join(dir, keyName)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil { //nolint:gosec // G306: a certificate is public
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, keyMode); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// The ordinary case still works: a readable keypair loads and serves.
func TestServeTLSWithCredentialsServesAReadableKeyPair(t *testing.T) {
	certPath, keyPath := writeKeyPair(t, t.TempDir(), 0o600)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }),
		ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- serveTLSWithCredentials(srv, ln, certPath, keyPath, nil, time.Minute) }()
	t.Cleanup(func() { _ = srv.Close() })

	// A handshake proves the certificate was installed on TLSConfig
	// rather than ServeTLS being asked to open the files.
	var conn *tls.Conn
	for i := 0; i < 50; i++ {
		conn, err = tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // G402: self-signed fixture
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("TLS handshake never succeeded: %v", err)
	}
	_ = conn.Close()
}

// The failure an operator sees is about the credential, and names it:
// http.Server.ServeTLS would have reported the same denial from inside
// the stdlib with no indication which file or why.
func TestServeTLSWithCredentialsReportsAnUnreadableKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unreadable file cannot be produced")
	}
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir, 0o600)
	if err := os.Chmod(keyPath, 0o000); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	err = serveTLSWithCredentials(&http.Server{ReadHeaderTimeout: time.Second}, ln, certPath, keyPath, nil, time.Minute)
	if err == nil {
		t.Fatal("serving started with an unreadable key")
	}
	if !strings.Contains(err.Error(), "TLS key") || !strings.Contains(err.Error(), keyPath) {
		t.Errorf("error does not name the key it could not read: %v", err)
	}
}
