package sshgateway

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestHostCertVerifiesFromTheAuthorityAlone is the test this whole
// change exists for.
//
// It uses x/crypto/ssh's own CertChecker, which is the same logic an
// OpenSSH client applies to a `@cert-authority` line: trust the CA, ask
// nothing about the host key underneath. Before the gateway presented a
// certificate, that check could not pass however the client was
// configured -- the published known_hosts line described a trust path
// that did not exist.
func TestHostCertVerifiesFromTheAuthorityAlone(t *testing.T) {
	host, ca := testSigner(t), testSigner(t)

	signer, err := NewHostCertSigner(host, ca, nil, time.Now())
	if err != nil {
		t.Fatalf("issuing a host certificate: %v", err)
	}

	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return string(auth.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}
	// Any name, because the certificate lists no principals.
	for _, addr := range []string{"ap.example.edu:22", "an-alias.example.org:2222", "127.0.0.1:41234"} {
		if err := checker.CheckHostKey(addr, nil, signer.PublicKey()); err != nil {
			t.Errorf("a client trusting the CA rejected the gateway at %s: %v", addr, err)
		}
	}
}

// A bare host key is what the gateway used to present. The same client
// must reject it, or the test above proves nothing.
func TestBareHostKeyIsNotAcceptedFromTheAuthority(t *testing.T) {
	host, ca := testSigner(t), testSigner(t)

	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return string(auth.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}
	if err := checker.CheckHostKey("ap.example.edu:22", nil, host.PublicKey()); err == nil {
		t.Fatal("a bare host key was accepted on the strength of the CA alone")
	}
}

func TestHostCertIsAHostCert(t *testing.T) {
	host, ca := testSigner(t), testSigner(t)
	signer, err := NewHostCertSigner(host, ca, nil, time.Now())
	if err != nil {
		t.Fatalf("issuing a host certificate: %v", err)
	}
	cert, ok := signer.PublicKey().(*ssh.Certificate)
	if !ok {
		t.Fatalf("the signer does not present a certificate at all, got %T", signer.PublicKey())
	}
	// A user certificate presented as a host key is not merely the
	// wrong constant: it would let anyone holding a user certificate
	// impersonate the gateway.
	if cert.CertType != ssh.HostCert {
		t.Errorf("CertType = %d, want HostCert (%d)", cert.CertType, ssh.HostCert)
	}
	if string(cert.Key.Marshal()) != string(host.PublicKey().Marshal()) {
		t.Error("the certificate does not certify the host key it was built from")
	}
}

func TestHostCertNamesOnlyItsPrincipals(t *testing.T) {
	host, ca := testSigner(t), testSigner(t)
	signer, err := NewHostCertSigner(host, ca, []string{"ap.example.edu"}, time.Now())
	if err != nil {
		t.Fatalf("issuing a host certificate: %v", err)
	}
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return string(auth.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}
	if err := checker.CheckHostKey("ap.example.edu:22", nil, signer.PublicKey()); err != nil {
		t.Errorf("rejected the name it was issued for: %v", err)
	}
	if err := checker.CheckHostKey("elsewhere.example.org:22", nil, signer.PublicKey()); err == nil {
		t.Error("accepted a name the certificate does not list")
	}
}

func TestHostCertRefusesMissingInputs(t *testing.T) {
	signer := testSigner(t)
	if _, err := NewHostCertSigner(nil, signer, nil, time.Now()); err == nil {
		t.Error("issued a certificate with no host key")
	}
	if _, err := NewHostCertSigner(signer, nil, nil, time.Now()); err == nil {
		t.Error("issued a certificate with no authority")
	}
}

func TestKnownHostsLinePattern(t *testing.T) {
	ca := testSigner(t).PublicKey()

	wildcard := KnownHostsLine(ca, nil)
	if !strings.HasPrefix(wildcard, "@cert-authority * ") {
		t.Errorf("without host names, got %q", wildcard)
	}
	// The key has to be on the line, or the client has nothing to trust.
	if !strings.Contains(wildcard, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca)))) {
		t.Error("the line does not carry the authority's key")
	}
	// One line, because known_hosts is line-oriented and a stray
	// newline silently truncates whatever follows it.
	if strings.Contains(wildcard, "\n") {
		t.Error("the line contains a newline")
	}

	named := KnownHostsLine(ca, []string{"ap.example.edu", "alias.example.org"})
	if !strings.HasPrefix(named, "@cert-authority ap.example.edu,alias.example.org ") {
		t.Errorf("with host names, got %q", named)
	}
}
