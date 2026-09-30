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

	// Every name twice, bare and bracketed: see
	// TestKnownHostsLineCoversANonDefaultPort.
	named := KnownHostsLine(ca, []string{"ap.example.edu", "alias.example.org"})
	wantPrefix := "@cert-authority ap.example.edu,[ap.example.edu]:*," +
		"alias.example.org,[alias.example.org]:* "
	if !strings.HasPrefix(named, wantPrefix) {
		t.Errorf("with host names, got %q", named)
	}
}

func TestParseHostNames(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"ap.example.edu", []string{"ap.example.edu"}},
		{"ap.example.edu, alias.example.org", []string{"ap.example.edu", "alias.example.org"}},
		// Written the way somebody types an ssh command. The setting is
		// documented as the name users ssh to, so this will happen.
		{"ap.example.edu:2222", []string{"ap.example.edu"}},
		{"[ap.example.edu]:2222", []string{"ap.example.edu"}},
		{"a,,b", []string{"a", "b"}},
	} {
		got := ParseHostNames(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("ParseHostNames(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("ParseHostNames(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}

// A gateway on a port other than 22 is the default this software
// ships, and OpenSSH looks such a host up as [name]:port. A line
// carrying only the bare name matches nothing for those users -- the
// certificate would verify and the client would still prompt.
func TestKnownHostsLineCoversANonDefaultPort(t *testing.T) {
	ca := testSigner(t).PublicKey()
	line := KnownHostsLine(ca, []string{"ap.example.edu"})

	patterns := strings.Fields(line)[1]
	for _, want := range []string{"ap.example.edu", "[ap.example.edu]:*"} {
		found := false
		for _, p := range strings.Split(patterns, ",") {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("pattern list %q does not cover %q", patterns, want)
		}
	}
}

// The certificate has to name the same hosts the line points at, or a
// client that matches the pattern is handed a certificate that does not
// list it.
func TestConfiguredNameIsBothPrincipalAndPattern(t *testing.T) {
	host, ca := testSigner(t), testSigner(t)
	names := ParseHostNames("ap.example.edu:2222")
	signer, err := NewHostCertSigner(host, ca, names, time.Now())
	if err != nil {
		t.Fatalf("issuing a host certificate: %v", err)
	}
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return string(auth.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}
	if err := checker.CheckHostKey("ap.example.edu:2222", nil, signer.PublicKey()); err != nil {
		t.Errorf("the configured name was rejected: %v", err)
	}
	if !strings.Contains(KnownHostsLine(ca.PublicKey(), names), "ap.example.edu") {
		t.Error("the published line does not mention the configured name")
	}
}

func TestParseGatewayAddress(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"", "", 0},
		// No port stated. Zero, not 22: the client decides what
		// "unstated" means, and the server guessing 22 would be
		// indistinguishable from the operator saying so.
		{"ap.example.edu", "ap.example.edu", 0},
		{"ap.example.edu:2222", "ap.example.edu", 2222},
		{"[ap.example.edu]:2222", "ap.example.edu", 2222},
		// The first name is the one to connect to; the rest exist so
		// the certificate and known_hosts cover every alias.
		{"ap.example.edu:2222, alias.example.org", "ap.example.edu", 2222},
		{"  spaced.example.edu:22  ", "spaced.example.edu", 22},
		// A typo'd port still yields a usable host. net.SplitHostPort
		// accepts a non-numeric port, so the name comes out clean and
		// only the port is discarded -- which sends the client to the
		// default rather than to a parse of garbage.
		{"ap.example.edu:notaport", "ap.example.edu", 0},
		{"ap.example.edu:0", "ap.example.edu", 0},
		{"ap.example.edu:99999", "ap.example.edu", 0},
	} {
		host, port := ParseGatewayAddress(tc.in)
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("ParseGatewayAddress(%q) = (%q, %d), want (%q, %d)",
				tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

// The host it advertises must be one the certificate actually names,
// or a client follows the advertisement to a host it cannot verify.
func TestAdvertisedHostIsACertificatePrincipal(t *testing.T) {
	const configured = "ap.example.edu:2222, alias.example.org"
	host, _ := ParseGatewayAddress(configured)

	hostKey, ca := testSigner(t), testSigner(t)
	signer, err := NewHostCertSigner(hostKey, ca, ParseHostNames(configured), time.Now())
	if err != nil {
		t.Fatalf("issuing a host certificate: %v", err)
	}
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return string(auth.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}
	if err := checker.CheckHostKey(host+":2222", nil, signer.PublicKey()); err != nil {
		t.Errorf("the advertised host is not one the certificate names: %v", err)
	}
}
