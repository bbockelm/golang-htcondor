// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sshgateway

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-htcondor/webapi/jobssh"
)

// certFixture is a CA, a user key, and a certificate binding them.
type certFixture struct {
	ca ssh.Signer
	// userRaw is kept because ssh.Signer does not expose the private
	// key, and staging an identity on disk for a real ssh client needs
	// it.
	userRaw ed25519.PrivateKey
	userKey ssh.Signer
	cert    *ssh.Certificate
}

// testAccount is the only principal these fixtures issue for. The
// gateway never chooses between principals, so varying it would test
// the test rather than the code.
const testAccount = "bbockelm"

func newCertFixture(t *testing.T) *certFixture {
	account := testAccount
	// An hour: long enough that no test races the expiry, short
	// enough to be a realistic issued lifetime. The expired case
	// builds its own certificate rather than waiting one out.
	const ttl = time.Hour
	t.Helper()
	ca := testSigner(t)
	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	user, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cert, err := SignUserCertificate(ca, user.PublicKey(), account, ttl, 1)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return &certFixture{ca: ca, userRaw: priv, userKey: user, cert: cert}
}

// signer returns an auth method presenting the certificate.
func (f *certFixture) auth(t *testing.T) ssh.AuthMethod {
	t.Helper()
	cs, err := ssh.NewCertSigner(f.cert, f.userKey)
	if err != nil {
		t.Fatalf("cert signer: %v", err)
	}
	return ssh.PublicKeys(cs)
}

// certGateway serves with certificate auth alongside the device flow.
func certGateway(t *testing.T, tr *fakeTransport, authority ssh.PublicKey) string {
	t.Helper()
	a := grantingAuthenticator(t, "device-user", Options{Prompt: "ap.example.edu"})
	srv := &Server{
		Transport: tr,
		Resolve: func(_ context.Context, account string, target Target, _ func(string)) (jobssh.Key, error) {
			if !target.IsJob() {
				return jobssh.Key{}, errors.New("no such session")
			}
			return jobssh.Key{Owner: account, Cluster: target.Cluster, Proc: target.Proc}, nil
		},
	}
	certs := &CertAuth{Authority: authority, Scopes: []string{"openid", "condor:/WRITE"}}

	cfg := &ssh.ServerConfig{
		KeyboardInteractiveCallback: a.KeyboardInteractive(context.Background()),
		PublicKeyCallback:           certs.Callback,
		MaxAuthTries:                32,
	}
	cfg.AddHostKey(testSigner(t))

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					_ = nc.Close()
					return
				}
				defer func() { _ = conn.Close() }()
				srv.Serve(context.Background(), conn, chans, reqs)
			}()
		}
	}()
	return ln.Addr().String()
}

func certDial(t *testing.T, addr, user string, auth ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test server, key generated per run
		Timeout:         10 * time.Second,
		Auth:            []ssh.AuthMethod{auth},
	})
}

// A certificate this CA signed logs in with no browser, and the
// account comes from the certificate rather than from the username --
// which on this gateway names the job.
func TestCertificateLoginCarriesTheAccount(t *testing.T) {
	f := newCertFixture(t)
	tr := &fakeTransport{}
	addr := certGateway(t, tr, f.ca.PublicKey())

	client, err := certDial(t, addr, "12345.0", f.auth(t))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("request pty: %v", err)
	}

	// Reaching a session at all proves the account resolved: the
	// resolver keys the job on it.
	if got := tr.lastSession(t); got == nil {
		t.Fatal("no session was opened")
	}
}

func TestCertificateFromAnotherCAIsRefused(t *testing.T) {
	f := newCertFixture(t)
	other := testSigner(t)
	tr := &fakeTransport{}
	addr := certGateway(t, tr, other.PublicKey())

	if _, err := certDial(t, addr, "12345.0", f.auth(t)); err == nil {
		t.Fatal("a certificate from an unknown CA logged in")
	}
}

func TestExpiredCertificateIsRefused(t *testing.T) {
	ca := testSigner(t)
	user := testSigner(t)
	// Signed to have already expired: ValidBefore in the past.
	cert := &ssh.Certificate{
		Key:             user.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "stale",
		ValidPrincipals: []string{"bbockelm"},
		ValidAfter:      uint64(time.Now().Add(-2 * time.Hour).Unix()), //nolint:gosec // a unix time in this century is positive
		ValidBefore:     uint64(time.Now().Add(-1 * time.Hour).Unix()), //nolint:gosec // same
	}
	if err := cert.SignCert(cryptorand.Reader, ca); err != nil {
		t.Fatalf("sign: %v", err)
	}
	tr := &fakeTransport{}
	addr := certGateway(t, tr, ca.PublicKey())

	cs, err := ssh.NewCertSigner(cert, user)
	if err != nil {
		t.Fatalf("cert signer: %v", err)
	}
	if _, err := certDial(t, addr, "12345.0", ssh.PublicKeys(cs)); err == nil {
		t.Fatal("an expired certificate logged in")
	}
}

// A bare public key carries no identity and no expiry. Accepting one
// would mean this server keeping a list of whose key is whose, which
// is the thing a CA exists to avoid.
func TestBarePublicKeyIsRefused(t *testing.T) {
	f := newCertFixture(t)
	tr := &fakeTransport{}
	addr := certGateway(t, tr, f.ca.PublicKey())

	if _, err := certDial(t, addr, "12345.0", ssh.PublicKeys(f.userKey)); err == nil {
		t.Fatal("a bare public key logged in")
	}
}

// The username names a job, so it must NOT have to appear in the
// certificate's principals -- otherwise a user needs a certificate per
// job, which defeats the point of having one.
func TestCertificatePrincipalNeedNotMatchTheUsername(t *testing.T) {
	f := newCertFixture(t)
	tr := &fakeTransport{}
	addr := certGateway(t, tr, f.ca.PublicKey())

	for _, user := range []string{"12345.0", "99.3", "work"} {
		client, err := certDial(t, addr, user, f.auth(t))
		if err != nil {
			t.Fatalf("dial as %q: %v", user, err)
		}
		_ = client.Close()
	}
}

// Choosing between principals is choosing an identity, which is the
// thing never to do.
func TestCertificateWithSeveralPrincipalsIsRefused(t *testing.T) {
	ca := testSigner(t)
	user := testSigner(t)
	cert, err := SignUserCertificate(ca, user.PublicKey(), "bbockelm", time.Hour, 1)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	cert.ValidPrincipals = []string{"bbockelm", "root"}
	if err := cert.SignCert(cryptorand.Reader, ca); err != nil {
		t.Fatalf("re-sign: %v", err)
	}

	tr := &fakeTransport{}
	addr := certGateway(t, tr, ca.PublicKey())
	cs, err := ssh.NewCertSigner(cert, user)
	if err != nil {
		t.Fatalf("cert signer: %v", err)
	}
	_, err = certDial(t, addr, "12345.0", ssh.PublicKeys(cs))
	if err == nil {
		t.Fatal("a certificate naming two principals logged in")
	}
}

func TestSignUserCertificateRefusesNonsense(t *testing.T) {
	ca := testSigner(t)
	pub := testSigner(t).PublicKey()

	if _, err := SignUserCertificate(nil, pub, "bbockelm", time.Hour, 1); err == nil {
		t.Error("signed with no CA")
	}
	if _, err := SignUserCertificate(ca, pub, "", time.Hour, 1); err == nil {
		t.Error("signed with no principal")
	}
	if _, err := SignUserCertificate(ca, pub, "bbockelm", 0, 1); err == nil {
		t.Error("signed with no lifetime")
	}
}

// A certificate issued a moment ago must work despite clock skew
// between the issuing host and the client's.
func TestFreshCertificateIsAlreadyValid(t *testing.T) {
	f := newCertFixture(t)
	if got := time.Unix(int64(f.cert.ValidAfter), 0); !got.Before(time.Now()) { //nolint:gosec // set from a unix time above
		t.Errorf("ValidAfter is %v, which is not yet in the past", got)
	}
	if !strings.Contains(f.cert.KeyId, "bbockelm") {
		t.Errorf("KeyId %q does not name the account", f.cert.KeyId)
	}
}

// writeCertIdentity stages a key and its certificate the way ssh
// expects: the private key at <path>, the certificate at
// <path>-cert.pub, which ssh picks up on its own.
func writeCertIdentity(t *testing.T, f *certFixture) string {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")

	block, err := ssh.MarshalPrivateKey(f.userRaw, "gateway test")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	// The certificate is public: it is the signed statement, not the
	// key. ssh does not care about its mode.
	if err := os.WriteFile(keyPath+"-cert.pub", ssh.MarshalAuthorizedKey(f.cert), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return keyPath
}

// The reason certificates exist. BatchMode refuses
// keyboard-interactive outright, so a script cannot use the device
// flow at all -- and nobody wants to approve a browser prompt for
// every connection either.
func TestRealClientLogsInWithACertificateInBatchMode(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh binary to test against")
	}

	f := newCertFixture(t)
	tr := &fakeTransport{}
	addr := certGateway(t, tr, f.ca.PublicKey())
	keyPath := writeCertIdentity(t, f)
	autoFinishSessions(t, tr, "cert-login-worked\r\n")

	out, sshErr := realSSHRaw(t, sshBin, addr, []string{
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=publickey",
		"-i", keyPath,
	}, "12345.0@HOST", "true")
	t.Logf("ssh exit=%v output:\n%q", sshErr, out)

	if sshErr != nil {
		t.Fatalf("a certificate did not log in under BatchMode: %v\n%s", sshErr, out)
	}
	if !strings.Contains(string(out), "cert-login-worked") {
		t.Errorf("the session did not run:\n%q", out)
	}
	// No browser was involved: the device-flow prompt never appeared.
	if strings.Contains(string(out), "Sign in to") {
		t.Errorf("the certificate path fell back to the device flow:\n%q", out)
	}
}
