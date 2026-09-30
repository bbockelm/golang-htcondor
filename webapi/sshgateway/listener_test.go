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
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testListener(t *testing.T, addr string) *Listener {
	t.Helper()
	a := grantingAuthenticator(t, "bbockelm", Options{})
	return &Listener{
		Addr:    addr,
		HostKey: testSigner(t),
		Auth:    a,
		Server:  &Server{Transport: &fakeTransport{}},
	}
}

// A port already in use has to reach the caller, so startup can fail
// on it. When the bind happened inside the serving goroutine this
// produced a log line and a daemon running without the gateway --
// which is the same class of failure as a missing host key, and that
// one is fatal.
func TestListenReportsAPortAlreadyInUse(t *testing.T) {
	var lc net.ListenConfig
	held, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold a port: %v", err)
	}
	defer func() { _ = held.Close() }()

	l := testListener(t, held.Addr().String())
	err = l.Listen(context.Background())
	if err == nil {
		_ = l.Close()
		t.Fatal("binding a port already in use succeeded")
	}
	if !strings.Contains(err.Error(), held.Addr().String()) {
		t.Errorf("the error does not name the address: %v", err)
	}
}

func TestListenRequiresItsParts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mangle func(*Listener)
	}{
		{"no host key", func(l *Listener) { l.HostKey = nil }},
		{"no authenticator", func(l *Listener) { l.Auth = nil }},
		{"no server", func(l *Listener) { l.Server = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := testListener(t, "127.0.0.1:0")
			tc.mangle(l)
			if err := l.Listen(context.Background()); err == nil {
				_ = l.Close()
				t.Fatal("Listen succeeded with a required part missing")
			}
		})
	}
}

// Serve before Listen is a programming mistake, and saying so beats a
// nil dereference in a goroutine.
func TestServeBeforeListenIsRefused(t *testing.T) {
	l := testListener(t, "127.0.0.1:0")
	if err := l.Serve(context.Background()); err == nil {
		t.Fatal("Serve ran without a listener")
	}
}

// BoundAddr is what a caller needs when it asked for port 0.
func TestBoundAddrReportsTheRealPort(t *testing.T) {
	l := testListener(t, "127.0.0.1:0")
	if err := l.Listen(context.Background()); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	addr := l.BoundAddr()
	if addr == "" || strings.HasSuffix(addr, ":0") {
		t.Errorf("BoundAddr = %q, want the port actually bound", addr)
	}
}

// One host must not be able to take every login slot.
//
// The global cap on its own is a denial-of-service primitive rather
// than a defence: sockets that answer the prompt and go silent hold
// slots for the full timeout, and nobody else gets in.
func TestLoginsAreCappedPerSource(t *testing.T) {
	a, err := NewAuthenticator(Options{
		Flow:         newBlockingFlow(testAuth()),
		Identity:     func(context.Context, *Grant) (string, error) { return "bbockelm", nil },
		MaxPerSource: 2,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	if !a.takeSource("10.0.0.1:1001") || !a.takeSource("10.0.0.1:1002") {
		t.Fatal("the first two logins from a source were refused")
	}
	if a.takeSource("10.0.0.1:1003") {
		t.Error("a third login from the same source was allowed past the cap")
	}
	// A different host is unaffected, which is the whole point.
	if !a.takeSource("10.0.0.2:1001") {
		t.Error("another source was refused because of the first one's slots")
	}
	// Releasing frees the slot rather than leaking it.
	a.releaseSource("10.0.0.1:1001")
	if !a.takeSource("10.0.0.1:1004") {
		t.Error("a released slot was not reusable")
	}
}

// The per-source map must not grow for the life of the daemon.
func TestPerSourceSlotsAreReleasedCompletely(t *testing.T) {
	a, err := NewAuthenticator(Options{
		Flow:     newBlockingFlow(testAuth()),
		Identity: func(context.Context, *Grant) (string, error) { return "bbockelm", nil },
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	for i := 0; i < 100; i++ {
		addr := fmt.Sprintf("10.0.0.%d:1000", i)
		if !a.takeSource(addr) {
			t.Fatalf("take %s", addr)
		}
		a.releaseSource(addr)
	}
	a.mu.Lock()
	n := len(a.inFlight)
	a.mu.Unlock()
	if n != 0 {
		t.Errorf("%d source entries left behind; the map grows forever", n)
	}
}

// Both host key algorithms have to be on offer, and that is a
// compatibility guarantee rather than a detail.
//
// A client that pinned the bare host key before certificates existed
// must keep connecting without noticing anything. If the gateway
// offered only the certificate, every such client would be met with
// what looks like an entirely new host -- the loudest possible warning,
// for a change that was supposed to remove a prompt.
func TestBothHostKeyAlgorithmsAreOffered(t *testing.T) {
	host, ca := testSigner(t), testSigner(t)
	cert, err := NewHostCertSigner(host, ca, nil, time.Now())
	if err != nil {
		t.Fatalf("issuing a host certificate: %v", err)
	}

	l := testListener(t, "127.0.0.1:0")
	l.HostKey = host
	l.HostCert = cert
	if err := l.Listen(context.Background()); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	go func() { _ = l.Serve(context.Background()) }()

	// Each client insists on exactly one algorithm, so a successful
	// handshake proves the server offered that one specifically.
	for _, tc := range []struct {
		name string
		algo string
		want ssh.PublicKey
	}{
		{"a client that trusts the CA", ssh.CertAlgoED25519v01, cert.PublicKey()},
		{"a client that pinned the bare key", ssh.KeyAlgoED25519, host.PublicKey()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen ssh.PublicKey
			_, _, _, err := sshDialHostKey(l.BoundAddr(), tc.algo, &seen)
			// Authentication is expected to fail -- no credential is
			// offered here -- but only AFTER the host key exchange,
			// which is the part under test.
			if seen == nil {
				t.Fatalf("no host key was exchanged with %s: %v", tc.algo, err)
			}
			if string(seen.Marshal()) != string(tc.want.Marshal()) {
				t.Errorf("server presented %s, want %s", seen.Type(), tc.want.Type())
			}
		})
	}
}

// sshDialHostKey handshakes with one host key algorithm and records
// what the server presented.
func sshDialHostKey(addr, algo string, seen *ssh.PublicKey) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	nc, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { _ = nc.Close() }()
	return ssh.NewClientConn(nc, addr, &ssh.ClientConfig{
		User:              "12345.0",
		HostKeyAlgorithms: []string{algo},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			*seen = key
			return nil
		},
		Auth:    []ssh.AuthMethod{},
		Timeout: 5 * time.Second,
	})
}
