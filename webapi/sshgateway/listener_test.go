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
	"net"
	"strings"
	"testing"
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
