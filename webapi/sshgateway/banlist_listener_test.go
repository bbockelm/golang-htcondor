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
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startBannedListener runs a real Listener whose device flow always
// refuses, with a lockout after `threshold` failures.
func startBannedListener(t *testing.T, threshold int) (*Listener, *Banlist) {
	t.Helper()

	auth := testAuth()
	auth.Interval = time.Millisecond
	flow := &fakeFlow{auth: auth, replies: []error{
		ErrDenied, ErrDenied, ErrDenied, ErrDenied, ErrDenied,
		ErrDenied, ErrDenied, ErrDenied, ErrDenied, ErrDenied,
	}}
	a := grantingAuthenticator(t, "bbockelm", Options{Flow: flow})

	bans := NewBanlist(BanlistOptions{
		HostThreshold: threshold,
		// Out of the way: this test is about the host tier, and the
		// loopback address is its own /24 as far as the list knows.
		NetThreshold: 1000,
		Window:       time.Hour,
		BanTime:      time.Hour,
		MaxTracked:   16,
	})

	l := &Listener{
		Addr:    "127.0.0.1:0",
		HostKey: testSigner(t),
		Auth:    a,
		Server:  &Server{Transport: &fakeTransport{}},
		Bans:    bans,
	}
	if err := l.Listen(context.Background()); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = l.Serve(context.Background()) }()
	t.Cleanup(func() { _ = l.Close() })
	return l, bans
}

// The whole chain, through a real handshake: a refused login reaches
// AuthLogCallback, the score reaches the threshold, and the NEXT
// connection is dropped before it can spend a connection slot.
//
// Worth an end-to-end test rather than trusting the unit tests,
// because every part of it is wiring: an AuthLogCallback that is never
// installed, or a check placed after the slot is taken, passes every
// test of the Banlist itself.
func TestTheListenerLocksOutARepeatedlyFailingClient(t *testing.T) {
	l, bans := startBannedListener(t, 2)

	for i := 0; i < 2; i++ {
		if _, err := dial(t, l.BoundAddr(), "12345.0"); err == nil {
			t.Fatalf("attempt %d: a refused login should not connect", i+1)
		}
	}
	if got := bans.Stats().BansIssued; got != 1 {
		t.Fatalf("issued %d lockouts after two refused logins, want 1", got)
	}

	if _, err := dial(t, l.BoundAddr(), "12345.0"); err == nil {
		t.Fatal("a locked-out client connected")
	}
	if got := bans.Stats().ConnectionsRefused; got != 1 {
		t.Fatalf("%d connections refused at the door, want 1", got)
	}
}

// The refusal happens BEFORE a connection slot is taken, so a
// locked-out source cannot spend the concurrency budget it was locked
// out for spending.
//
// Asserting that by peeking at the slot channel after a refused
// connection does not work: it is held by whichever goroutine is still
// unwinding, and released moments later either way -- so the check
// races on a fast machine and proves nothing on a slow one. It passed
// 20 times on macOS and failed in Rocky Linux CI.
//
// The discriminator is what refuses the connection when the cap is
// ALREADY full. With the check in the right place the lockout turns it
// away and says so; with the check after the cap, the cap turns it
// away first and the lockout never sees it.
func TestALockedOutSourceIsRefusedBeforeTheConcurrencyCap(t *testing.T) {
	a := grantingAuthenticator(t, "bbockelm", Options{})
	bans := NewBanlist(BanlistOptions{
		HostThreshold: 1, NetThreshold: 1000, Window: time.Hour,
		BanTime: time.Hour, MaxTracked: 16,
	})
	l := &Listener{
		Addr:           "127.0.0.1:0",
		HostKey:        testSigner(t),
		Auth:           a,
		Server:         &Server{Transport: &fakeTransport{}},
		Bans:           bans,
		MaxConnections: 1,
	}
	if err := l.Listen(context.Background()); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = l.Serve(context.Background()) }()
	t.Cleanup(func() { _ = l.Close() })

	// Occupy the only slot. The handshake completing means serveConn
	// is running, which means its slot is taken.
	held := dialKeepOpen(t, l.BoundAddr(), "12345.0")
	defer func() { _ = held.Close() }()

	bans.Ban(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, "test")

	if _, err := dial(t, l.BoundAddr(), "12345.0"); err == nil {
		t.Fatal("a locked-out client connected")
	}
	if got := bans.Stats().ConnectionsRefused; got != 1 {
		t.Fatalf("%d connections refused by the lockout, want 1 -- "+
			"the concurrency cap turned it away first, so the check is in the wrong place", got)
	}
}

// dialKeepOpen connects and hands back the live client, so the caller
// can hold a server-side connection slot open.
func dialKeepOpen(t *testing.T, addr, user string) *ssh.Client {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test server, key generated per run
		Timeout:         10 * time.Second,
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				return make([]string, len(questions)), nil
			}),
		},
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return client
}

// A client that succeeds is never locked out, however many times it
// connects. The obvious way to get the counting wrong is to charge
// every completed handshake.
func TestTheListenerDoesNotLockOutASuccessfulClient(t *testing.T) {
	a := grantingAuthenticator(t, "bbockelm", Options{})
	bans := NewBanlist(BanlistOptions{
		HostThreshold: 2, NetThreshold: 4, Window: time.Hour,
		BanTime: time.Hour, MaxTracked: 16,
	})
	l := &Listener{
		Addr:    "127.0.0.1:0",
		HostKey: testSigner(t),
		Auth:    a,
		Server:  &Server{Transport: &fakeTransport{}},
		Bans:    bans,
	}
	if err := l.Listen(context.Background()); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = l.Serve(context.Background()) }()
	t.Cleanup(func() { _ = l.Close() })

	for i := 0; i < 6; i++ {
		if _, err := dial(t, l.BoundAddr(), "12345.0"); err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if got := bans.Stats().BansIssued; got != 0 {
		t.Fatalf("issued %d lockouts against a client that kept succeeding", got)
	}
}
