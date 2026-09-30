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
	"testing"
	"time"
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

	// And the connection slot was never taken: the refusal happens
	// before the cap is consulted, so a locked-out source cannot spend
	// the budget it was locked out for spending.
	if got := len(l.connSlots); got != 0 {
		t.Fatalf("%d connection slots held after a refused connection, want 0", got)
	}
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
