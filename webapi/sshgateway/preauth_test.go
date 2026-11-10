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
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// twoSources returns a listen address and two local addresses to dial
// it from that count as different hosts. Linux routes all of 127/8 to
// loopback; macOS has only 127.0.0.1, so there the second source is ::1
// and the listener takes both families.
func twoSources(t *testing.T) (listen string, first, second net.Addr) {
	t.Helper()
	first = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	var lc net.ListenConfig
	if probe, err := lc.Listen(context.Background(), "tcp", "127.0.0.2:0"); err == nil {
		_ = probe.Close()
		return "127.0.0.1:0", first, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}
	}
	return ":0", first, &net.TCPAddr{IP: net.IPv6loopback}
}

// dialFrom handshakes and authenticates from a given local address.
func dialFrom(addr string, from net.Addr) error {
	d := net.Dialer{Timeout: 10 * time.Second, LocalAddr: from}
	host := "127.0.0.1"
	if ta, ok := from.(*net.TCPAddr); ok && ta.IP.To4() == nil {
		host = "::1"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	target := net.JoinHostPort(host, port)
	nc, err := d.DialContext(context.Background(), "tcp", target)
	if err != nil {
		return err
	}
	defer func() { _ = nc.Close() }()
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
	conn, chans, reqs, err := ssh.NewClientConn(nc, target, &ssh.ClientConfig{
		User:            "12345.0",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test server, key generated per run
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				return make([]string, len(questions)), nil
			}),
		},
	})
	if err != nil {
		return err
	}
	_ = ssh.NewClient(conn, chans, reqs).Close()
	return nil
}

// One source opening sockets and sending nothing cannot keep anybody
// else out. Only a few of its sockets are let in at all, those few are
// closed at the short pre-authentication deadline rather than the
// six-minute login one, the source is charged for each -- and meanwhile
// another host completes a login.
func TestIdleSocketsFromOneSourceDoNotLockOutAnother(t *testing.T) {
	const preAuth = 300 * time.Millisecond
	listen, first, second := twoSources(t)
	bans := NewBanlist(BanlistOptions{
		HostThreshold: DefaultMaxPreAuthPerHost, NetThreshold: 1000,
		Window: time.Hour, BanTime: time.Hour, MaxTracked: 16,
	})
	l := &Listener{
		Addr:           listen,
		HostKey:        testSigner(t),
		Auth:           grantingAuthenticator(t, "bbockelm", Options{}),
		Server:         &Server{Transport: &fakeTransport{}},
		Bans:           bans,
		PreAuthTimeout: preAuth,
	}
	if err := l.Listen(context.Background()); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = l.Serve(context.Background()) }()
	t.Cleanup(func() { _ = l.Close() })
	_, port, _ := net.SplitHostPort(l.BoundAddr())

	const idle = 300
	start := time.Now()
	socks := make([]net.Conn, 0, idle)
	defer func() {
		for _, c := range socks {
			_ = c.Close()
		}
	}()
	d := net.Dialer{Timeout: 10 * time.Second, LocalAddr: first}
	for i := 0; i < idle; i++ {
		c, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			t.Fatalf("idle socket %d: %v", i+1, err)
		}
		socks = append(socks, c)
	}

	if err := dialFrom(l.BoundAddr(), second); err != nil {
		t.Fatalf("another host could not log in while one held %d idle sockets: %v", idle, err)
	}

	// Every idle socket is closed by the server -- refused at accept, or
	// cut at the pre-authentication deadline -- well before the login
	// deadline. Reading to EOF is how the client sees that.
	for i, c := range socks {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.Copy(io.Discard, c); err != nil {
			if ne := net.Error(nil); errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("idle socket %d was still open %v after the burst began", i+1, time.Since(start).Round(time.Millisecond))
			}
		}
	}
	if elapsed := time.Since(start); elapsed > preAuth+8*time.Second {
		t.Errorf("idle sockets took %v to close", elapsed)
	}

	// Each socket let in sat out the deadline, and each is a strike.
	deadline := time.Now().Add(5 * time.Second)
	for bans.Stats().ActiveHostBans != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("the stalling source was not locked out: %+v", bans.Stats())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The per-network cap binds across hosts in one network, and only that
// network; a released slot is reusable and leaves nothing behind.
func TestPreAuthCounterCapsHostsAndNetworks(t *testing.T) {
	c := newPreAuthCounter(2, 3)
	addr := func(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 1} }

	r1, ok1 := c.take(addr("10.0.0.1"))
	_, ok2 := c.take(addr("10.0.0.1"))
	_, ok3 := c.take(addr("10.0.0.1"))
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("per-host cap: %v %v %v, want true true false", ok1, ok2, ok3)
	}
	_, ok4 := c.take(addr("10.0.0.2"))
	_, ok5 := c.take(addr("10.0.0.3"))
	if !ok4 || ok5 {
		t.Fatalf("per-network cap: %v %v, want true false", ok4, ok5)
	}
	if _, ok := c.take(addr("10.0.1.1")); !ok {
		t.Fatal("another network was refused")
	}
	r1()
	r1()
	if _, ok := c.take(addr("10.0.0.3")); !ok {
		t.Fatal("a released slot was not reusable")
	}
	for i := 0; i < 100; i++ {
		r, ok := c.take(addr(fmt.Sprintf("192.168.%d.1", i)))
		if !ok {
			t.Fatalf("take %d", i)
		}
		r()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.hosts) != 4 || len(c.nets) != 2 {
		t.Errorf("%d hosts and %d networks tracked, want 4 and 2: released entries are left behind", len(c.hosts), len(c.nets))
	}
}
