package main

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Only ports that actually need root should trigger an elevation attempt.
// A permission error on a high port is a sandbox or an SELinux policy, and
// re-raising would neither help nor describe what went wrong.
func TestPrivilegedPortOf(t *testing.T) {
	cases := map[string]int{
		"127.0.0.1:443":  443,
		":443":           443,
		"0.0.0.0:80":     80,
		"127.0.0.1:1023": 1023,
		"127.0.0.1:1024": 0,
		":8080":          0,
		"127.0.0.1:0":    0,
	}
	for addr, want := range cases {
		got, err := privilegedPortOf(addr)
		if err != nil {
			t.Errorf("%s: %v", addr, err)
			continue
		}
		if got != want {
			t.Errorf("%s: port = %d, want %d", addr, got, want)
		}
	}

	if _, err := privilegedPortOf("not-an-address"); err == nil {
		t.Error("a malformed address was accepted")
	}
}

// An unprivileged port binds without any elevation, which is the common
// case and must stay untouched.
func TestListenMaybePrivilegedBindsOrdinaryPort(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	ln, err := listenMaybePrivileged("127.0.0.1:0", logger)
	if err != nil {
		t.Fatalf("binding an ephemeral port failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if _, port, err := net.SplitHostPort(ln.Addr().String()); err != nil || port == "0" {
		t.Errorf("listener has no real port: addr=%s err=%v", ln.Addr(), err)
	}
}

// A bind that fails for a reason other than permission is reported as-is.
// Re-raising cannot fix an address already in use, and swallowing the real
// error would send an operator looking in the wrong place.
func TestListenMaybePrivilegedPassesThroughNonPermissionErrors(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	held, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = held.Close() }()

	_, err = listenMaybePrivileged(held.Addr().String(), logger)
	if err == nil {
		t.Fatal("binding an address already in use succeeded")
	}
	if !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("the original error was lost: %v", err)
	}
}
