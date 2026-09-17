package idmap

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubSSSDSocket accepts connections and never replies, which is enough
// to tell "connected" from "not connected".
func stubSSSDSocket(t *testing.T) string {
	t.Helper()
	// Unix socket paths are limited to ~104 bytes, so keep it short.
	path := filepath.Join(t.TempDir(), "s")
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "unix", path)
	if err != nil {
		t.Skipf("cannot listen on a unix socket here: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return path
}

// The regression that cost this feature its SSSD support.
//
// gosssd's ConnectContext used to dial a shallow copy of the client, so
// it reported success while leaving the caller's client unconnected;
// every lookup then failed with "not connected". Because nothing here
// could point the source at a socket, the failure was invisible without
// a live SSSD -- and with the group chain refusing partial answers, it
// would have denied every login on an sss host.
//
// Fixed upstream in gosssd v0.0.2 (bbockelm/gosssd#3). This pins the
// symptom so a dependency regression is caught here rather than in
// production.
func TestSSSDGroupsActuallyConnects(t *testing.T) {
	src := &SSSDGroups{SocketPath: stubSSSDSocket(t)}
	t.Cleanup(func() { _ = src.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// The stub never answers, so this must fail -- on a read or a
	// timeout, never because the client was never connected.
	_, err := src.GroupsFor(ctx, "someone")
	if err == nil {
		t.Skip("stub unexpectedly satisfied the request")
	}
	if strings.Contains(err.Error(), "not connected") {
		t.Fatalf("SSSD source is not connecting: %v "+
			"(gosssd >= v0.0.2 is required; before that ConnectContext connected a copy)", err)
	}
	t.Logf("connected; the request failed downstream as expected: %v", err)
}

// A socket that is not there must report a connection failure, not an
// empty group list -- an empty list would read as "this user has no
// permissions".
func TestSSSDGroupsReportsAnAbsentSocket(t *testing.T) {
	src := &SSSDGroups{SocketPath: filepath.Join(t.TempDir(), "absent")}
	t.Cleanup(func() { _ = src.Close() })

	got, err := src.GroupsFor(context.Background(), "someone")
	if err == nil {
		t.Fatalf("an absent SSSD socket produced groups %v", got)
	}
	if got != nil {
		t.Errorf("returned %v alongside the error", got)
	}
}

func TestSSSDGroupsRejectsAnEmptyUsername(t *testing.T) {
	src := &SSSDGroups{SocketPath: stubSSSDSocket(t)}
	t.Cleanup(func() { _ = src.Close() })

	if _, err := src.GroupsFor(context.Background(), ""); err == nil {
		t.Error("an empty username must not be sent to SSSD")
	}
}
