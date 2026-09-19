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

//go:build linux

package droppriv

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// deadSSSD listens on a unix socket and hangs up on every connection,
// which is what a caller sees when the daemon behind the socket has gone
// away. It counts accepts so a test can tell whether a second connection
// was ever dialled.
type deadSSSD struct {
	accepts atomic.Int32
	ln      net.Listener
	wg      sync.WaitGroup
}

func newDeadSSSD(t *testing.T) *deadSSSD {
	t.Helper()
	// The socket lives in a temp dir; the path length matters on some
	// systems, and t.TempDir() is short enough.
	path := filepath.Join(t.TempDir(), "nss")
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatalf("listening on %s: %v", path, err)
	}
	d := &deadSSSD{ln: ln}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			d.accepts.Add(1)
			_ = conn.Close()
		}
	}()

	// Point the package at this socket and make sure no connection from
	// an earlier test is still cached.
	oldPath := sssdAccountsPath
	sssdAccountsPath = path
	sssdAccountsMu.Lock()
	oldClient := sssdAccountsClient
	sssdAccountsClient = nil
	sssdAccountsMu.Unlock()

	t.Cleanup(func() {
		_ = ln.Close()
		d.wg.Wait()
		sssdAccountsPath = oldPath
		sssdAccountsMu.Lock()
		if sssdAccountsClient != nil {
			_ = sssdAccountsClient.Close()
		}
		sssdAccountsClient = oldClient
		sssdAccountsMu.Unlock()
	})
	return d
}

// gosssd caches one connection for the life of the process and does not
// reconnect on its own: once the daemon restarts, every later request
// fails with "not connected" and keeps failing. Without the retry this
// asserts, a single SSSD restart silently disables directory lookups
// until the daemon using this package is itself restarted.
func TestSSSDCallRedialsAfterTheConnectionDies(t *testing.T) {
	d := newDeadSSSD(t)

	_, err := enumerateSSSDAccounts()
	if err == nil {
		t.Fatal("a socket that hangs up produced no error")
	}
	if got := d.accepts.Load(); got != 2 {
		t.Errorf("accepted %d connections, want 2: the failed one and the re-dial", got)
	}
}

// The failed connection must not stay cached, or the retry merely moves
// the permanent failure one call later.
func TestAFailedSSSDConnectionIsNotLeftCached(t *testing.T) {
	d := newDeadSSSD(t)

	if _, err := enumerateSSSDAccounts(); err == nil {
		t.Fatal("precondition: the call should have failed")
	}
	first := d.accepts.Load()

	if _, err := enumerateSSSDAccounts(); err == nil {
		t.Fatal("precondition: the second call should have failed too")
	}
	if got := d.accepts.Load(); got <= first {
		t.Errorf("accepts stayed at %d; the second call reused a connection known to be dead", got)
	}
}

// Dropping a client that is no longer the shared one must not close a
// healthy replacement another goroutine has since installed.
func TestDropSSSDClientLeavesAReplacementAlone(t *testing.T) {
	newDeadSSSD(t)

	stale, err := sssdAccountClient()
	if err != nil {
		t.Fatalf("dialling the fake: %v", err)
	}
	// Simulate another goroutine having already replaced it.
	sssdAccountsMu.Lock()
	sssdAccountsClient = nil
	sssdAccountsMu.Unlock()
	replacement, err := sssdAccountClient()
	if err != nil {
		t.Fatalf("dialling again: %v", err)
	}

	dropSSSDClient(stale)

	sssdAccountsMu.Lock()
	current := sssdAccountsClient
	sssdAccountsMu.Unlock()
	if current != replacement {
		t.Error("dropping a stale client discarded the replacement connection")
	}
}
