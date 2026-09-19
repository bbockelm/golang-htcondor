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

// A connection that dies must be retried rather than poisoning every
// later lookup: a restarted SSSD used to disable directory lookups for
// the life of this process.
//
// gosssd owns that retry as of v0.0.4, so what is asserted here is that
// the behaviour still reaches through this call path -- not how many
// attempts gosssd chooses to make, which is its business and would make
// this test a tripwire on its defaults.
func TestSSSDLookupsRetryWhenTheConnectionDies(t *testing.T) {
	d := newDeadSSSD(t)

	_, err := enumerateSSSDAccounts()
	if err == nil {
		t.Fatal("a socket that hangs up produced no error")
	}
	if got := d.accepts.Load(); got < 2 {
		t.Errorf("accepted %d connections; a dead connection was not retried", got)
	}
}

// A failed call must not leave the shared client permanently broken: the
// next lookup has to dial again. This is the property that actually
// failed in production -- a restarted SSSD disabled directory lookups for
// the life of the process.
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
