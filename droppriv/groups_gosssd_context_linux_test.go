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

//go:build linux && !cgo

package droppriv

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/gosssd"
)

// fakeSSSD answers the handful of NSS requests a group lookup makes.
//
// It exists to pin the lifetime of the cached client, not the protocol:
// the bug it guards against is a client bound to a context that ends,
// which leaves the socket closed and every later lookup failing with
// "context canceled" long after the request that opened it is gone.
type fakeSSSD struct {
	path string
	ln   net.Listener

	mu    sync.Mutex
	conns int
}

func newFakeSSSD(t *testing.T, gids []uint32) *fakeSSSD {
	t.Helper()

	// Not t.TempDir(): a unix socket path is capped near 100 bytes, and
	// the test name is in that directory's name.
	dir, err := os.MkdirTemp("", "sssd")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "nss")
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatalf("listen on %s: %v", path, err)
	}

	f := &fakeSSSD{path: path, ln: ln}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
			go f.serve(conn, gids)
		}
	}()
	return f
}

// connections reports how many times a client has dialled.
func (f *fakeSSSD) connections() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

func (f *fakeSSSD) serve(conn net.Conn, gids []uint32) {
	defer func() { _ = conn.Close() }()

	for {
		header := make([]byte, 16)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		length := binary.LittleEndian.Uint32(header[0:4])
		command := binary.LittleEndian.Uint32(header[4:8])
		if length > 16 {
			if _, err := io.ReadFull(conn, make([]byte, length-16)); err != nil {
				return
			}
		}

		var body []byte
		status := uint32(gosssd.SSS_NSS_STATUS_SUCCESS)
		switch command {
		case gosssd.SSS_NSS_INITGR:
			body = make([]byte, 8+4*len(gids))
			binary.LittleEndian.PutUint32(body[0:4], uint32(len(gids))) // #nosec G115 - fixed-size test fixture
			for i, gid := range gids {
				binary.LittleEndian.PutUint32(body[8+4*i:], gid)
			}
		case gosssd.SSS_NSS_GETPWNAM:
			// One entry: uid, gid, then name/passwd/gecos/home/shell.
			body = make([]byte, 16)
			binary.LittleEndian.PutUint32(body[0:4], 1)
			binary.LittleEndian.PutUint32(body[8:12], 4242)
			binary.LittleEndian.PutUint32(body[12:16], gids[0])
			body = append(body, "alice\x00x\x00\x00/home/alice\x00/bin/sh\x00"...)
		default:
			// Including GETGRGID: an unresolved gid is reported as its
			// number, which is enough for this test and keeps the fake
			// to the two requests that matter.
			status = gosssd.SSS_NSS_STATUS_NOTFOUND
		}

		resp := make([]byte, 16+len(body))
		binary.LittleEndian.PutUint32(resp[0:4], uint32(len(resp))) // #nosec G115 - fixed-size test fixture
		binary.LittleEndian.PutUint32(resp[4:8], command)
		binary.LittleEndian.PutUint32(resp[8:12], status)
		copy(resp[16:], body)
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

// TestSSSDGroupsSurvivesCallerCancellation is the regression test for a
// cached SSSD client bound to the context of whichever request happened
// to dial it. The client is reused for the life of the process, so when
// that one request finished the socket was closed and never redialled:
// the first login after startup worked and every login afterwards failed
// with "sssd was unavailable: ... context canceled", while `id` on the
// same host kept answering.
func TestSSSDGroupsSurvivesCallerCancellation(t *testing.T) {
	fake := newFakeSSSD(t, []uint32{1001, 1002})
	s := &SSSDGroups{SocketPath: fake.path}

	ctx, cancel := context.WithCancel(context.Background())
	first, err := s.LookupGroups(ctx, "alice")
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("first lookup returned %v, want 2 groups", first)
	}

	// The request that opened the connection ends. Nothing about the
	// next user's login depends on it.
	cancel()
	time.Sleep(50 * time.Millisecond)

	second, err := s.LookupGroups(context.Background(), "alice")
	if err != nil {
		t.Fatalf("lookup after the first caller's context was cancelled: %v", err)
	}
	if len(second) != len(first) {
		t.Fatalf("second lookup returned %v, want the same %v", second, first)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatal("a cancelled caller must not be reported as SSSD being unavailable")
	}
}

// TestSSSDGroupsRedialsAfterFailure pins the gosssd behaviour this
// package now relies on in place of a context: a cached client redials a
// dropped socket by itself, so an sssd restart is a blip rather than an
// outage lasting until this process is restarted.
func TestSSSDGroupsRedialsAfterFailure(t *testing.T) {
	fake := newFakeSSSD(t, []uint32{1001})
	s := &SSSDGroups{SocketPath: fake.path}

	if _, err := s.LookupGroups(context.Background(), "alice"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	before := fake.connections()

	// Drop the connection out from under the cached client, the way an
	// sssd restart does.
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		t.Fatal("no client was cached")
	}
	_ = client.Close()

	if _, err := s.LookupGroups(context.Background(), "alice"); err != nil {
		t.Fatalf("lookup after the socket was dropped: %v", err)
	}
	if after := fake.connections(); after <= before {
		t.Fatalf("client did not redial: %d connections before, %d after", before, after)
	}
}

// TestSSSDLookupSurvivesConstructionDeadline covers the UID/GID half.
// NewSSSDLookup was called with a five-second construction deadline that
// was cancelled as soon as construction returned, so the strategy stored
// in the process-wide lookup cache was dead before its first use.
func TestSSSDLookupSurvivesConstructionDeadline(t *testing.T) {
	fake := newFakeSSSD(t, []uint32{1001})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	s, err := newSSSDLookupAt(ctx, fake.path)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	cancel()
	time.Sleep(50 * time.Millisecond)

	info, err := s.LookupUser(context.Background(), "alice")
	if err != nil {
		t.Fatalf("lookup after the construction context expired: %v", err)
	}
	if info.Username != "alice" {
		t.Fatalf("looked up %q, want alice", info.Username)
	}
}
