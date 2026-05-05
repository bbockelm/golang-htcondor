package sharedport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPassSockHeaderRoundTrip verifies that writePassSockHeader produces
// bytes the readPassSockHeader on the receive side accepts. This is the
// minimum bar — both sides must speak the same dialect of CEDAR, and
// without this the integration test below has nothing to verify.
func TestPassSockHeaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writePassSockHeader(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := readPassSockHeader(&buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("trailing bytes after read: %d", buf.Len())
	}
}

// TestPassSockHeaderRejects exercises the validation paths so a future
// refactor can't accidentally relax the parsing. We feed inputs that
// should each be detected:
//
//   - empty stream (short read)
//   - bogus length
//   - wrong CEDAR command id
//
// Without these we'd silently dispatch random bytes through SCM_RIGHTS
// to whatever fd the next syscall returns, which would corrupt
// production traffic.
func TestPassSockHeaderRejects(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		want string
	}{
		{
			name: "empty",
			buf:  nil,
			want: "header",
		},
		{
			name: "length zero",
			buf:  buildHeader(0, nil),
			want: "frame length",
		},
		{
			name: "length too big",
			buf:  buildHeader(1024, make([]byte, 1024)),
			want: "frame length",
		},
		{
			name: "wrong command id",
			buf:  buildPassSockFrame(99 /* != 76 */),
			want: "unexpected command",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := readPassSockHeader(bytes.NewReader(tc.buf))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %q missing expected substring %q", err.Error(), tc.want)
			}
		})
	}
}

// buildHeader emits a CEDAR frame header with the supplied payload
// length and concatenates the payload. Helper for the rejection tests.
func buildHeader(length uint32, payload []byte) []byte {
	out := make([]byte, cedarHeaderSize+len(payload))
	out[0] = 1
	binary.BigEndian.PutUint32(out[1:5], length)
	copy(out[cedarHeaderSize:], payload)
	return out
}

// buildPassSockFrame emits a complete (header + payload) frame
// carrying `cmd` as the int payload, suitable for feeding readPassSockHeader.
func buildPassSockFrame(cmd uint64) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, cmd)
	return buildHeader(8, payload)
}

// TestListenerForwardsFD spins up the full receive path:
//
//  1. Open a socketpair we'll use as the "forwarded" TCP connection
//     stand-in: side A becomes the "client" the test owns, side B is
//     the fd we pass through SCM_RIGHTS as if shared_port had picked
//     it up off a real TCP listener.
//  2. Hand side B over the UDS to a sharedport.Listener via
//     SendForwardedConn. That drives the SHARED_PORT_PASS_SOCK +
//     SCM_RIGHTS handshake.
//  3. Accept() the resulting net.Conn and verify bytes round-trip
//     through it.
//
// We deliberately avoid involving an http.Server in this test — that
// would couple the harness to TCP-listener accept timing on the
// loopback path, which has bitten previous iterations of this test.
// Bytes-only verification proves the listener delivers a working
// connection; the http.Server end-to-end check lives in the integration
// test against condor_shared_port.
func TestListenerForwardsFD(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "ep.sock")

	spListener, err := Listen(socket, Options{
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = spListener.Close() }()

	// Pair of connected stream sockets. We pass `passFd` over the UDS;
	// `clientConn` stays in our hands so the test can drive bytes
	// through the link and prove the dup path is intact.
	clientConn, passFd := mustSocketpair(t)
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = passFd.Close() }()

	var udsDialer net.Dialer
	udsConn, err := udsDialer.DialContext(context.Background(), "unix", socket)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	udsUnix, ok := udsConn.(*net.UnixConn)
	if !ok {
		t.Fatalf("dial unix returned %T, want *net.UnixConn", udsConn)
	}
	defer func() { _ = udsUnix.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := SendForwardedConn(ctx, udsUnix, passFd.Fd()); err != nil {
		t.Fatalf("SendForwardedConn: %v", err)
	}

	// Now Accept() should hand us the same kernel socket as `passFd`
	// (modulo dups). Bytes written by the client must arrive on the
	// accepted conn, and vice versa.
	accepted, err := acceptWithTimeout(spListener, 2*time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = accepted.Close() }()

	const probe = "shared-port-test-probe"
	if _, err := clientConn.Write([]byte(probe)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(probe))
	if err := accepted.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := io.ReadFull(accepted, got); err != nil {
		t.Fatalf("accepted read: %v", err)
	}
	if string(got) != probe {
		t.Errorf("probe mismatch: got %q want %q", got, probe)
	}

	// Reverse direction.
	const reply = "ack-from-accept-side"
	if _, err := accepted.Write([]byte(reply)); err != nil {
		t.Fatalf("accepted write: %v", err)
	}
	gotBack := make([]byte, len(reply))
	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("client SetReadDeadline: %v", err)
	}
	if _, err := io.ReadFull(clientConn, gotBack); err != nil {
		t.Fatalf("client read back: %v", err)
	}
	if string(gotBack) != reply {
		t.Errorf("reply mismatch: got %q want %q", gotBack, reply)
	}
}

// mustSocketpair returns (a, b) connected stream sockets. Side a is a
// net.Conn the test can write to / read from; side b is an *os.File
// whose Fd() can be passed via SCM_RIGHTS as a stand-in for a real
// TCP server-side connection.
func mustSocketpair(t *testing.T) (net.Conn, *os.File) {
	t.Helper()
	pair, err := socketpairStream()
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	aFile := os.NewFile(uintptr(pair[0]), "spp-a")
	if aFile == nil {
		t.Fatalf("os.NewFile returned nil for fd %d", pair[0])
	}
	a, err := net.FileConn(aFile)
	_ = aFile.Close()
	if err != nil {
		t.Fatalf("net.FileConn: %v", err)
	}
	bFile := os.NewFile(uintptr(pair[1]), "spp-b")
	if bFile == nil {
		_ = a.Close()
		t.Fatalf("os.NewFile returned nil for fd %d", pair[1])
	}
	return a, bFile
}

// TestListenerCloseUnblocksAccept guards against a blocking Close
// returning before Accept observes the shutdown. http.Server.Serve
// loops on Accept until it returns an error; if we forget to unblock
// it on Close, the daemon never exits cleanly.
func TestListenerCloseUnblocksAccept(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "ep.sock")
	l, err := Listen(socket, Options{Logf: t.Logf})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	gotErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := l.Accept()
		gotErr <- err
	}()

	// Brief pause so Accept is definitely parked on the channel select.
	time.Sleep(20 * time.Millisecond)
	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	select {
	case err := <-gotErr:
		if err == nil {
			t.Errorf("Accept returned nil error after Close; want an error")
		}
		// We accept either errClosed or any wrapping of it; the
		// http.Server.Serve loop bails on any non-nil error here.
		if !errors.Is(err, errClosed) && !strings.Contains(err.Error(), "closed") {
			t.Errorf("Accept error = %v; want close-related", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Accept did not unblock after Close")
	}
	wg.Wait()
}

// TestListenerHandlesGarbage feeds a junk handshake and confirms the
// listener drops it without affecting subsequent valid handshakes —
// otherwise a misbehaved peer could DoS the daemon.
func TestListenerHandlesGarbage(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "ep.sock")
	l, err := Listen(socket, Options{Logf: t.Logf})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Garbage handshake.
	var junkDialer net.Dialer
	junk, err := junkDialer.DialContext(context.Background(), "unix", socket)
	if err != nil {
		t.Fatalf("dial junk: %v", err)
	}
	_, _ = junk.Write([]byte("not a CEDAR frame"))
	_ = junk.Close()

	// After the bad handshake, a healthy one must still go through. We
	// hand off one side of a socketpair as the "forwarded" fd —
	// net.FileConn rejects non-socket fds (a pipe would fail with
	// "socket operation on non-socket"), so we need an actual stream
	// socket to drive the recvmsg path through to net.Conn.
	clientConn, passFd := mustSocketpair(t)
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = passFd.Close() }()

	var udsDialer net.Dialer
	udsConn, err := udsDialer.DialContext(context.Background(), "unix", socket)
	if err != nil {
		t.Fatalf("dial good: %v", err)
	}
	udsUnix, ok := udsConn.(*net.UnixConn)
	if !ok {
		t.Fatalf("not unix conn")
	}
	defer func() { _ = udsUnix.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := SendForwardedConn(ctx, udsUnix, passFd.Fd()); err != nil {
		t.Fatalf("SendForwardedConn: %v", err)
	}

	conn, err := acceptWithTimeout(l, 2*time.Second)
	if err != nil {
		t.Fatalf("Accept after garbage: %v", err)
	}
	_ = conn.Close()
}

func acceptWithTimeout(l *Listener, d time.Duration) (net.Conn, error) {
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := l.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-time.After(d):
		return nil, fmt.Errorf("Accept timed out after %v", d)
	}
}
