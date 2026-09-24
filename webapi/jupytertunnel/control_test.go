package jupytertunnel

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A control stream must be distinguishable from a proxied request, and the
// distinction has to be one an HTTP request cannot accidentally satisfy:
// mistaking one for the other would forward a live credential to JupyterLab.
func TestControlStreamIsNotMistakenForARequest(t *testing.T) {
	for _, req := range []string{
		"GET /api/kernels HTTP/1.1\r\nHost: x\r\n\r\n",
		"POST /api/sessions HTTP/1.1\r\n\r\n",
		"", // too short to tell
	} {
		br := bufio.NewReader(strings.NewReader(req))
		if _, isControl := peekControl(readerConn{br}); isControl {
			t.Errorf("an HTTP request was read as a control stream: %q", req)
		}
	}
}

// And the bytes peeked at must survive, or every proxied request loses its
// opening line.
func TestPeekLeavesARequestIntact(t *testing.T) {
	const req = "GET /api/kernels HTTP/1.1\r\nHost: x\r\n\r\n"
	br, isControl := peekControl(readerConn{bufio.NewReader(strings.NewReader(req))})
	if isControl {
		t.Fatal("classified as control")
	}
	got := make([]byte, len(req))
	if _, err := br.Read(got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got[:4]) != "GET " {
		t.Errorf("request starts %q; the peeked bytes were lost", got[:8])
	}
}

func TestControlStreamCarriesTheNextToken(t *testing.T) {
	payload := controlMagic + controlNextToken + "tok-abc\n"
	br, isControl := peekControl(readerConn{bufio.NewReader(strings.NewReader(payload))})
	if !isControl {
		t.Fatal("a control stream was not recognised")
	}
	verb, arg, err := readControl(br)
	if err != nil {
		t.Fatalf("readControl: %v", err)
	}
	if verb != "next-token" || arg != "tok-abc" {
		t.Errorf("verb=%q arg=%q", verb, arg)
	}
}

// A token written non-atomically can be found half-written by a helper
// that restarts mid-write, and a truncated token authenticates nothing.
func TestPersistTokenReplacesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jupyter-token")
	if err := os.WriteFile(path, []byte("old-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistToken(path, "new-token"); err != nil {
		t.Fatalf("persistToken: %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // path is this test's own TempDir
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-token" {
		t.Errorf("token = %q", got)
	}
	// The temp file must not be left behind: the sandbox is the job's
	// scratch dir and gets transferred back on some configurations.
	if _, err := os.Stat(path + ".new"); !os.IsNotExist(err) {
		t.Error("the temporary file survived the rename")
	}
}

// readerConn is the read half of a net.Conn over a reader, which is all
// peekControl touches.
type readerConn struct{ r *bufio.Reader }

func (c readerConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c readerConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c readerConn) Close() error                     { return nil }
func (c readerConn) LocalAddr() net.Addr              { return nil }
func (c readerConn) RemoteAddr() net.Addr             { return nil }
func (c readerConn) SetDeadline(time.Time) error      { return nil }
func (c readerConn) SetReadDeadline(time.Time) error  { return nil }
func (c readerConn) SetWriteDeadline(time.Time) error { return nil }

// The proxy path must forward the bytes peekControl already pulled off the
// stream. Reading the raw stream instead of the buffered reader silently
// drops them, so JupyterLab sees a request with its opening bytes missing --
// on every request, which is the sort of corruption that looks like a
// mysterious protocol error rather than a bug here.
func TestProxiedRequestArrivesWhole(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	got := make(chan string, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			got <- "accept: " + aerr.Error()
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 512)
		n, _ := c.Read(buf)
		got <- string(buf[:n])
	}()

	const req = "GET /api/kernels HTTP/1.1\r\nHost: x\r\n\r\n"
	client, server := net.Pipe()
	go func() {
		_, _ = io.WriteString(client, req)
		_ = client.Close()
	}()

	// Exactly what the accept loop does: classify, then proxy.
	br, isControl := peekControl(server)
	if isControl {
		t.Fatal("an ordinary request was classified as control")
	}
	handleBufferedStream(context.Background(), server, br, sock, func(string, ...any) {})

	select {
	case line := <-got:
		if line != req {
			t.Errorf("upstream received %q, want the whole request %q", line, req)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing reached the upstream socket")
	}
}
