package jupytertunnel

import (
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// yamuxFrame is a yamux header (version 0) followed by body.
func yamuxFrame(msgType uint8, flags uint16, stream, length uint32, body []byte) []byte {
	hdr := make([]byte, 12, 12+len(body))
	hdr[1] = msgType
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint32(hdr[4:8], stream)
	binary.BigEndian.PutUint32(hdr[8:12], length)
	return append(hdr, body...)
}

const (
	yamuxData = 0
	yamuxPing = 2
	yamuxSYN  = 1
	yamuxACK  = 2
)

// discardFrame is a well-formed yamux data frame for a stream that does
// not exist, which yamux reads and throws away -- so the only thing
// that can end a session over one is its size.
func discardFrame(size int) []byte {
	return yamuxFrame(yamuxData, 0, 7, uint32(size), make([]byte, size)) //nolint:gosec // test sizes are small
}

// A message larger than the tunnel's read limit closes the tunnel
// instead of being buffered whole. One within it does not.
func TestAnOversizedTunnelMessageClosesTheTunnel(t *testing.T) {
	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	id, tok, err := reg.CreateInstance(CreateInstanceOptions{Owner: "x"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	accepted := make(chan *Tunnel, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		tun, err := reg.AcceptTunnel(id, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ws)
		if err != nil {
			t.Errorf("AcceptTunnel: %v", err)
			_ = ws.Close()
			return
		}
		accepted <- tun
	}))
	defer srv.Close()

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+tok)
	helper, resp, err := websocket.DefaultDialer.Dial(strings.Replace(srv.URL, "http://", "ws://", 1), hdr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	defer func() { _ = helper.Close() }()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the tunnel was never accepted")
	}
	tunnelClosed := func() bool {
		inst, ok := reg.Lookup(id)
		if !ok {
			return true
		}
		inst.mu.Lock()
		defer inst.mu.Unlock()
		return inst.tunnel == nil || inst.tunnel.IsClosed()
	}

	// Within the limit: discarded, and the session answers a ping after
	// it -- which proves it read past the frame and is still up.
	send := func(b []byte) {
		t.Helper()
		if err := helper.WriteMessage(websocket.BinaryMessage, b); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	send(discardFrame(maxTunnelMessage / 2))
	send(yamuxFrame(yamuxPing, yamuxSYN, 0, 42, nil))
	_ = helper.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, msg, err := helper.ReadMessage()
		if err != nil {
			t.Fatalf("the tunnel did not answer a ping after a message within the limit: %v", err)
		}
		if len(msg) >= 12 && msg[1] == yamuxPing && binary.BigEndian.Uint16(msg[2:4])&yamuxACK != 0 {
			break
		}
	}
	if tunnelClosed() {
		t.Fatal("a message within the limit closed the tunnel")
	}

	// Past it: the session ends, and the helper sees its connection go.
	send(discardFrame(maxTunnelMessage))
	_ = helper.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, _, err := helper.ReadMessage(); err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				t.Fatal("the tunnel stayed open after a message over the limit")
			}
			break
		}
	}
	if !waitFor(5*time.Second, tunnelClosed) {
		t.Fatal("the registry still holds the tunnel open")
	}
}
