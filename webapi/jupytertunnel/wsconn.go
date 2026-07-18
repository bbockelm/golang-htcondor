// Package jupytertunnel implements an outbound-only reverse tunnel for
// running short-lived web services (initially: JupyterLab) inside an HTCondor
// job and exposing them through the htcondor-api web app.
//
// Topology:
//
//	browser ─HTTPS─▶ web app ─yamux stream─┐
//	                                       │
//	                       (one persistent ws, opened by the helper outward)
//	                                       │
//	                                       ▼
//	                    worker ─UDS─▶ jupyter lab
//	                    (helper)
//
// The helper inside the job opens a single websocket back to the web app and
// wraps it with hashicorp/yamux. The web app multiplexes browser HTTP
// requests onto that websocket, one yamux stream per request. The helper
// accepts each stream and proxies its bytes to a Unix domain socket where
// JupyterLab is listening. The UDS scopes the service so other users on the
// worker host cannot reach it; the websocket is bearer-token authenticated.
package jupytertunnel

import (
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsConn adapts a *websocket.Conn into an io.ReadWriteCloser suitable for
// hashicorp/yamux. yamux performs its own framing, so we just need to ferry
// arbitrary byte slices in both directions; we use binary websocket frames
// as the carrier.
type wsConn struct {
	ws *websocket.Conn

	// readMu guards the websocket's reader side: gorilla/websocket only
	// allows one concurrent reader. yamux is single-threaded for reads, so
	// in practice this is uncontended — the mutex is for safety.
	readMu sync.Mutex
	rb     []byte // bytes left over from the last binary message

	// writeMu serializes binary writes (gorilla/websocket requires a single
	// concurrent writer) and the close write.
	writeMu sync.Mutex

	closed   chan struct{}
	closeOne sync.Once
}

// newWSConn wraps a websocket connection. Caller must not use ws directly
// after handing it to this adapter.
func newWSConn(ws *websocket.Conn) *wsConn {
	return &wsConn{ws: ws, closed: make(chan struct{})}
}

func (c *wsConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.rb) == 0 {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		default:
		}
		mt, msg, err := c.ws.ReadMessage()
		if err != nil {
			return 0, err
		}
		// Ignore non-binary frames (control frames are handled by gorilla
		// internally; text frames are an error from a yamux peer but we
		// don't want to crash).
		if mt != websocket.BinaryMessage {
			continue
		}
		c.rb = msg
	}
	n := copy(p, c.rb)
	c.rb = c.rb[n:]
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) Close() error {
	c.closeOne.Do(func() { close(c.closed) })
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	// Best-effort close frame; ignore errors since the peer might be gone.
	_ = c.ws.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "tunnel closing"),
		time.Now().Add(2*time.Second),
	)
	return c.ws.Close()
}

// Compile-time interface conformance: yamux only uses io.ReadWriteCloser, but
// we also satisfy net.Conn-ish to be future-proof. The deadlines below are
// passthroughs to the websocket's deadline support.

func (c *wsConn) LocalAddr() net.Addr  { return c.ws.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }
