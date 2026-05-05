// Package sharedport implements the endpoint side of HTCondor's
// shared_port HTTP/HTTPS forwarding protocol.
//
// When SHARED_PORT_HTTP_FORWARDING_ID is set on a condor_shared_port
// daemon, traffic that doesn't speak the CEDAR command protocol (i.e.
// looks like HTTP/1.x or a TLS ClientHello) is handed off to a
// "designated" daemon by passing the connected client fd over a Unix
// domain socket via SCM_RIGHTS.
//
// Wire protocol on the UDS, per shared_port_server / shared_port_endpoint:
//
//  1. The server sends a single CEDAR-framed message containing the
//     int command SHARED_PORT_PASS_SOCK (76) terminated by an
//     end-of-message marker.
//  2. The server then sendmsg(2)s a 1-byte iov plus an SCM_RIGHTS
//     ancillary record carrying the connected client fd.
//  3. No application-level ack is sent in either direction; the UDS
//     connection is then closed by the server.
//
// We model the forwarded fds as net.Conn values produced by a
// net.Listener implementation, so callers (notably http.Server.Serve)
// can treat them like any other accepted connection.
package sharedport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// SharedPortPassSock is the CEDAR command id that shared_port_server
// uses on the UDS handshake before passing the fd. Mirrors the C++
// constant SHARED_PORT_PASS_SOCK = 76 in condor_commands.h.
const SharedPortPassSock = 76

// CEDAR's framed wire format on a connection:
//
//	[1 byte: end flag] [4 bytes: payload length, big-endian] [payload]
//
// PutInt encodes its value as 8 bytes big-endian (uint64), so a single
// "PutInt; FinishMessage" is one frame whose payload length is 8.
const (
	cedarHeaderSize    = 5  // 1-byte end flag + 4-byte length
	cedarIntPayloadLen = 8  // PutInt encodes int64
	maxHeaderPayload   = 64 // sanity bound; the only valid command here is 8 bytes
)

// readPassSockHeader consumes the CEDAR-framed header sent by shared_port
// over the UDS, validates that it carries SHARED_PORT_PASS_SOCK, and
// returns nil on success. Anything else (short read, bad length, wrong
// command) returns a descriptive error so the caller can drop the
// connection without engaging recvmsg.
func readPassSockHeader(r io.Reader) error {
	var hdr [cedarHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("read CEDAR frame header: %w", err)
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length == 0 || length > maxHeaderPayload {
		return fmt.Errorf("unexpected CEDAR frame length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("read CEDAR frame payload: %w", err)
	}
	if len(payload) != cedarIntPayloadLen {
		return fmt.Errorf("expected %d-byte int payload, got %d", cedarIntPayloadLen, len(payload))
	}
	//nolint:gosec // CEDAR ints are 8 bytes; we compare against a small constant
	cmd := int64(binary.BigEndian.Uint64(payload))
	if cmd != SharedPortPassSock {
		return fmt.Errorf("unexpected command %d; want SHARED_PORT_PASS_SOCK (%d)", cmd, SharedPortPassSock)
	}
	return nil
}

// writePassSockHeader is the producer side of the CEDAR-framed header.
// Used by tests (and in principle by any client that wants to emulate
// shared_port's handshake) so we can exercise the receiver in-process
// without standing up condor_shared_port.
//
// We pick endFlag = 1 ("complete message in single frame") to match
// the value cedar's stream.SendMessage emits.
func writePassSockHeader(w io.Writer) error {
	var frame [cedarHeaderSize + cedarIntPayloadLen]byte
	frame[0] = 1 // EndFlagComplete
	binary.BigEndian.PutUint32(frame[1:5], cedarIntPayloadLen)
	binary.BigEndian.PutUint64(frame[5:13], uint64(SharedPortPassSock))
	_, err := w.Write(frame[:])
	return err
}

// errClosed signals that the listener has been Close()'d. Returned via
// Accept() so http.Server.Serve recognises shutdown rather than tight-
// looping on the failure.
var errClosed = errors.New("sharedport: listener closed")
