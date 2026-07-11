package droppriv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"syscall"
)

// maxFrameSize bounds a single protocol frame. Requests carry paths and argv,
// which are comfortably small; the bound guards against a corrupt length prefix.
const maxFrameSize = 1 << 20 // 1 MiB

// errFrameTooLarge indicates a length prefix exceeding maxFrameSize.
var errFrameTooLarge = errors.New("droppriv: protocol frame too large")

// msgConn is a synchronous, framed message channel over one end of an
// AF_UNIX/SOCK_STREAM socketpair. Each frame is a 4-byte big-endian length
// followed by a JSON payload; file descriptors ride along as SCM_RIGHTS
// ancillary data attached to the frame's bytes. The protocol is strictly
// request/reply with a single frame in flight per direction, so a fresh recv
// loop per frame never straddles two frames.
//
// A msgConn is NOT safe for concurrent senders or concurrent receivers; the
// pool serializes each helper so only one goroutine drives a given msgConn at a
// time.
type msgConn struct {
	fd  int
	buf []byte // carry-over bytes read past the current frame (normally empty)
}

func newMsgConn(fd int) *msgConn {
	return &msgConn{fd: fd}
}

// send writes payload as one frame, attaching passFDs (if any) as SCM_RIGHTS.
func (c *msgConn) send(payload []byte, passFDs []int) error {
	if len(payload) > maxFrameSize {
		return errFrameTooLarge
	}
	frame := make([]byte, 4+len(payload))
	//nolint:gosec // G115 - payload length is bounded by the maxFrameSize check above, well within uint32.
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)

	var oob []byte
	if len(passFDs) > 0 {
		oob = syscall.UnixRights(passFDs...)
	}

	// First chunk carries the ancillary data. SendmsgN reports how many data
	// bytes were accepted; any remainder is a plain stream write.
	n, err := syscall.SendmsgN(c.fd, frame, oob, nil, 0)
	if err != nil {
		return fmt.Errorf("droppriv: sendmsg: %w", err)
	}
	for n < len(frame) {
		m, werr := syscall.Write(c.fd, frame[n:])
		if werr != nil {
			return fmt.Errorf("droppriv: write frame: %w", werr)
		}
		n += m
	}
	return nil
}

// recv reads one frame and returns its payload plus any received file
// descriptors. On a clean peer close it returns io.EOF.
func (c *msgConn) recv() ([]byte, []int, error) {
	var fds []int

	// Ensure we have the 4-byte length header.
	for len(c.buf) < 4 {
		more, moreFDs, err := c.readChunk()
		if err != nil {
			if errors.Is(err, io.EOF) && len(c.buf) == 0 {
				return nil, nil, io.EOF
			}
			return nil, fds, err
		}
		c.buf = append(c.buf, more...)
		fds = append(fds, moreFDs...)
	}

	frameLen := int(binary.BigEndian.Uint32(c.buf[:4]))
	if frameLen > maxFrameSize {
		return nil, fds, errFrameTooLarge
	}

	for len(c.buf) < 4+frameLen {
		more, moreFDs, err := c.readChunk()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fds, io.ErrUnexpectedEOF
			}
			return nil, fds, err
		}
		c.buf = append(c.buf, more...)
		fds = append(fds, moreFDs...)
	}

	payload := make([]byte, frameLen)
	copy(payload, c.buf[4:4+frameLen])
	c.buf = c.buf[4+frameLen:]
	return payload, fds, nil
}

// readChunk performs one recvmsg, returning any data bytes and any file
// descriptors decoded from SCM_RIGHTS ancillary data.
func (c *msgConn) readChunk() ([]byte, []int, error) {
	data := make([]byte, 64*1024)
	oob := make([]byte, 256)
	n, oobn, _, _, err := syscall.Recvmsg(c.fd, data, oob, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("droppriv: recvmsg: %w", err)
	}
	if n == 0 && oobn == 0 {
		return nil, nil, io.EOF
	}

	var fds []int
	if oobn > 0 {
		scms, perr := syscall.ParseSocketControlMessage(oob[:oobn])
		if perr != nil {
			closeFDs(fds)
			return nil, nil, fmt.Errorf("droppriv: parse control message: %w", perr)
		}
		for i := range scms {
			rights, rerr := syscall.ParseUnixRights(&scms[i])
			if rerr != nil {
				closeFDs(fds)
				return nil, nil, fmt.Errorf("droppriv: parse unix rights: %w", rerr)
			}
			fds = append(fds, rights...)
		}
	}
	return data[:n], fds, nil
}

func (c *msgConn) close() error {
	return syscall.Close(c.fd)
}

// closeFDs closes a batch of received descriptors, used on error paths so a
// partially decoded ancillary payload never leaks a descriptor.
func closeFDs(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}
