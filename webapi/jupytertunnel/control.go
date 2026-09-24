package jupytertunnel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

// The control channel carries the one thing the helper cannot work out for
// itself: the token it must present next.
//
// Tokens are single-use, so a helper that has connected once holds a spent
// one and could never come back. Minting the replacement needs the signing
// secret, which lives only on the server -- deliberately, since a helper runs
// on an execute node -- so the replacement has to be handed over.
//
// It travels as a yamux stream rather than a header on the websocket
// handshake because the handshake is over before the token is minted: the
// upgrade happens first so a rejected tunnel can still be sent a clean CLOSE
// frame, which is worth more than saving this stream.
//
// controlMagic distinguishes it from a proxied request. Every other stream
// carries an HTTP request to the local JupyterLab socket, and an HTTP
// request-line cannot begin with a NUL, so the two can never be confused --
// which matters, because mistaking a control stream for a request would
// forward a live credential to JupyterLab.
const controlMagic = "\x00JUPYTER-CTRL/1\n"

// controlNextToken is the one control verb: "here is your next token".
const controlNextToken = "next-token "

// controlDeadline bounds a control exchange. It is two short writes on an
// established tunnel; anything slower is a stuck peer, and the caller has a
// working session to get on with.
const controlDeadline = 10 * time.Second

// SendNextToken hands an instance's helper the token for its next dial.
func SendNextToken(inst *Instance, token string) error {
	if inst == nil {
		return errors.New("jupytertunnel: no instance")
	}
	inst.mu.Lock()
	session := inst.tunnel
	inst.mu.Unlock()
	return sendNextToken(session, token)
}

// sendNextToken hands the helper the token for its next dial.
//
// Best-effort by contract: the session it was just given is working, and
// failing the connection because the NEXT one cannot be provisioned would
// turn a future inconvenience into a present outage. The caller logs.
func sendNextToken(session *yamux.Session, token string) error {
	if session == nil || token == "" {
		return errors.New("jupytertunnel: no session or token")
	}
	stream, err := session.Open()
	if err != nil {
		return fmt.Errorf("opening the control stream: %w", err)
	}
	defer func() { _ = stream.Close() }()
	_ = stream.SetWriteDeadline(time.Now().Add(controlDeadline))
	if _, err := io.WriteString(stream, controlMagic+controlNextToken+token+"\n"); err != nil {
		return fmt.Errorf("writing the next token: %w", err)
	}
	return nil
}

// readControl consumes a control stream the peer has opened, returning the
// verb's argument.
//
// The magic has already been matched by the caller, which had to read those
// bytes to know this was a control stream at all.
func readControl(r *bufio.Reader) (verb, arg string, err error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if strings.HasPrefix(line, controlNextToken) {
		return "next-token", strings.TrimPrefix(line, controlNextToken), nil
	}
	// An unknown verb is not an error worth tearing the tunnel down for:
	// a newer server may send something this helper predates, and the
	// session it is carrying is still good.
	return line, "", nil
}

// peekControl reports whether a freshly-accepted stream is a control stream,
// handing back a reader positioned after the magic when it is, and one that
// has consumed nothing when it is not.
func peekControl(stream net.Conn) (*bufio.Reader, bool) {
	br := bufio.NewReader(stream)
	head, err := br.Peek(len(controlMagic))
	if err != nil || string(head) != controlMagic {
		// Not control, or too short to tell. Either way the reader has
		// consumed nothing, so the proxy path sees the stream intact.
		return br, false
	}
	_, _ = br.Discard(len(controlMagic))
	return br, true
}
