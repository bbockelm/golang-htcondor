package jupytertunnel

import (
	"errors"

	"github.com/gorilla/websocket"
)

// Telling "try again" apart from "never again".
//
// A reconnect loop that retries everything is right for a server that is
// restarting and wrong for a token that will never be accepted: it holds a
// slot for the rest of the job, dialing every minute, with a live JupyterLab
// behind it that nobody can reach.
//
// The two are distinguishable at the far end. A server that is down refuses
// the connection or fails the handshake; a server that is up and has decided
// against this helper says so with a policy-violation close, which is what
// the tunnel handler sends when the token does not verify.
//
// Why a token can stop being accepted at all: the roll is not transactional
// with its delivery. The server commits the next nonce, then hands the token
// over the control stream, and a helper that dies in between -- or whose
// control stream fails -- keeps a token the server has already moved past.
// Nothing recovers that, because re-issuing requires the authentication that
// just failed.

// ErrIdleTimeout reports that the helper's idle watcher gave up.
//
// Distinct from a lost connection, which looks the same at the accept loop
// and means the opposite: one is a session that should end, the other a
// session that should come back. Conflating them lets a reconnect dial
// straight back in and turns the idle timeout into a no-op.
var ErrIdleTimeout = errors.New("jupytertunnel: idle timeout")

// ErrRejected reports a refusal that retrying cannot fix.
var ErrRejected = errors.New("jupytertunnel: the server rejected this helper's token")

// rejectionCloseCodes are the close codes that mean "not you, not ever".
//
// PolicyViolation is what the tunnel handler sends for a token that does not
// verify. Normal and GoingAway are deliberately absent: those are an orderly
// shutdown, which is exactly when a helper SHOULD come back.
var rejectionCloseCodes = []int{
	websocket.ClosePolicyViolation,
}

// IsRejection reports whether an error from RunHelperTunnel means this
// helper will never be accepted again.
//
// Conservative: anything unrecognised is treated as retryable, because
// giving up wrongly ends a session that would have recovered, while
// retrying wrongly only wastes a slot until the job's ceiling.
func IsRejection(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrRejected) {
		return true
	}
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		for _, code := range rejectionCloseCodes {
			if ce.Code == code {
				return true
			}
		}
	}
	return websocket.IsCloseError(err, rejectionCloseCodes...)
}
