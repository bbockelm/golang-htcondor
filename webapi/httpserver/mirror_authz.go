package httpserver

import (
	"context"
	"errors"
	"net/http"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// A read served from the htcondordb mirror is a read the schedd never
// sees: the mirror is dialed with this daemon's own credential, not the
// caller's. Reading the queue or the history is a READ-level command on
// the schedd, so the mirror may answer only a caller whose credential
// the schedd accepts at READ -- otherwise a credential the schedd would
// refuse (an identity outside ALLOW_READ, a token whose authorizations
// do not include READ) reads every job out of the mirror instead.
//
// Being identified is not the same thing. DC_NOP, which identity
// resolution used to ping with, is registered at ALLOW and succeeds for
// anything the schedd can authenticate; an opaque OAuth2 access token is
// identified by this server's own authorization server and never shown
// to the schedd at all; a browser session is identified by its cookie.

// mirrorReadVerified reports whether the schedd has accepted this
// request's credential at READ level, which is what serving it from the
// mirror requires. ctx is the request's authenticated context.
//
// The answer is cached for as long as a resolved identity is (see
// mcpActorTTL), so a mirror read costs at most one handshake per caller
// per interval rather than one per request. A request that cannot be
// verified is not refused here; the caller stays off the mirror, and the
// schedd answers it or refuses it as it would have anyway.
func (h *Handler) mirrorReadVerified(ctx context.Context, r *http.Request) bool {
	user := htcondor.GetAuthenticatedUserFromContext(ctx)
	if user == "" {
		return false
	}
	// Without a credential of its own the ping would authenticate as this
	// daemon and verify nothing about the caller. An API key that carries
	// no condor:/ scope is such a request.
	if _, ok := htcondor.GetSecurityConfigFromContext(ctx); !ok {
		return false
	}

	// A bearer is verified by the same READ-level resolution that
	// identifies forwarded tokens, keyed by the bearer and charged to the
	// request's source like every other resolution. For those tokens this
	// is the cached answer createAuthenticatedContext already obtained;
	// for an opaque access token, identified by the authorization server
	// rather than the schedd, it is the first time the schedd is asked. A
	// throttled resolution is not a verification.
	if bearer, err := extractBearerToken(r); err == nil && bearer != "" {
		actor, rerr := h.resolveActor(ctx, r, bearer)
		return rerr == nil && actor != ""
	}

	// A session cookie or a trusted user header: the credential is minted
	// per request for this username, so whether the schedd accepts it
	// depends on the username alone, which is what the answer is keyed by.
	// A separate cache from the bearer one, whose keys are attacker-chosen
	// strings: a bearer equal to someone's username must not find their
	// answer.
	if actor, ok := h.mirrorReaders.get(user); ok {
		return actor != ""
	}
	result, err := h.pingAsCaller(ctx)
	if err != nil || result.User == "" {
		h.logger.Info(logging.DestinationHTTP, "The schedd did not accept this caller at READ; their reads will not be served from the htcondordb mirror",
			"user", user, "error", err)
		h.mirrorReaders.put(user, "", mcpActorFailTTL)
		return false
	}
	h.mirrorReaders.put(user, result.User, mcpActorTTL)
	return true
}

// errMirrorNotVerified is why a read that could have come from the
// mirror did not.
var errMirrorNotVerified = errors.New("the schedd has not accepted this caller's credential for reading, so the htcondordb mirror cannot answer for it")

// mirrorAllowed returns nil when this request may be answered from the
// mirror: routing is configured, and the caller passes
// mirrorReadVerified. Otherwise it says why, for the caller's log. The
// order matters only for cost -- with no mirror there is no reason to
// ask the schedd anything.
func (h *Handler) mirrorAllowed(ctx context.Context, r *http.Request) error {
	if !h.dbMirror.Enabled() {
		return errors.New("no htcondordb mirror is configured")
	}
	if !h.mirrorReadVerified(ctx, r) {
		return errMirrorNotVerified
	}
	return nil
}
