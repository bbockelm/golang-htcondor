package httpserver

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
)

// Authenticating to the htcondordb mirror.
//
// The mirror connection used to offer only whatever the ambient
// SEC_CLIENT_AUTHENTICATION_METHODS provided, which on a containerised
// access point is usually nothing that can work: FS wants a shared
// filesystem and matching uid, Kerberos wants a ccache, and SSL wants a
// certificate the mirror's has not outlived. An observed failure listed
// all three and never mentioned TOKEN, because cedar skips that method
// when it has no token to offer -- so "all authentication methods
// failed" was reporting on a set that excluded the one likely to work.
//
// This daemon already mints IDTOKENs for talking to the schedd on a
// user's behalf. htcondordb's session command requires READ
// (server.go: srv.Handle(command.DBSession, s.handleSession, "READ")),
// so a short-lived token asserting READ for the daemon's own identity is
// enough, and is the method least coupled to how the two are deployed.

// dbMirrorTokenSubject is the identity the mirror token asserts when the
// operator has not chosen one. "condor@<trust domain>" is HTCondor's
// conventional daemon identity, which is what an htcondordb's ALLOW_READ
// is most likely to already admit.
const dbMirrorTokenSubject = "condor"

// dbMirrorTokenLifetime is short on purpose: the token authenticates one
// connection, is never handed to anyone, and cedar caches the resulting
// session, so a brief expiry costs nothing and limits the damage if one
// leaks into a log.
const dbMirrorTokenLifetime = 10 * time.Minute

// mirrorTokenSource returns a function that mints an IDTOKEN for the
// htcondordb mirror, or nil when this daemon cannot mint one.
//
// Returning nil rather than a function that always errors is deliberate:
// the Locator treats a nil source as "no token configured" and says
// nothing about it, while a source that fails is reported. A deployment
// with no signing key has not misconfigured anything and should not be
// told it has.
func (h *Handler) mirrorTokenSource() func(context.Context) (string, error) {
	if h.signingKeyPath == "" || h.trustDomain == "" {
		return nil
	}
	subject := h.dbMirrorTokenSubject
	if subject == "" {
		subject = dbMirrorTokenSubject + "@" + h.trustDomain
	}
	keyDir := filepath.Dir(h.signingKeyPath)
	keyID := filepath.Base(h.signingKeyPath)

	return func(_ context.Context) (string, error) {
		iat := time.Now().Unix()
		exp := time.Now().Add(dbMirrorTokenLifetime).Unix()
		// generateMCPAccessJWT rather than cedar's GenerateJWT for the
		// same reason the schedd path uses it: it backdates nbf to
		// absorb clock skew between this pod and the peer, which has
		// been seen to reject tokens over a single second.
		token, err := generateMCPAccessJWT(keyDir, keyID, subject, h.trustDomain, iat, exp, []string{"READ"})
		if err != nil {
			return "", fmt.Errorf("minting an htcondordb token for %q: %w", subject, err)
		}
		return token, nil
	}
}
