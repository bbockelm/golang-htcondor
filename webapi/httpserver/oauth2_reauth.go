package httpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/fosite"

	"github.com/bbockelm/golang-htcondor/logging"
)

// DefaultMaxGrantLifetime bounds how long a single consent can be stretched
// by refreshing. See Handler.oauth2MaxGrantLifetime.
const DefaultMaxGrantLifetime = 30 * 24 * time.Hour

// UserStatus is an oracle's verdict on whether a user is still entitled to
// hold a grant issued to them earlier.
type UserStatus int

const (
	// UserStatusUnknown means the oracle has no opinion — it could not
	// reach its backing store, or the backing store has no record of this
	// user. It is NOT a denial: absence of a record is routinely
	// indistinguishable from "this user has simply never been seen here",
	// and denying on it would lock out every user of a fresh pool.
	UserStatusUnknown UserStatus = iota
	// UserStatusActive means the oracle affirmatively vouches for the user.
	UserStatusActive
	// UserStatusRevoked means the oracle affirmatively says this user may
	// no longer hold a grant. Only this verdict revokes.
	UserStatusRevoked
)

func (s UserStatus) String() string {
	switch s {
	case UserStatusActive:
		return "active"
	case UserStatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// ReauthDecision is what a RevocationOracle reports about one user.
type ReauthDecision struct {
	// Status is the verdict on the user as a whole.
	Status UserStatus
	// Reason is a short operator-facing explanation, surfaced in logs and
	// (for revocations) in the OAuth2 error description. HTCondor's
	// per-user records carry a DisableReason string that lands here.
	Reason string
	// DeniedScopes are scopes the oracle says this user may no longer
	// hold, even when Status is Active. They are removed from the
	// refreshed grant rather than failing it, so a user who loses write
	// access keeps working read-only instead of being logged out.
	DeniedScopes []string
}

// RevocationOracle answers "is this user still entitled to what they were
// granted?" at refresh time.
//
// Implementations must fail OPEN: a backend that is unreachable, slow, or
// simply has no record of the user returns UserStatusUnknown, never
// UserStatusRevoked. A refresh endpoint that hard-denies whenever a
// dependency hiccups is an outage amplifier, and the absolute grant lifetime
// cap is what bounds exposure when every oracle is silent.
type RevocationOracle interface {
	// Name identifies the oracle in log lines.
	Name() string
	// Check reports on username, which is the grant's subject. scopes is
	// the set currently granted, so an oracle can skip work for scopes
	// nobody holds.
	Check(ctx context.Context, username string, scopes []string) (ReauthDecision, error)
}

// grantRevokedError builds the RFC 6749 error returned when a refresh grant
// is rejected outright. invalid_grant is the correct code: it tells a
// conformant client the refresh token is dead and it must start a fresh
// authorization, which is exactly what we want a removed user's client to do.
func grantRevokedError(reason string) error {
	err := fosite.ErrInvalidGrant.WithHint("The grant is no longer valid; re-authorization is required.")
	if reason != "" {
		return err.WithDescription(reason)
	}
	return err
}

// reauthorizeRefreshGrant re-runs the authorization decision for a refresh
// grant before new tokens are minted.
//
// fosite's refresh handler replays a grant verbatim: it clones the stored
// session and re-grants every scope the original grant carried, checking only
// that the *client* is still allowed those scopes. Nothing re-examines the
// user. Left alone that makes a grant immortal — every refresh also resets
// the refresh token's expiry, so a client refreshing on any cadence shorter
// than the refresh lifespan holds its access forever, including across the
// user being removed from the group that authorized it.
//
// This runs after NewAccessRequest (so the session and granted scopes are
// hydrated from storage) and before NewAccessResponse (so narrowing here
// actually shapes the tokens that get minted). It can do three things:
//
//   - revoke the whole grant, when the absolute lifetime cap has passed or an
//     oracle affirmatively says the user is gone;
//   - narrow the granted scopes, when the user's groups no longer justify
//     everything they hold;
//   - do nothing, which is the common case.
//
// A non-nil error means the caller must abandon the request; the grant has
// already been revoked in storage by then.
func (h *Handler) reauthorizeRefreshGrant(ctx context.Context, ar fosite.AccessRequester) error {
	username := ar.GetSession().GetSubject()
	granted := []string(ar.GetGrantedScopes())

	sess, ok := sessionFrom(ar)
	if !ok {
		// The row was written by a build that predates the Session type.
		// We cannot re-derive its groups or its true auth time, so it gets
		// the cap measured from now — a bounded, one-time grace rather
		// than either an immediate logout or a permanent exemption.
		h.logger.Warn(logging.DestinationHTTP,
			"Refresh grant has a legacy session; reauthorization limited to the lifetime cap",
			"username", username, "request_id", ar.GetID())
		return nil
	}

	// --- absolute lifetime cap ------------------------------------------
	if sess.AuthTime.IsZero() {
		// Same migration case as above, reached when an older row did
		// carry a Session but no auth time. Stamp it so the cap starts
		// running from first sight instead of never.
		sess.AuthTime = time.Now().UTC()
		h.logger.Info(logging.DestinationHTTP,
			"Stamping auth time on a grant that predates the lifetime cap",
			"username", username, "request_id", ar.GetID())
	} else if age := time.Since(sess.AuthTime); age > h.maxGrantLifetime() {
		reason := fmt.Sprintf("grant exceeded the maximum lifetime of %s (authorized %s ago)",
			h.maxGrantLifetime(), age.Round(time.Minute))
		h.logger.Info(logging.DestinationHTTP, "Revoking refresh grant past its lifetime cap",
			"username", username, "request_id", ar.GetID(),
			"auth_time", sess.AuthTime, "age", age.Round(time.Minute))
		h.revokeGrant(ctx, ar.GetID(), username, reason)
		return grantRevokedError(reason)
	}

	// --- group policy re-evaluation -------------------------------------
	// IMPORTANT: sess.Groups is the membership list as of consent, not a
	// live reading. Re-running the policy against it therefore catches
	// POLICY drift — an operator changing MCP_WRITE_GROUP, or adding an
	// MCP_ACCESS_GROUP where there was none — but NOT MEMBERSHIP drift.
	// A user removed from condor-writers upstream still carries
	// "condor-writers" here and still passes.
	//
	// That gap is deliberate, not an oversight. Reading live membership
	// means holding a live credential to the upstream IDP (an upstream
	// refresh token) or a separate directory binding, neither of which
	// this server has. Membership changes are covered instead by the
	// revocation oracles below, by the admin revoke endpoint, and
	// ultimately by the lifetime cap above — which is the only mechanism
	// that bounds exposure with no cooperation from anything else.
	//
	// A future live-membership source plugs in as a RevocationOracle: it
	// would re-read the user's groups, run getScopesForGroups against
	// them, and report the difference as DeniedScopes.
	//
	// A nil list means the user authenticated by a path that asserts no
	// groups (the trusted user header, say), so there is no policy to
	// re-run at all.
	if sess.Groups != nil {
		if err := h.validateGroupAccess(sess.Groups); err != nil {
			reason := fmt.Sprintf("user no longer has required group membership: %v", err)
			h.logger.Info(logging.DestinationHTTP, "Revoking refresh grant on lost group access",
				"username", username, "request_id", ar.GetID(), "groups", sess.Groups)
			h.revokeGrant(ctx, ar.GetID(), username, reason)
			return grantRevokedError(reason)
		}
		allowed := h.getScopesForGroups(sess.Groups, granted)
		if narrowed := intersectScopes(granted, allowed); len(narrowed) != len(granted) {
			h.logger.Info(logging.DestinationHTTP, "Narrowing refreshed grant to current group policy",
				"username", username, "request_id", ar.GetID(),
				"was", granted, "now", narrowed,
				"dropped", subtractScopes(granted, narrowed))
			granted = narrowed
		}
	}

	// --- external oracles -----------------------------------------------
	for _, oracle := range h.revocationOracles {
		decision, err := oracle.Check(ctx, username, granted)
		if err != nil {
			// Fail open, loudly. An oracle that cannot answer must not
			// take the token endpoint down with it.
			h.logger.Warn(logging.DestinationHTTP, "Revocation oracle failed; treating as no opinion",
				"oracle", oracle.Name(), "username", username, "error", err)
			continue
		}
		switch decision.Status {
		case UserStatusRevoked:
			reason := decision.Reason
			if reason == "" {
				reason = fmt.Sprintf("access revoked by %s", oracle.Name())
			}
			h.logger.Info(logging.DestinationHTTP, "Revoking refresh grant on oracle verdict",
				"oracle", oracle.Name(), "username", username,
				"request_id", ar.GetID(), "reason", reason)
			h.revokeGrant(ctx, ar.GetID(), username, reason)
			return grantRevokedError(reason)
		case UserStatusActive, UserStatusUnknown:
			// Fall through to the per-scope denials below; an oracle may
			// vouch for the user while still stripping individual scopes.
		}
		if len(decision.DeniedScopes) > 0 {
			if narrowed := subtractScopes(granted, decision.DeniedScopes); len(narrowed) != len(granted) {
				h.logger.Info(logging.DestinationHTTP, "Narrowing refreshed grant on oracle verdict",
					"oracle", oracle.Name(), "username", username,
					"request_id", ar.GetID(),
					"denied", decision.DeniedScopes, "now", narrowed,
					"reason", decision.Reason)
				granted = narrowed
			}
		}
	}

	// --- apply -----------------------------------------------------------
	// fosite exposes no way to un-grant a scope through the AccessRequester
	// interface, so reach the concrete request to replace the set. If the
	// type ever changes upstream, the assertion fails closed-ish: the grant
	// is not narrowed, which we log rather than silently accept.
	if len(granted) != len(ar.GetGrantedScopes()) {
		req, ok := ar.(*fosite.AccessRequest)
		if !ok {
			h.logger.Error(logging.DestinationHTTP,
				"Cannot narrow refreshed grant: unexpected AccessRequester type",
				"username", username, "request_id", ar.GetID(),
				"type", fmt.Sprintf("%T", ar))
			reason := "unable to apply current authorization policy to this grant"
			h.revokeGrant(ctx, ar.GetID(), username, reason)
			return grantRevokedError(reason)
		}
		req.GrantedScope = fosite.Arguments(granted)
	}

	return nil
}

// revokeGrant kills every token in a refresh chain. fosite preserves the
// request ID across refreshes (flow_refresh.go calls SetID with the original
// request's ID), so one request ID addresses the whole chain — the token just
// presented, its predecessors, and the access tokens minted alongside them.
//
// Errors are logged rather than returned: the caller is already rejecting the
// request, and a storage failure here must not turn a denial into a 500 that
// a client would retry.
func (h *Handler) revokeGrant(ctx context.Context, requestID, username, reason string) {
	storage := h.oauth2Provider.GetStorage()
	if err := storage.RevokeRefreshToken(ctx, requestID); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to revoke refresh token chain",
			"request_id", requestID, "username", username, "error", err)
	}
	if err := storage.RevokeAccessToken(ctx, requestID); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to revoke access tokens for grant",
			"request_id", requestID, "username", username, "error", err)
	}
	h.logger.Info(logging.DestinationHTTP, "Revoked OAuth2 grant",
		"request_id", requestID, "username", username, "reason", reason)
}

// maxGrantLifetime returns the configured absolute cap, defaulting when the
// Handler predates the knob.
func (h *Handler) maxGrantLifetime() time.Duration {
	if h.oauth2MaxGrantLifetime > 0 {
		return h.oauth2MaxGrantLifetime
	}
	return DefaultMaxGrantLifetime
}

// intersectScopes returns the members of have that also appear in allow,
// preserving have's order.
func intersectScopes(have, allow []string) []string {
	allowed := make(map[string]bool, len(allow))
	for _, s := range allow {
		allowed[s] = true
	}
	out := make([]string, 0, len(have))
	for _, s := range have {
		if allowed[s] {
			out = append(out, s)
		}
	}
	return out
}

// subtractScopes returns the members of have that do not appear in drop,
// preserving have's order.
func subtractScopes(have, drop []string) []string {
	dropped := make(map[string]bool, len(drop))
	for _, s := range drop {
		dropped[s] = true
	}
	out := make([]string, 0, len(have))
	for _, s := range have {
		if !dropped[s] {
			out = append(out, s)
		}
	}
	return out
}

// reauthorizeIDPRefreshGrant re-checks a refresh grant issued by the built-in
// IDP.
//
// The IDP is its own source of truth for who exists, which makes this a much
// stronger check than the MCP provider's: there is no upstream to be out of
// sync with. handleIDPAuthorize already gates the authorization-code path on
// UserExists, so this closes the matching hole on the refresh path, where
// fosite replays the stored session with no reference to the user table.
//
// It enforces the same absolute lifetime cap as the MCP path, then requires
// that the subject still exists and is not back in the "pending" state that
// AuthenticateUser refuses to log in.
func (h *Handler) reauthorizeIDPRefreshGrant(ctx context.Context, ar fosite.AccessRequester) error {
	username := ar.GetSession().GetSubject()
	if username == "" {
		// Nothing to check against; the grant carries no subject. Let
		// fosite's own validation decide the request's fate.
		return nil
	}

	if sess, ok := sessionFrom(ar); ok {
		if sess.AuthTime.IsZero() {
			sess.AuthTime = time.Now().UTC()
		} else if age := time.Since(sess.AuthTime); age > h.maxGrantLifetime() {
			reason := fmt.Sprintf("grant exceeded the maximum lifetime of %s (authorized %s ago)",
				h.maxGrantLifetime(), age.Round(time.Minute))
			h.logger.Info(logging.DestinationHTTP, "Revoking IDP refresh grant past its lifetime cap",
				"username", username, "request_id", ar.GetID(), "age", age.Round(time.Minute))
			h.revokeIDPGrant(ctx, ar.GetID(), username, reason)
			return grantRevokedError(reason)
		}
	}

	storage := h.idpProvider.GetStorage()
	exists, err := storage.UserExists(ctx, username)
	if err != nil {
		// Fail open on a storage error, consistent with the oracle
		// contract: a DB hiccup must not log every user out.
		h.logger.Warn(logging.DestinationHTTP,
			"Could not verify IDP user on refresh; allowing the grant",
			"username", username, "error", err)
		return nil
	}
	if !exists {
		reason := "the user account no longer exists"
		h.logger.Info(logging.DestinationHTTP, "Revoking IDP refresh grant for a deleted user",
			"username", username, "request_id", ar.GetID())
		h.revokeIDPGrant(ctx, ar.GetID(), username, reason)
		return grantRevokedError(reason)
	}

	state, err := storage.GetUserState(ctx, username)
	if err != nil {
		h.logger.Warn(logging.DestinationHTTP,
			"Could not read IDP user state on refresh; allowing the grant",
			"username", username, "error", err)
		return nil
	}
	if state == "pending" {
		// Mirrors AuthenticateUser, which refuses to log in a pending
		// account. An admin resetting a user to pending is deactivating
		// them, and that has to reach existing grants too.
		reason := "the user account is pending activation"
		h.logger.Info(logging.DestinationHTTP, "Revoking IDP refresh grant for a deactivated user",
			"username", username, "request_id", ar.GetID(), "state", state)
		h.revokeIDPGrant(ctx, ar.GetID(), username, reason)
		return grantRevokedError(reason)
	}

	return nil
}

// revokeIDPGrant is revokeGrant for the built-in IDP's separate token tables.
func (h *Handler) revokeIDPGrant(ctx context.Context, requestID, username, reason string) {
	storage := h.idpProvider.GetStorage()
	if err := storage.RevokeRefreshToken(ctx, requestID); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to revoke IDP refresh token chain",
			"request_id", requestID, "username", username, "error", err)
	}
	if err := storage.RevokeAccessToken(ctx, requestID); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to revoke IDP access tokens for grant",
			"request_id", requestID, "username", username, "error", err)
	}
	h.logger.Info(logging.DestinationHTTP, "Revoked IDP grant",
		"request_id", requestID, "username", username, "reason", reason)
}
