package httpserver

// Whether a client can ever hold a refresh token.
//
// Two independent things have to be true, and missing either one has the
// same symptom: the user is sent through a full re-authorization every
// time an access token expires. It is a confusing failure because
// nothing errors -- the client simply never receives a refresh token.
// This project has already been bitten by it once, with claude.ai
// re-authenticating on every expiry.
//
// Computing it here rather than in the SPA is deliberate: these are
// properties of THIS server's OAuth behavior (see filterRequestedScopes
// in mcp_handlers.go), so the rule belongs next to the code that
// implements it, where it can be tested.

const (
	// refreshTokenGrant is the grant type fosite requires before it will
	// issue a refresh token at all.
	refreshTokenGrant = "refresh_token"
	// offlineAccessScope must be in the client's ALLOWED scope set.
	// filterRequestedScopes drops any requested scope the client is not
	// registered for, so a client that asks for offline_access without
	// being allowed it has the scope stripped at authorize time and
	// fosite never mints a refresh token.
	offlineAccessScope = "offline_access"
	// authorizationCodeGrant and deviceCodeGrant are the flows with a
	// human on the other end. Only they have a person to send back
	// through consent, so only they can exhibit the symptom.
	authorizationCodeGrant = "authorization_code"
	deviceCodeGrant        = "urn:ietf:params:oauth:grant-type:device_code"
)

// refreshBlockedBy names what stops a client from ever receiving a
// refresh token, or nil when nothing does.
//
// It returns nil for a non-interactive client. A client_credentials
// integration re-authenticates from its own secret and has no user to
// inconvenience, so flagging it would be noise -- and noise in an
// advisory is worse than no advisory, because it teaches an operator to
// ignore the column.
func refreshBlockedBy(grantTypes, scopes []string) []string {
	if !containsAny(grantTypes, authorizationCodeGrant, deviceCodeGrant) {
		return nil
	}

	var blocked []string
	if !containsAny(grantTypes, refreshTokenGrant) {
		blocked = append(blocked, "the refresh_token grant")
	}
	if !containsAny(scopes, offlineAccessScope) {
		blocked = append(blocked, "the offline_access scope")
	}
	return blocked
}

func containsAny(haystack []string, needles ...string) bool {
	for _, h := range haystack {
		for _, n := range needles {
			if h == n {
				return true
			}
		}
	}
	return false
}
