package httpserver

import (
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// Session is the fosite session persisted for every grant this server
// issues, for both the MCP OAuth2 provider and the built-in IDP.
//
// It exists to carry the *inputs* of the authorization decision alongside
// its output, so that a refresh grant can recompute the decision instead of
// replaying it. fosite's refresh pipeline rebuilds a request by cloning the
// stored session and re-granting whatever scopes the original grant carried
// (see handler/oauth2/flow_refresh.go), so anything the refresh path needs
// has to survive that round trip. Two fields do that work:
//
//   - Groups: the IDP-asserted group memberships that produced the granted
//     scopes at consent time. They are read once from the userinfo endpoint
//     and otherwise dropped on the floor, so without persisting them here
//     the refresh path cannot re-run getScopesForGroups at all. Note this is
//     a snapshot, not a live reading — see reauthorizeRefreshGrant for what
//     that does and does not catch.
//   - AuthTime: when the human actually authenticated and consented. Every
//     refresh resets the refresh token's own expiry, so AuthTime is the only
//     fixed point from which an absolute cap on the grant can be measured.
//
// Both are advisory inputs to reauthorizeRefreshGrant; nothing else reads
// them, and a session that predates this type (deserialized from a row
// written by an older build) simply has them zero-valued. See
// reauthorizeRefreshGrant for how that case is handled.
type Session struct {
	*openid.DefaultSession

	// Groups is the group list asserted by the upstream IDP (or the
	// browser session) at the time consent was granted.
	Groups []string `json:"groups,omitempty"`

	// AuthTime is when the user authenticated and consented, in UTC.
	// It is deliberately NOT refreshed when the grant is refreshed.
	AuthTime time.Time `json:"authTime,omitempty"`
}

// Clone deep-copies the session, including the fields declared above.
//
// This override is load-bearing; do not delete it. openid.DefaultSession has
// its own Clone that reflection-copies its receiver, and if that method were
// left to promote through the embedded pointer it would return a bare
// *openid.DefaultSession and silently drop Groups and AuthTime. fosite's
// refresh handler rebuilds every refreshed request via
// originalRequest.GetSession().Clone(), so a promoted Clone would erase
// exactly the data the refresh path exists to consult — and erase it
// quietly, because the result still satisfies fosite.Session and a missing
// group list is indistinguishable from "this user has no groups".
//
// TestSessionClonedeepPreservesFields guards this.
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	clone := &Session{AuthTime: s.AuthTime}
	if s.DefaultSession != nil {
		// DefaultSession.Clone returns a fosite.Session whose concrete
		// type is *openid.DefaultSession.
		if inner, ok := s.DefaultSession.Clone().(*openid.DefaultSession); ok {
			clone.DefaultSession = inner
		}
	}
	if s.DefaultSession != nil && clone.DefaultSession == nil {
		// Defensive: never hand back a Session with a nil embedded
		// pointer, since every promoted accessor would panic.
		clone.DefaultSession = &openid.DefaultSession{}
	}
	if s.Groups != nil {
		clone.Groups = append([]string(nil), s.Groups...)
	}
	return clone
}

// WithGroups records the group memberships that authorized this grant and
// returns the session, for chaining at the consent call sites.
func (s *Session) WithGroups(groups []string) *Session {
	if s == nil {
		return nil
	}
	if groups == nil {
		s.Groups = nil
		return s
	}
	s.Groups = append([]string(nil), groups...)
	return s
}

// newSession builds a Session for an authenticated user. issuer names the
// component minting the ID token ("htcondor-mcp" or "htcondor-idp").
func newSession(username, issuer string) *Session {
	now := time.Now().UTC()
	return &Session{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   username,
				Issuer:    issuer,
				IssuedAt:  now,
				ExpiresAt: now.Add(1 * time.Hour),
				// auth_time is a standard OIDC claim and carries the
				// same meaning as Session.AuthTime; the duplicate keeps
				// the authoritative copy out of the ID token claims,
				// which callers are free to overwrite.
				AuthTime: now,
				// requested_at must be set whenever auth_time is, and to
				// the same instant. fosite never populates this claim
				// itself, it only reads it, and for prompt=none it
				// checks auth_time <= requested_at
				// (handler/openid/strategy_jwt.go). A zero requested_at
				// makes any auth_time "after" it, so the check fails and
				// the token endpoint answers 500 server_error with
				//
				//	Failed to generate id token because prompt was set to
				//	'none' but auth_time happened after the authorization
				//	request was registered
				//
				// Sharing `now` makes the two Equal, which satisfies both
				// that comparison and the mirrored one for prompt=login.
				RequestedAt: now,
			},
			Headers: &jwt.Headers{},
			Subject: username,
		},
		AuthTime: now,
	}
}

// newEmptySession builds the zero-valued session handed to fosite when it is
// about to hydrate one from storage (token endpoint, introspection). The
// embedded pointer must be non-nil: storage unmarshals the persisted JSON
// directly into this value, and every promoted accessor dereferences it.
//
// Passing a bare &openid.DefaultSession{} here instead would still compile
// and still authenticate — the extra fields would just silently decode into
// nothing, and refresh-time reauthorization would see every grant as having
// no groups and no auth time.
func newEmptySession() *Session {
	return &Session{DefaultSession: &openid.DefaultSession{}}
}

// sessionFrom extracts our Session from a fosite request, reporting whether
// the request carried one. A false return means the grant was persisted by a
// build that predates this type, or that some call site handed fosite a bare
// openid.DefaultSession; callers decide how to treat that.
func sessionFrom(r fosite.Requester) (*Session, bool) {
	if r == nil {
		return nil, false
	}
	s, ok := r.GetSession().(*Session)
	return s, ok
}
