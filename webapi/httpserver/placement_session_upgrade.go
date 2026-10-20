package httpserver

import (
	"net/http"
	"sync"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

// A person who signs in before they are onboarded gets a placement-only
// session. When an administrator then maps their identity to an account,
// GET /api/v1/auth/me -- which the web UI calls on every page load, on focus,
// and from the placement page's "Check again" -- re-runs the sign-in's
// identity mapping for that session, and when it now maps to an account,
// replaces the session with a full one. Only /api/v1/auth/me does this: it is
// what the web UI reads to choose its shell, and the one endpoint whose
// answer is the session itself.
//
// The rules are the SSO callback's own, run through the same code
// (mapLoginIdentity, webUILoginAccess, commitLoginMapping): HTTP_API_IDENTITY_MAP
// in its configured order, a placementd account only when it is authorized,
// unexpired and holds READ or WRITE, and the web UI's access group. Its input
// is only what the session stored at sign-in -- the provider's subject and
// groups and the placement identity it verified -- never anything from the
// request. Where groups come from the system, the stored provider groups are
// not used: the new session gets the account's system groups, as a sign-in
// would.
//
// Only a server whose HTTP_API_IDENTITY_MAP names placementd does this: that
// is the mapping an administrator changes from this server.
//
// An upgrade never changes the session in place. A new session, with a new
// id, replaces the placement-only one in a single transaction, so the old id
// stops working everywhere at once and a cookie fixed on somebody before
// they were onboarded is not promoted with them. The new session ends when
// the placement-only one would have: the sign-in it rests on is no fresher.

// placementUpgradeEvery bounds how often one session's mapping is re-run, so
// a page that polls /api/v1/auth/me does not become load on the placementd.
const placementUpgradeEvery = 30 * time.Second

// placementUpgradeThrottle remembers when each placement-only session's
// mapping was last re-run, keyed by its stored session key.
type placementUpgradeThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// allow reports whether key's mapping may be re-run now, and if so records
// that it was. Entries older than the interval are dropped as it goes, so
// the map holds only sessions that checked recently.
func (t *placementUpgradeThrottle) allow(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.last == nil {
		t.last = make(map[string]time.Time)
	}
	for k, at := range t.last {
		if now.Sub(at) >= placementUpgradeEvery {
			delete(t.last, k)
		}
	}
	if _, recent := t.last[key]; recent {
		return false
	}
	t.last[key] = now
	return true
}

// upgradePlacementSession re-runs the sign-in's identity mapping for the
// placement-only session sd, whose id is sessionID. When it now maps to an
// account the web UI admits, the session is rotated to a full one, its
// cookie is set on w, and the new session is returned with r carrying the
// new cookie. Otherwise nothing changes and it returns nil, r.
func (h *Handler) upgradePlacementSession(w http.ResponseWriter, r *http.Request, sessionID string, sd *SessionData) (*SessionData, *http.Request) {
	if !sd.IsPlacementOnly() || !h.placementOnboard.mapIdentity || h.sessionStore == nil {
		return nil, r
	}
	// A session from before the subject was kept cannot be re-mapped; the
	// person signs in again.
	if sd.IDPSubject == "" || sd.PlacementIdentity == "" {
		return nil, r
	}
	if !h.placementUpgrades.allow(sessionKey(sessionID), time.Now()) {
		return nil, r
	}
	ctx := r.Context()
	li := loginIdentity{
		subject:       sd.IDPSubject,
		groups:        sd.Groups,
		placementID:   sd.PlacementIdentity,
		placementName: sd.DisplayName,
		email:         sd.Email,
		browser:       true,
	}
	// No identity-cookie hint: the request contributes nothing.
	m := h.mapLoginIdentity(ctx, li, "")
	if m.placementOnly || m.refused != nil {
		return nil, r
	}
	if _, err := h.webUILoginAccess(li, m); err != nil {
		h.logger.Debug(logging.DestinationHTTP, "A placement-only session maps to an account the web UI does not admit",
			"identity", sd.PlacementIdentity, "account", m.subject, "error", err)
		return nil, r
	}
	if err := h.commitLoginMapping(ctx, w, li, m); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to record a placementd account", "error", err, "account", m.subject)
		return nil, r
	}
	data := browserSessionData(li, m)
	data.ExpiresAt = sd.ExpiresAt
	newID, newSD, err := h.sessionStore.Rotate(sessionID, data)
	if err != nil {
		h.logger.Warn(logging.DestinationHTTP, "Could not replace a placement-only session",
			"identity", sd.PlacementIdentity, "session_key", sessionLogID(sessionID), "error", err)
		return nil, r
	}
	h.setSessionCookie(w, newID, newSD.ExpiresAt)
	h.logger.Info(logging.DestinationSecurity, "Replaced a placement-only session with a full one after onboarding",
		"oidc_subject", sd.IDPSubject, "identity", sd.PlacementIdentity, "account", newSD.Username,
		"placementd", newSD.IsPlacementd(),
		"old_session_key", sessionLogID(sessionID), "session_key", sessionLogID(newID))
	return newSD, requestWithSessionCookie(r, newID)
}

// requestWithSessionCookie is r with its session cookie replaced by
// sessionID, so the rest of a handler sees the session just issued.
func requestWithSessionCookie(r *http.Request, sessionID string) *http.Request {
	r2 := r.Clone(r.Context())
	r2.Header.Del("Cookie")
	for _, c := range r.Cookies() {
		if c.Name != sessionCookieName {
			r2.AddCookie(c)
		}
	}
	r2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID}) //nolint:gosec // G124: a request cookie, not one set on a response
	return r2
}
