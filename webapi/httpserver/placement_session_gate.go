package httpserver

import (
	"net/http"
	"path"
	"strings"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/webui"
)

// A placement-only session belongs to somebody who signed in but maps to no
// local account. It exists so they can get a placement token, and it reaches
// nothing else. Two things enforce that:
//
//   - getSessionFromRequest does not return such a session, so every
//     handler that authenticates from the session sees none; and
//   - this gate, in front of the whole mux, refuses every route outside
//     placementOnlyAllowed before any handler runs.
//
// The gate is the one the route-walking test holds to account: a route
// added later is refused unless it is added to the allowlist here.

// placementOnlyAPIPaths are the exact API and server paths a placement-only
// session may use, besides /api/v1/placement/me and below.
var placementOnlyAPIPaths = map[string]bool{
	"/api/v1/auth/me":            true,
	"/api/v1/auth/logout":        true,
	"/login":                     true,
	"/logout":                    true,
	"/auth/device_authorization": true,
	"/auth/code":                 true,
	"/auth/cancel_device":        true,
	// This server's own device verification page, where a placement-only
	// session may approve a placement request and nothing else (the
	// handler checks which).
	mcpDeviceVerifyPath:   true,
	webUIDeviceVerifyPath: true,
	// The chrome of the placement pages this session does reach: what
	// the site is called and what goes in its footer.
	brandingPath:  true,
	webui.CSSPath: true,
}

// placementOnlyPages are the web UI pages a placement-only session may load.
var placementOnlyPages = map[string]bool{
	"/placement":        true,
	"/placement/device": true,
}

// placementOnlyAllowed reports whether a placement-only session may make
// this request. pattern is the mux pattern the request matched.
func placementOnlyAllowed(urlPath, pattern string) bool {
	if placementOnlyAPIPaths[urlPath] {
		return true
	}
	if urlPath == "/api/v1/placement/me" || strings.HasPrefix(urlPath, "/api/v1/placement/me/") {
		return true
	}
	if strings.HasPrefix(urlPath, brandingAssetPrefix) {
		return true
	}
	if pattern != "/" {
		return false
	}
	// The web UI. Its pages are the same static files an anonymous
	// visitor gets, but only the placement pages are for this session;
	// assets (scripts, styles, images, page data) are not pages.
	page := strings.TrimSuffix(urlPath, "/")
	page = strings.TrimSuffix(page, ".html")
	if placementOnlyPages[page] {
		return true
	}
	return strings.Contains(path.Base(urlPath), ".")
}

// placementSessionGate refuses a placement-only session's request for
// anything outside the allowlist, reporting whether it did. Page loads are
// sent to /placement; everything else is a 403.
func (h *Handler) placementSessionGate(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || !strings.HasPrefix(c.Value, placementSessionPrefix) {
		return false
	}
	_, pattern := h.mux.Handler(r)
	if placementOnlyAllowed(r.URL.Path, pattern) {
		return false
	}
	// The cookie looks like a placement session; refuse only if it is one.
	// An expired one makes the request anonymous, which the handler
	// decides about as usual.
	session, ok := h.getAnySessionFromRequest(r)
	if !ok || !session.IsPlacementOnly() {
		return false
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && pattern == "/" {
		http.Redirect(w, r, "/placement", http.StatusFound)
		return true
	}
	h.logger.Debug(logging.DestinationHTTP, "Refused a placement-only session outside placement",
		"method", r.Method, "path", r.URL.Path)
	h.writeError(w, http.StatusForbidden,
		"This sign-in can only request placement tokens. It is not linked to an account on this access point.")
	return true
}
