package httpserver

import (
	"net/http"
	"strings"

	"github.com/bbockelm/golang-htcondor/webapi/siteapps"
)

// expertCookieName marks a session that has stepped through the expert
// door and wants the full console.
//
// A cookie rather than a field on the session record, because it is not
// a privilege and should not look like one in storage. It expires with
// the session for the same reason: nobody should acquire a permanently
// cluttered console by having been curious once.
const expertCookieName = "htcondor_site_expert"

// isAppOnly reports whether this session should be sent to its app
// instead of the dashboard.
//
// True only when EVERY group the caller holds is an app-only group. A
// user who is also in a staff group has a reason to see the console,
// and taking it away from them because of one of their memberships
// would be the wrong way round.
func (h *Handler) isAppOnly(groups []string) bool {
	if !h.webuiAppOnlyGroups.configured() || len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if !h.webuiAppOnlyGroups.allows([]string{g}) {
			return false
		}
	}
	return true
}

// expertModeArmed reports that this request asked for the full console.
func expertModeArmed(r *http.Request) bool {
	c, err := r.Cookie(expertCookieName)
	return err == nil && c.Value != ""
}

// handleExpertMode is the door: GET /site/expert opens the full
// console for this session, and ?close=1 returns to app-only.
//
// Deliberately a visible link that says "Expert mode" rather than a
// query parameter somebody has to know about. The mechanism is the
// same; a hidden one has worse ergonomics and becomes folklore.
func (h *Handler) handleExpertMode(w http.ResponseWriter, r *http.Request) {
	session, ok := h.getSessionFromRequest(r)
	if !ok {
		h.siteAppLogin(w, r)
		return
	}

	if r.URL.Query().Get("close") != "" {
		http.SetCookie(w, &http.Cookie{
			Name: expertCookieName, Value: "", Path: "/",
			MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, h.appOnlyDestination(session.Groups), http.StatusFound)
		return
	}

	// Session-scoped: no Expires and no Max-Age, so it dies with the
	// browser session the same way the login cookie does.
	http.SetCookie(w, &http.Cookie{
		Name: expertCookieName, Value: "1", Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// appOnlyDestination is where an app-only session belongs: its single
// home if it has exactly one, and otherwise the switcher.
//
// More than one home is a supported state, not an edge case -- group
// memberships overlap -- and picking one of them arbitrarily would send
// half of those people to the wrong place every time.
func (h *Handler) appOnlyDestination(groups []string) string {
	if h.siteApps == nil {
		return "/site/"
	}
	homes := h.siteApps.Homes(groups)
	if len(homes) == 1 {
		return siteapps.MountPath(homes[0].App.ID)
	}
	return "/site/"
}

// appOnlyRedirect wraps the SPA so an app-only session lands on its app
// rather than the dashboard.
//
// This is presentation, not authorization, and the difference matters
// enough to say twice: the API is untouched, every page is still
// reachable by typing its URL, and a user who takes the expert door
// gets the whole console. What this prevents is a non-technical user
// meeting a general-purpose batch console they did not ask for -- not
// a determined one reaching it.
func (h *Handler) appOnlyRedirect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.webuiAppOnlyGroups.configured() || !isRedirectableUIPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if expertModeArmed(r) {
			next.ServeHTTP(w, r)
			return
		}
		session, ok := h.getSessionFromRequest(r)
		if !ok || !h.isAppOnly(session.Groups) {
			next.ServeHTTP(w, r)
			return
		}
		dest := h.appOnlyDestination(session.Groups)
		if dest == r.URL.Path {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, dest, http.StatusFound)
	})
}

// isRedirectableUIPath reports whether a path is a page a browser
// navigates to, as opposed to an asset, an API call or a login step.
//
// Redirecting an asset would break the very app we are sending people
// to: its JavaScript and CSS come from the same catch-all handler as
// its pages.
func isRedirectableUIPath(p string) bool {
	switch {
	case p == "/":
		return true
	case strings.HasPrefix(p, "/api/"),
		strings.HasPrefix(p, "/site/"),
		strings.HasPrefix(p, "/login"),
		strings.HasPrefix(p, "/logout"),
		strings.HasPrefix(p, "/idp/"),
		strings.HasPrefix(p, "/mcp"),
		strings.HasPrefix(p, "/.well-known/"),
		strings.HasPrefix(p, "/_next/"),
		p == "/healthz", p == "/readyz", p == "/metrics":
		return false
	}
	// Anything with a file extension is an asset the export serves.
	if dot := strings.LastIndex(p, "."); dot >= 0 && !strings.Contains(p[dot:], "/") {
		return strings.EqualFold(p[dot:], ".html")
	}
	return true
}
