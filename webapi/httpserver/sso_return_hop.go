package httpserver

import (
	"fmt"
	"html"
	"net/http"
)

// finishBrowserLogin sends the browser to redirectURL after a successful
// SSO login, in a way the session cookie survives.
//
// Not an http.Redirect, and that is the whole point.
//
// The session cookie is SameSite=Strict, so a browser withholds it on a
// cross-site request. Arriving back from the identity provider IS cross
// site, and a 302 does not end the chain: the browser attributes the
// whole redirect chain to whoever started it, so the request to
// redirectURL still counts as coming from the IdP and still arrives
// without the cookie we just set. The page then sees no session, sends
// the user to the IdP again, and the user is in a loop they cannot get
// out of by trying harder.
//
// Reported from production: a logged-out person opening an SSH device
// code URL bounced through CILogon forever. Two things made it look
// intermittent and hid it for a while. Opening the same URL a second
// time works, because an address-bar navigation has no initiator and so
// is same-site -- the session was there all along, the browser just
// would not send it. And anyone already signed in to the dashboard never
// meets it at all.
//
// So the browser performs the last hop itself. This page is same-origin
// with redirectURL, so the navigation it starts is same-site, Strict is
// satisfied, and the cookie goes. The cost is one render that is visible
// for a few milliseconds.
//
// The alternative is SameSite=Lax, which setSessionCookie's own comment
// rejects because it lets a cross-site top-level GET carry the cookie --
// a CSRF foothold for any state-changing endpoint that accepts GET.
// Keeping Strict and paying for one render keeps that closed at the
// cookie layer.
func (s *Handler) finishBrowserLogin(w http.ResponseWriter, redirectURL string) {
	// Both escapes matter and they are different escapes: one for an
	// HTML attribute, one for a JavaScript string literal. redirectURL
	// has already been checked by isSafeLocalRedirect, so this is
	// defence in depth rather than the only thing standing here.
	attr := html.EscapeString(redirectURL)
	js := jsStringLiteral(redirectURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// No-store: this page names where somebody was going, and it is
	// worthless to replay.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	// location.replace rather than assignment, so the back button skips
	// this page instead of bouncing the user through it again.
	//
	// The meta refresh and the link are for a browser with JavaScript
	// off: the refresh still performs a same-site navigation, and the
	// link is there if even that is disabled, so the flow degrades to
	// one extra click rather than to a dead end.
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0; url=%s">
<title>Signing you in</title>
</head>
<body>
<p>Signing you in&hellip; <a href="%s">continue</a> if nothing happens.</p>
<script>location.replace(%s);</script>
</body>
</html>
`, attr, attr, js)
}

// jsStringLiteral renders s as a quoted JavaScript string.
//
// Written out rather than reached for from encoding/json because the
// characters that matter here are the ones that end the literal or the
// enclosing <script>: a redirect carrying `</script>` would otherwise
// close the block and whatever followed would be markup.
func jsStringLiteral(s string) string {
	out := make([]rune, 0, len(s)+2)
	out = append(out, '"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			out = append(out, '\\', r)
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '<', '>', '&':
			// \u-escaped so neither the HTML parser nor a naive
			// sanitiser sees a tag boundary inside the script.
			out = append(out, []rune(fmt.Sprintf("\\u%04x", r))...)
		default:
			out = append(out, r)
		}
	}
	return string(append(out, '"'))
}
