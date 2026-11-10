// Package proxyscrub keeps this server's own credentials out of requests
// it forwards to an HTTP server running inside a job, and keeps that
// server from setting them.
//
// A job's server is reached on this server's origin, so the browser sends
// it everything it holds for the origin: the session cookie, and on an API
// client the bearer token. Inside the sandbox those are readable by
// whatever the job runs, and either one replayed to this server acts as
// the user. The job's server has no use for them -- this server already
// decided the caller may reach the job, and the servers it launches run
// with their own authentication off.
//
// The cookie names live here rather than in the HTTP server so the two
// cannot drift apart: the server's own constants are these.
package proxyscrub

import (
	"net/http"
	"strings"
)

// The cookies this server sets on its own origin.
const (
	SessionCookie    = "htcondor_session"
	IDPSessionCookie = "idp_session"
	IdentityCookie   = "htcondor_api_last_account"
	// LoginCookie binds a pending SSO login to the browser that started
	// it; a job that could read or set it could complete someone else's.
	LoginCookie = "__Host-htcondor_login"
)

var ownCookies = map[string]bool{
	SessionCookie:    true,
	IDPSessionCookie: true,
	IdentityCookie:   true,
	LoginCookie:      true,
}

// Request headers that carry a credential or say who the caller is.
var credentialHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"Forwarded",
	"X-Real-Ip",
	"X-Remote-User",
	"Remote-User",
	// Tokens an authenticating ingress in front of this server adds.
	"Cf-Access-Jwt-Assertion",
	"X-Goog-Iap-Jwt-Assertion",
}

// Prefixes of the same, compared case-insensitively: oauth2-proxy's
// X-Auth-Request-* and X-Forwarded-User/-Email/-Access-Token, AWS ALB's
// X-Amzn-Oidc-*, mod_auth_openidc's OIDC_*.
var credentialPrefixes = []string{
	"x-forwarded-",
	"x-auth-request-",
	"x-amzn-oidc-",
	"oidc_",
}

// forwardedAddress are the X-Forwarded-* headers that describe this
// server's public address rather than the caller. They pass through:
// web apps build their own URLs from them, and the proxies have always
// forwarded whatever the ingress set.
var forwardedAddress = map[string]bool{
	"X-Forwarded-Host":   true,
	"X-Forwarded-Proto":  true,
	"X-Forwarded-Port":   true,
	"X-Forwarded-Prefix": true,
}

// Scrubber removes credentials from proxied requests and responses. The
// zero value and a nil *Scrubber both remove the fixed set.
type Scrubber struct {
	extra []string
}

// New returns a Scrubber that also removes the named request headers --
// the header this server is configured to read a username from.
func New(extraHeaders ...string) *Scrubber {
	s := &Scrubber{}
	for _, h := range extraHeaders {
		if h = strings.TrimSpace(h); h != "" {
			s.extra = append(s.extra, h)
		}
	}
	return s
}

// Request removes this server's credentials from an outbound proxy
// request. Call it from a ReverseProxy Director.
//
// Only this server's cookies are removed from Cookie; the rest belong to
// the job's server, which may need them (an XSRF cookie, its own login).
// The Connection and Upgrade headers are left alone, so a WebSocket
// handshake still upgrades.
func (s *Scrubber) Request(req *http.Request) {
	h := req.Header
	for _, name := range credentialHeaders {
		h.Del(name)
	}
	if s != nil {
		for _, name := range s.extra {
			h.Del(name)
		}
	}
	for name := range h {
		if forwardedAddress[name] {
			continue
		}
		lower := strings.ToLower(name)
		for _, p := range credentialPrefixes {
			if strings.HasPrefix(lower, p) {
				delete(h, name)
				break
			}
		}
	}
	// A nil value stops ReverseProxy appending the caller's address
	// after the Director returns.
	h["X-Forwarded-For"] = nil

	stripCookies(h)
}

// stripCookies removes this server's cookies from every Cookie header,
// keeping the others byte for byte.
func stripCookies(h http.Header) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var kept []string
	for _, line := range lines {
		var parts []string
		for part := range strings.SplitSeq(line, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, _, _ := strings.Cut(part, "=")
			if ownCookies[strings.TrimSpace(name)] {
				continue
			}
			parts = append(parts, part)
		}
		if len(parts) > 0 {
			kept = append(kept, strings.Join(parts, "; "))
		}
	}
	if len(kept) == 0 {
		h.Del("Cookie")
		return
	}
	h["Cookie"] = kept
}

// Response drops any Set-Cookie for one of this server's cookies. Use it
// as a ReverseProxy's ModifyResponse. A job that could set the session
// cookie on this origin could log the browser in as somebody else, or out.
func (s *Scrubber) Response(resp *http.Response) error {
	lines := resp.Header.Values("Set-Cookie")
	if len(lines) == 0 {
		return nil
	}
	kept := lines[:0:0]
	for _, line := range lines {
		pair, _, _ := strings.Cut(line, ";")
		name, _, _ := strings.Cut(pair, "=")
		if ownCookies[strings.TrimSpace(name)] {
			continue
		}
		kept = append(kept, line)
	}
	if len(kept) == 0 {
		resp.Header.Del("Set-Cookie")
		return nil
	}
	resp.Header["Set-Cookie"] = kept
	return nil
}
