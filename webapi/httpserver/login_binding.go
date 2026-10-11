package httpserver

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/proxyscrub"
)

// A login that leaves for the IdP is bound to the browser that started it.
//
// The OAuth2 state alone does not do that: it proves the callback answers
// a login this server started, not that the browser presenting it is the
// one that started it. Without the binding, a callback URL obtained by
// starting a login and authenticating as one person could be completed in
// another person's browser, which would then hold a session for the first.
//
// So every path that stores a state for the IdP round trip gives the
// browser a nonce in a short-lived cookie and stores the same nonce with
// the state, and the callback accepts the state only from a browser that
// presents it.
//
// The cookie is SameSite=Lax because the callback is a top-level
// navigation from the IdP's site, which Lax admits and Strict does not.
// The __Host- prefix keeps a sibling host from setting it. One nonce
// serves every login the browser has in flight, so two tabs logging in at
// once do not overwrite each other's binding.
const (
	loginBindingCookieName = proxyscrub.LoginCookie
	loginBindingNonceBytes = 32
)

// bindLoginToBrowser returns the nonce to store with a new login state,
// and sets (or refreshes) the cookie that carries it.
func (h *Handler) bindLoginToBrowser(w http.ResponseWriter, r *http.Request) (string, error) {
	nonce := ""
	if c, err := r.Cookie(loginBindingCookieName); err == nil && validLoginNonce(c.Value) {
		nonce = c.Value
	} else {
		b := make([]byte, loginBindingNonceBytes)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		nonce = base64.RawURLEncoding.EncodeToString(b)
	}
	expires := time.Now().Add(oauth2StateLifetime)
	http.SetCookie(w, &http.Cookie{
		Name:     loginBindingCookieName,
		Value:    nonce,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(oauth2StateLifetime.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nonce, nil
}

// loginBoundToBrowser reports whether r carries the binding stored with a
// login state. A state stored without one never matches: it was not made
// for the IdP round trip.
func loginBoundToBrowser(r *http.Request, binding string) bool {
	if binding == "" {
		return false
	}
	c, err := r.Cookie(loginBindingCookieName)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(binding)) == 1
}

// validLoginNonce accepts only a value this server could have issued, so
// a cookie of some other shape is replaced rather than reused.
func validLoginNonce(v string) bool {
	b, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(b) == loginBindingNonceBytes
}
