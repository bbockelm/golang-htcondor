package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/bbockelm/golang-htcondor/logging"
)

// consentCSRFField is the hidden input the consent forms carry.
const consentCSRFField = "csrf_token"

// consentCSRFKey is the consent forms' own subkey of the application
// master. See purposeKey.
func (h *Handler) consentCSRFKey() []byte {
	return h.purposeKey(consentCSRFInfo, &h.consentCSRFKeyOnce, &h.consentCSRFKeyBytes,
		"the consent form CSRF token")
}

// consentCSRFToken authenticates a consent form back to the person it was
// rendered for.
//
// The forms that use it are the two that hand out credentials: the
// authorization consent page and the device verification page. Both were
// relying on SameSite=Lax alone, which protects a cookie and therefore
// protects nothing in a deployment that authenticates with a proxy-set
// header -- a supported mode. ServeHTTP's Origin check now covers them
// too; this is the second opinion that does not depend on the browser
// telling the truth about where it came from, and it is what the OWASP
// guidance asks for on a form that grants access.
//
// Bound to the username and to the request the form is about -- the
// authorization's state, or the device's user code -- so a token minted
// for one person's form cannot approve another's, and a token minted for
// one request cannot approve a different one.
//
// Keyed by its own HKDF subkey of the application master, not by the SSH
// approval token's. Both descend from the same master, which is what
// makes them manageable -- wrapped under the pool signing keys, stable
// across restarts and replicas -- and the separate labels are what stop
// a token minted for one from verifying against the other.
func (h *Handler) consentCSRFToken(username, binding string) string {
	mac := hmac.New(sha256.New, h.consentCSRFKey())
	// Length-prefixed rather than concatenated: with a separator alone,
	// a crafted username could borrow part of the binding.
	_, _ = fmt.Fprintf(mac, "consent:%d:%s%d:%s", len(username), username, len(binding), binding)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// checkConsentCSRF verifies the token a consent form posted back.
//
// Returns false for an absent token as well as a wrong one. There is no
// grandfathering path: a form rendered by a build without the field is a
// form from before this existed, and accepting one would leave the hole
// open to anybody who could replay an old page.
func (h *Handler) checkConsentCSRF(r *http.Request, username, binding string) bool {
	presented := r.FormValue(consentCSRFField)
	if presented == "" {
		return false
	}
	want := h.consentCSRFToken(username, binding)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(want)) == 1
}

// refuseStaleConsent answers a consent POST whose token did not verify.
//
// Deliberately the same answer whether the token was missing, wrong, or
// minted for somebody else: the form is reloadable, and distinguishing
// the cases tells whoever is probing which part they got right.
func (h *Handler) refuseStaleConsent(w http.ResponseWriter, r *http.Request, username, why string) {
	h.logger.Warn(logging.DestinationSecurity,
		"Refusing a consent form that did not verify",
		"reason", why, "username", username,
		"path", r.URL.Path, "origin", r.Header.Get("Origin"))
	h.renderResultPage(w, http.StatusBadRequest,
		"Session Expired", "#b45309", "This form is no longer valid",
		"Reload the page and try again.",
		"If you did not open this page yourself, you can close it.")
}
