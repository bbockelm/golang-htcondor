// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// The identity cookie remembers which local account a subject mapped to
// last time, so a later login can confirm that mapping directly instead of
// rebuilding the whole GECOS index to discover it.
//
// The index inverts GECOS -> account, which needs an enumeration of the
// account database. Confirming a KNOWN account needs only a by-name
// lookup, which reaches the directory even where nothing can enumerate it.
// So a returning user can be mapped in the window where a cold SSSD can
// answer getpwnam but not getpwent.
//
// Why this is safe against a forged cookie: the cookie only PROPOSES an
// account. The test applied to it is "does this account currently have the
// asserted subject as its GECOS", and the subject comes from the identity
// provider, not the cookie. Naming somebody else's account therefore only
// succeeds if that account's GECOS already equals the attacker's own
// subject -- which is the mapping a full resolution would have returned
// anyway.
//
// It is signed regardless, for the one thing verification cannot check: a
// by-name confirmation cannot see that TWO accounts share the GECOS, which
// a full resolution refuses as ambiguous. Issuing the cookie only from a
// complete index, and accepting only cookies we issued, means the
// ambiguity question was answered when the cookie was minted.
const (
	identityCookieName = "htcondor_api_last_account"

	// Long enough to span the restarts and redeploys this exists for,
	// short enough that "it was unambiguous when issued" is a claim about
	// the recent past.
	identityCookieLifetime = 7 * 24 * time.Hour
)

// identityCookiePayload binds an account to the subject it was issued for.
// A cookie minted for one subject proposes nothing for another.
type identityCookiePayload struct {
	Account string `json:"a"`
	Subject string `json:"s"`
	Expires int64  `json:"e"`
}

// identityCookieEnabled reports whether there is a key to sign with. With
// no signing keys in the deployment there is no master, so the hint is
// simply unavailable and every login takes the index path.
func (s *Handler) identityCookieEnabled() bool { return len(s.identityCookieKey) > 0 }

func (s *Handler) signIdentityCookie(p identityCookiePayload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, s.identityCookieKey)
	mac.Write([]byte(enc))
	return enc + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// readIdentityCookie returns the account a previous login recorded for
// this subject, or "" if there is no usable hint.
//
// Every failure is silent and returns "": a missing, expired, forged or
// mismatched cookie is not an error, it just means this login resolves the
// ordinary way.
func (s *Handler) readIdentityCookie(r *http.Request, subject string) string {
	if !s.identityCookieEnabled() || subject == "" {
		return ""
	}
	c, err := r.Cookie(identityCookieName)
	if err != nil || c.Value == "" {
		return ""
	}

	enc, sig, ok := strings.Cut(c.Value, ".")
	if !ok || enc == "" || sig == "" {
		return ""
	}
	mac := hmac.New(sha256.New, s.identityCookieKey)
	mac.Write([]byte(enc))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return ""
	}

	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return ""
	}
	var p identityCookiePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return ""
	}
	if p.Expires <= time.Now().Unix() {
		return ""
	}
	// Bound to the subject it was issued for.
	if p.Subject != subject {
		return ""
	}
	return p.Account
}

// setIdentityCookie records a mapping for next time.
//
// Called only where the mapping was made against a COMPLETE index; see the
// ambiguity note above.
func (s *Handler) setIdentityCookie(w http.ResponseWriter, subject, account string) {
	if !s.identityCookieEnabled() || subject == "" || account == "" {
		return
	}
	expires := time.Now().Add(identityCookieLifetime)
	value, err := s.signIdentityCookie(identityCookiePayload{
		Account: account, Subject: subject, Expires: expires.Unix(),
	})
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     identityCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
