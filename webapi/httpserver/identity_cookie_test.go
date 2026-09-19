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
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/collections/crypt"
)

func cookieHandler(t *testing.T) *Handler {
	t.Helper()
	master, err := crypt.NewMaster()
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypt.Subkey(master, identityCookieInfo)
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{logger: testLogger(t), identityCookieKey: key}
}

// issuedFor is the subject every cookie in these tests is minted for.
const (
	issuedFor     = "bockelman@wisc.edu"
	issuedAccount = "bbockelm"
)

// roundTrip issues a cookie and reads it back as a later request would.
func roundTrip(t *testing.T, issuer, reader *Handler, readAs string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	issuer.setIdentityCookie(rec, issuedFor, issuedAccount)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	return reader.readIdentityCookie(req, readAs)
}

func TestTheIdentityCookieRoundTrips(t *testing.T) {
	h := cookieHandler(t)
	if got := roundTrip(t, h, h, "bockelman@wisc.edu"); got != "bbockelm" {
		t.Errorf("hint = %q, want bbockelm", got)
	}
}

// The signature is what lets the hint stand in for an ambiguity check that
// a by-name confirmation cannot perform. A cookie this daemon did not mint
// must therefore be ignored entirely.
func TestACookieSignedWithAnotherKeyIsIgnored(t *testing.T) {
	issuer, reader := cookieHandler(t), cookieHandler(t)
	if got := roundTrip(t, issuer, reader, "bockelman@wisc.edu"); got != "" {
		t.Errorf("hint = %q; a cookie from a foreign key was accepted", got)
	}
}

func TestATamperedCookieIsIgnored(t *testing.T) {
	h := cookieHandler(t)
	rec := httptest.NewRecorder()
	h.setIdentityCookie(rec, "bockelman@wisc.edu", "bbockelm")

	c := rec.Result().Cookies()[0]
	// Re-sign nothing: swap the payload for one naming a different
	// account, keeping the original signature.
	forged, err := h.signIdentityCookie(identityCookiePayload{
		Account: "root", Subject: "bockelman@wisc.edu",
		Expires: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := cutAt(forged, '.')
	_, sig := cutAt(c.Value, '.')

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name: identityCookieName, Value: payload + "." + sig,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	if got := h.readIdentityCookie(req, "bockelman@wisc.edu"); got != "" {
		t.Errorf("hint = %q; a payload swapped under an old signature was accepted", got)
	}
}

// A cookie is a claim about ONE identity. Presenting somebody else's must
// propose nothing, so a shared browser cannot leak a mapping across
// logins.
func TestACookieForAnotherSubjectIsIgnored(t *testing.T) {
	h := cookieHandler(t)
	if got := roundTrip(t, h, h, "tatannen@wisc.edu"); got != "" {
		t.Errorf("hint = %q; a cookie issued for another subject was offered", got)
	}
}

func TestAnExpiredCookieIsIgnored(t *testing.T) {
	h := cookieHandler(t)
	value, err := h.signIdentityCookie(identityCookiePayload{
		Account: "bbockelm", Subject: "bockelman@wisc.edu",
		Expires: time.Now().Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name: identityCookieName, Value: value,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	if got := h.readIdentityCookie(req, "bockelman@wisc.edu"); got != "" {
		t.Errorf("hint = %q; an expired cookie was accepted", got)
	}
}

// With no signing keys there is no master and no cookie key, and the hint
// must simply not exist rather than fall back to something unsigned.
func TestWithoutAKeyNoCookieIsIssuedOrRead(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	rec := httptest.NewRecorder()
	h.setIdentityCookie(rec, "bockelman@wisc.edu", "bbockelm")
	if len(rec.Result().Cookies()) != 0 {
		t.Error("a cookie was issued with no key to sign it")
	}

	signed := cookieHandler(t)
	if got := roundTrip(t, signed, h, "bockelman@wisc.edu"); got != "" {
		t.Errorf("hint = %q; a keyless handler accepted a cookie", got)
	}
}

// The cookie must not leak to script or travel in the clear: it names a
// local account.
func TestTheIdentityCookieIsHardened(t *testing.T) {
	h := cookieHandler(t)
	rec := httptest.NewRecorder()
	h.setIdentityCookie(rec, "bockelman@wisc.edu", "bbockelm")

	c := rec.Result().Cookies()[0]
	if !c.HttpOnly {
		t.Error("cookie is readable by script")
	}
	if !c.Secure {
		t.Error("cookie may travel in the clear")
	}
	if c.SameSite != http.SameSiteLaxMode && c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v", c.SameSite)
	}
}

// --- the master key it hangs off -------------------------------------

func TestTheMasterKeySurvivesAndRotates(t *testing.T) {
	db := newTestDB(t, filepath.Join(t.TempDir(), "app.db"))
	ctx := context.Background()

	pool := crypt.KEK{ID: "POOL", Material: []byte("pool-key-material-0123456789")}
	first, err := openOrCreateMaster(ctx, db, []crypt.KEK{pool})
	if err != nil || len(first) == 0 {
		t.Fatalf("openOrCreateMaster: %v", err)
	}

	// A second open with the same key recovers the SAME master, or
	// everything derived from it would silently change.
	again, err := openOrCreateMaster(ctx, db, []crypt.KEK{pool})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if string(again) != string(first) {
		t.Fatal("reopening minted a different master key")
	}

	// Rotation: a newly added signing key gets its own wrapping, so the
	// old one can later be withdrawn.
	next := crypt.KEK{ID: "NEXT", Material: []byte("second-key-material-987654321")}
	if _, err := openOrCreateMaster(ctx, db, []crypt.KEK{pool, next}); err != nil {
		t.Fatalf("adding a key: %v", err)
	}
	viaNext, err := openOrCreateMaster(ctx, db, []crypt.KEK{next})
	if err != nil {
		t.Fatalf("opening with the rotated-in key alone: %v", err)
	}
	if string(viaNext) != string(first) {
		t.Error("the rotated-in key recovered a different master")
	}
}

// A master that no available key can open must be an error. Minting a
// replacement would silently invalidate everything it protects, and the
// likely cause -- a misconfigured SEC_PASSWORD_DIRECTORY -- is the
// recoverable half of the problem.
func TestAnUnopenableMasterIsRefusedRatherThanReplaced(t *testing.T) {
	db := newTestDB(t, filepath.Join(t.TempDir(), "app.db"))
	ctx := context.Background()

	if _, err := openOrCreateMaster(ctx, db,
		[]crypt.KEK{{ID: "POOL", Material: []byte("the-original-key-material-01")}}); err != nil {
		t.Fatal(err)
	}

	_, err := openOrCreateMaster(ctx, db,
		[]crypt.KEK{{ID: "POOL", Material: []byte("a-DIFFERENT-key-material-99")}})
	if err == nil {
		t.Fatal("a master that could not be opened was silently replaced")
	}
}

// No signing keys means no master: the deployment has nothing to key an
// envelope with, and inventing one any reader of the database could also
// derive would be worse than doing without.
func TestNoSigningKeysMeansNoMaster(t *testing.T) {
	db := newTestDB(t, filepath.Join(t.TempDir(), "app.db"))
	master, err := openOrCreateMaster(context.Background(), db, nil)
	if err != nil {
		t.Fatalf("openOrCreateMaster: %v", err)
	}
	if master != nil {
		t.Error("a master key was minted with no signing key to wrap it")
	}
}

// cutAt splits on the first sep, mirroring strings.Cut without importing
// it into every test.
func cutAt(s string, sep byte) (before, after string) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}
