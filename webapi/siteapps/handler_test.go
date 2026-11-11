package siteapps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// testHandler builds a library from dir and wraps it, with the caller
// holding the given groups.
func testHandler(t *testing.T, dir string, authenticated bool, groups ...string) *Handler {
	t.Helper()
	lib := NewLibrary(dir)
	t.Cleanup(func() { _ = lib.Close() })
	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	identify := func(*http.Request) Caller {
		return Caller{Authenticated: authenticated, Groups: groups}
	}
	login := func(w http.ResponseWriter, r *http.Request) {
		// G710: the destination is a fixed local path with the request
		// path appended as a query value; nothing here is attacker
		// controlled in a way that could leave the origin.
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.Path), http.StatusFound) //nolint:gosec
	}
	return NewHandler(lib, identify, login)
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
	return rec
}

func twoAppDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeBundle(t, dir, "cryoem", "name: CryoEM Pipeline\n", map[string]string{
		"web/index.html":      "<html><head></head><body>cryoem</body></html>",
		"web/assets/app.js":   "// smith lab secrets",
		"web/deep/nested.css": "body{}",
	})
	writePolicy(t, dir, "cryoem", "groups: [smith_lab]\n")
	writeBundle(t, dir, "seqqc", "name: SeqQC\n", defaultFiles())
	writePolicy(t, dir, "seqqc", "groups: [jones_lab]\n")
	return dir
}

func TestMemberGetsTheApp(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab")

	rec := get(h, "/site/cryoem/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "cryoem") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// THE test for this package. A gate wired up on the HTML alone passes
// a check of the app root and still ships the bundle's JavaScript --
// which is where the pipeline names and parameters live -- to anyone
// who asks.
func TestNonMemberIsRefusedOnNestedAssetsToo(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "jones_lab")

	for _, path := range []string{
		"/site/cryoem/",
		"/site/cryoem/index.html",
		"/site/cryoem/assets/app.js",
		"/site/cryoem/deep/nested.css",
		"/site/cryoem/some/client/route",
	} {
		rec := get(h, path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "smith lab secrets") {
			t.Errorf("GET %s leaked the bundle's content", path)
		}
	}
}

// 404 rather than 403: the set of app ids is site information and a
// 403 confirms which exist.
func TestNonMemberCannotDistinguishMissingFromForbidden(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "nobody")

	existing := get(h, "/site/cryoem/")
	missing := get(h, "/site/doesnotexist/")
	if existing.Code != missing.Code {
		t.Errorf("an existing app answers %d and a missing one %d; the difference says which exist",
			existing.Code, missing.Code)
	}
	if existing.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", existing.Code)
	}
}

// Not logged in is a different situation from not permitted: send the
// browser to log in rather than a 404 they would read as a broken link.
func TestUnauthenticatedIsSentToLogin(t *testing.T) {
	h := testHandler(t, twoAppDir(t), false)

	rec := get(h, "/site/cryoem/assets/app.js")
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want a redirect", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Errorf("Location = %q, want the login page", loc)
	}
	if strings.Contains(rec.Body.String(), "smith lab secrets") {
		t.Error("content was served to an unauthenticated caller")
	}
}

// Group-scoped bytes must not land in a shared cache.
func TestResponsesArePrivateAndUncached(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab")

	for _, path := range []string{"/site/cryoem/", "/site/cryoem/assets/app.js"} {
		rec := get(h, path)
		cc := rec.Header().Get("Cache-Control")
		if !strings.Contains(cc, "private") || !strings.Contains(cc, "no-store") {
			t.Errorf("GET %s Cache-Control = %q, want private and no-store", path, cc)
		}
		if v := rec.Header().Get("Vary"); !strings.Contains(v, "Cookie") {
			t.Errorf("GET %s Vary = %q, want Cookie", path, v)
		}
	}
}

// The bundle learns its mount point from the server, which is what
// lets the same artifact be deployed under a different file name.
func TestPagesAreToldTheirMountPoint(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab")

	rec := get(h, "/site/cryoem/")
	body := rec.Body.String()
	if !strings.Contains(body, `<base href="/site/cryoem/">`) {
		t.Errorf("no base tag: %s", body)
	}

	start := strings.Index(body, "window.__HTCONDOR_APP__=")
	if start < 0 {
		t.Fatalf("no app global: %s", body)
	}
	raw := body[start+len("window.__HTCONDOR_APP__="):]
	end := strings.Index(raw, ";</script>")
	if end < 0 {
		t.Fatalf("the app global is not terminated: %s", raw)
	}
	raw = raw[:end]

	var got appGlobal
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("app global is not valid JSON (%v): %s", err, raw)
	}
	if got.ID != "cryoem" || got.Base != "/site/cryoem/" || got.Name != "CryoEM Pipeline" {
		t.Errorf("app global = %+v", got)
	}
}

// Assets must not be injected into, and must come back byte-exact.
func TestAssetsAreNotInjected(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab")

	rec := get(h, "/site/cryoem/assets/app.js")
	if body := rec.Body.String(); body != "// smith lab secrets" {
		t.Errorf("asset body = %q, want it unchanged", body)
	}
}

// Client-side routes fall back to index.html, still inside the gate
// and still injected.
func TestClientSideRouteFallsBackToIndex(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab")

	rec := get(h, "/site/cryoem/jobs/12345")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "cryoem") ||
		!strings.Contains(rec.Body.String(), "__HTCONDOR_APP__") {
		t.Errorf("fallback body = %q", rec.Body.String())
	}
}

// A caller in both labs reaches both apps; each app still refuses the
// other's members.
func TestMultipleGroupsReachMultipleApps(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab", "jones_lab")

	for _, path := range []string{"/site/cryoem/", "/site/seqqc/"} {
		if rec := get(h, path); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
		}
	}
}

// Reserved paths are the server's own. An unrecognised one answers
// 404 rather than falling through to an app, and no bundle can claim
// one because ValidateID refuses an id beginning with "_".
func TestReservedPrefixIsNotAnApp(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab")
	for _, path := range []string{"/site/_switch", "/site/_nothing/here"} {
		if rec := get(h, path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
}

func TestShellScriptIsServed(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab")

	rec := get(h, "/site/_shell.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q", ct)
	}
	// It must carry no site content: it is served to every
	// authenticated caller, and does its own filtering by asking
	// auth/me.
	body := rec.Body.String()
	for _, leak := range []string{"CryoEM", "SeqQC", "smith_lab", "jones_lab"} {
		if strings.Contains(body, leak) {
			t.Errorf("the shell script carries site content: %q", leak)
		}
	}
	if !strings.Contains(body, "/api/v1/auth/me") {
		t.Error("the shell does not ask auth/me, so it cannot be filtering anything")
	}
	if v := rec.Header().Get("Cache-Control"); !strings.Contains(v, "private") {
		t.Errorf("Cache-Control = %q, want private", v)
	}
}

// A subresource must not be answered with a redirect to a login page:
// the browser would parse HTML as JavaScript.
func TestShellScriptWithoutASessionIsNotARedirect(t *testing.T) {
	h := testHandler(t, twoAppDir(t), false)

	rec := get(h, "/site/_shell.js")
	if rec.Code == http.StatusFound || rec.Code == http.StatusMovedPermanently {
		t.Fatalf("status %d: a script request was answered with a redirect", rec.Code)
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("status %d, want 204", rec.Code)
	}
}

// Every page carries the overlay tag, so a user is never stranded in
// an app with no way across or out.
func TestPagesCarryTheShellTag(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab")

	for _, path := range []string{"/site/cryoem/", "/site/cryoem/some/client/route"} {
		body := get(h, path).Body.String()
		if !strings.Contains(body, `src="/site/_shell.js"`) {
			t.Errorf("GET %s has no shell tag: %s", path, body)
		}
		if !strings.Contains(body, "defer") {
			t.Errorf("GET %s loads the shell without defer", path)
		}
	}
}

// A path that escapes the mount point must not reach another app or
// the filesystem.
func TestPathEscapesAreRefused(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab")

	for _, path := range []string{
		"/site/cryoem/../seqqc/index.html",
		"/site/cryoem/..%2f..%2fetc%2fpasswd",
	} {
		rec := get(h, path)
		if body := rec.Body.String(); strings.Contains(body, "root:") || strings.Contains(body, "SeqQC") {
			t.Errorf("GET %s escaped: %s", path, body)
		}
	}
}

// The switcher is what resolves the multiple-homes case and what a PI
// can paste into a lab wiki: the same URL sends each person to their
// own set.
func TestSwitcherListsOnlyTheCallersApps(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab")

	rec := get(h, "/site/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "CryoEM Pipeline") {
		t.Errorf("the caller's own app is missing: %s", body)
	}
	// Listing an app the caller cannot open would leak which apps
	// exist, which is the same thing the 404-not-403 rule protects.
	if strings.Contains(body, "SeqQC") {
		t.Error("the switcher lists an app the caller cannot open")
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q", cc)
	}
}

// Somebody in two labs sees both, which is the state the switcher
// exists for.
func TestSwitcherShowsEveryVisibleApp(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab", "jones_lab")

	body := get(h, "/site/").Body.String()
	for _, want := range []string{"CryoEM Pipeline", "SeqQC"} {
		if !strings.Contains(body, want) {
			t.Errorf("%q missing from the switcher: %s", want, body)
		}
	}
}

// A caller with no apps gets a page that says so and offers a way
// onward, not a 404 and not a blank list.
func TestSwitcherWithNoAppsStillOffersAWayOnward(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "nobody")

	rec := get(h, "/site/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want a readable page", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "CryoEM") || strings.Contains(body, "SeqQC") {
		t.Error("an app leaked to a caller in neither group")
	}
	if !strings.Contains(body, `href="/"`) {
		t.Errorf("no link back to the console: %s", body)
	}
}

func TestSwitcherRequiresASession(t *testing.T) {
	h := testHandler(t, twoAppDir(t), false)

	rec := get(h, "/site/")
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want a login redirect", rec.Code)
	}
}

// App names come from manifests an operator deployed: trusted input,
// not safe input. A name carrying markup must not become markup.
func TestSwitcherEscapesAppNames(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "evil", "name: \"<script>alert(1)</script>\"\n", defaultFiles())
	writePolicy(t, dir, "evil", "groups: [\"*\"]\n")
	h := testHandler(t, dir, true, "anyone")

	body := get(h, "/site/").Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("an app name was rendered as markup: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the name was not escaped into the page at all: %s", body)
	}
}
