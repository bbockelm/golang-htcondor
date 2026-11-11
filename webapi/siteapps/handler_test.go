package siteapps

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		http.Redirect(w, r, "/login?return_to="+r.URL.Path, http.StatusFound)
	}
	return NewHandler(lib, identify, login)
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
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

	real := get(h, "/site/cryoem/")
	fake := get(h, "/site/doesnotexist/")
	if real.Code != fake.Code {
		t.Errorf("an existing app answers %d and a missing one %d; the difference says which exist",
			real.Code, fake.Code)
	}
	if real.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", real.Code)
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
	raw = raw[:strings.Index(raw, ";</script>")]

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

// Reserved ids answer 404 rather than falling through to an app.
func TestReservedPrefixIsNotAnApp(t *testing.T) {
	h := testHandler(t, twoAppDir(t), true, "smith_lab")
	for _, path := range []string{"/site/_shell.js", "/site/_switch"} {
		if rec := get(h, path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
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
