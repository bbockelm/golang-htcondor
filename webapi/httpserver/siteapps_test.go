package httpserver

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// siteAppBundle writes a minimal bundle and its policy file.
func siteAppBundle(t *testing.T, dir, id, name, groups string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for entry, body := range map[string]string{
		"app.yaml":          "name: " + name + "\n",
		"web/index.html":    "<html><head></head><body>" + id + " page</body></html>",
		"web/assets/app.js": "// " + id + " private bundle code",
	} {
		w, err := zw.Create(entry)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".zip"), buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte("groups: ["+groups+"]\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
}

func siteAppServer(t *testing.T, dir string) *Handler {
	t.Helper()
	h, err := NewHandler(HandlerConfig{
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		Logger:       testLogger(t),
		OAuth2DBPath: t.TempDir() + "/sessions.db",
		SiteAppsDir:  dir,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	t.Cleanup(func() {
		if h.mcpServer != nil {
			h.mcpServer.Close()
		}
		if h.siteApps != nil {
			_ = h.siteApps.Close()
		}
	})
	h.setupRoutes()
	return h
}

// The route must exist, and must sit above the SPA catch-all: without
// that, /site/cryoem/ returns the stock UI's index.html with a 200 and
// the app looks broken in a way nothing explains.
func TestSiteAppRouteIsRegisteredAndGated(t *testing.T) {
	dir := t.TempDir()
	siteAppBundle(t, dir, "cryoem", "CryoEM Pipeline", "smith_lab")
	h := siteAppServer(t, dir)

	if h.siteApps == nil {
		t.Fatal("the library was not built from SiteAppsDir")
	}
	if _, ok := h.siteApps.Get("cryoem"); !ok {
		t.Fatal("the bundle was not published")
	}

	// No session: the gate must send the browser to log in rather than
	// let the SPA catch-all answer with the stock UI.
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/site/cryoem/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want a redirect to login; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Errorf("Location = %q", loc)
	}
	// And nothing of the bundle leaked on the way.
	if strings.Contains(rec.Body.String(), "private bundle code") {
		t.Error("bundle content was served without a session")
	}
}

// A nested asset must take the same path as the page. This is the one
// that catches a gate wired up on the HTML only.
func TestSiteAppAssetsAreGatedToo(t *testing.T) {
	dir := t.TempDir()
	siteAppBundle(t, dir, "cryoem", "CryoEM Pipeline", "smith_lab")
	h := siteAppServer(t, dir)

	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/site/cryoem/assets/app.js", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("an asset was served without a session: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "private bundle code") {
		t.Error("asset content leaked")
	}
}

// With no directory configured the feature is absent entirely: no
// library, and /site/ falls through to whatever else answers it.
func TestSiteAppsAbsentWhenUnconfigured(t *testing.T) {
	h := siteAppServer(t, "")
	if h.siteApps != nil {
		t.Error("a library was built with no directory configured")
	}
}

// auth/me is the single source of truth for app visibility in the UI.
// It must filter by group, not merely list what is published.
func TestSiteAppsForFiltersByGroup(t *testing.T) {
	dir := t.TempDir()
	siteAppBundle(t, dir, "cryoem", "CryoEM Pipeline", "smith_lab")
	siteAppBundle(t, dir, "seqqc", "SeqQC", "jones_lab")
	siteAppBundle(t, dir, "shared", "Shared Tools", `"*"`)
	h := siteAppServer(t, dir)

	got := h.siteAppsFor([]string{"smith_lab"})
	ids := make([]string, 0, len(got))
	for _, a := range got {
		ids = append(ids, a.ID)
	}
	if len(got) != 2 {
		t.Fatalf("smith_lab sees %v, want cryoem and shared", ids)
	}
	for _, a := range got {
		if a.ID == "seqqc" {
			t.Error("smith_lab can see jones_lab's app through auth/me")
		}
		if a.URL != "/site/"+a.ID+"/" {
			t.Errorf("URL = %q for %s", a.URL, a.ID)
		}
	}
	if got[0].Name != "CryoEM Pipeline" {
		t.Errorf("Name = %q, want the manifest's", got[0].Name)
	}

	// Somebody in neither lab still sees the wildcard app, and nothing
	// else.
	if other := h.siteAppsFor([]string{"nobody"}); len(other) != 1 || other[0].ID != "shared" {
		t.Errorf("an unrelated group sees %v, want just shared", other)
	}
}

func TestSiteAppsForIsEmptyWithoutALibrary(t *testing.T) {
	h := siteAppServer(t, "")
	if got := h.siteAppsFor([]string{"anyone"}); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
