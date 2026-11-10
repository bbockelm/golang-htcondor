package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/webui"
)

// brandingServer is a started server, because the branding routes are
// registered by setupRoutes and some of them are checked in ServeHTTP.
func brandingServer(t *testing.T, apply func(*Config)) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	if apply != nil {
		apply(&cfg)
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()
	return s
}

func brandingGet(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

// An unconfigured deployment answers with the values the frontend
// already hard-codes, so nothing about its pages changes.
func TestBrandingEndpointDefaults(t *testing.T) {
	rec := brandingGet(t, brandingServer(t, nil), brandingPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", brandingPath, rec.Code, rec.Body.String())
	}
	var b webui.Branding
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	if !b.IsDefault() {
		t.Errorf("an unconfigured server reports %+v", b)
	}
	if b.FooterLogos != nil {
		t.Errorf("footer_logos = %v; null is what tells the UI to keep its own band", b.FooterLogos)
	}
}

func TestBrandingEndpointReportsTheSitesOwn(t *testing.T) {
	s := brandingServer(t, func(c *Config) {
		c.WebUISiteName = "UChicago ATLAS Analysis Facility"
		c.WebUIFooterLogos = `[{"src":"/branding/af.svg","alt":"ATLAS AF","href":"https://af.example/"}]`
	})
	rec := brandingGet(t, s, brandingPath)
	var b webui.Branding
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	if b.SiteName != "UChicago ATLAS Analysis Facility" {
		t.Errorf("site_name = %q", b.SiteName)
	}
	if len(b.FooterLogos) != 1 || b.FooterLogos[0].Alt != "ATLAS AF" {
		t.Errorf("footer_logos = %+v", b.FooterLogos)
	}
	// Whoever runs the service, the software is still named.
	if !b.SoftwareCredit {
		t.Error("a site band without the HTCondor credit line leaves the software unattributed")
	}
}

// A logo on the site's own web server is refused by the policy unless
// its origin is named there, which is a blank footer and a console
// message rather than an error anyone would connect to their config.
func TestBrandingWidensTheImagePolicy(t *testing.T) {
	plain := brandingGet(t, brandingServer(t, nil), brandingPath)
	if csp := plain.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "img-src 'self' data: blob:;") {
		t.Errorf("an unconfigured server's img-src is not the shipped one: %q", csp)
	}

	s := brandingServer(t, func(c *Config) {
		c.WebUIFooterLogos = `[{"src":"https://www.uchicago.edu/logo.svg","alt":"UChicago"},
		                       {"src":"https://www.uchicago.edu/seal.svg","alt":"Seal"},
		                       {"src":"/branding/af.svg","alt":"ATLAS AF"}]`
		c.WebUIFavicon = "https://cdn.example/af.ico"
	})
	csp := brandingGet(t, s, brandingPath).Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src 'self' data: blob: https://www.uchicago.edu https://cdn.example;") {
		t.Errorf("img-src does not name the site's image origins exactly once each: %q", csp)
	}
	// Images only: nothing else in the policy moved.
	if !strings.Contains(csp, "script-src 'self' 'unsafe-inline';") || strings.Contains(csp, "default-src 'self' https") {
		t.Errorf("the rest of the policy changed: %q", csp)
	}
}

func TestBrandingCSS(t *testing.T) {
	dir := t.TempDir()
	css := filepath.Join(dir, "site.css")
	if err := os.WriteFile(css, []byte(":root{--color-brand-600:#800000}"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Unconfigured: nothing is served, and the page is not told to ask.
	plain := brandingServer(t, nil)
	if rec := brandingGet(t, plain, webui.CSSPath); rec.Code != http.StatusNotFound {
		t.Errorf("GET %s with no stylesheet = %d", webui.CSSPath, rec.Code)
	}
	if plain.branding.current().CustomCSS {
		t.Error("an unconfigured server claims a site stylesheet")
	}

	s := brandingServer(t, func(c *Config) { c.WebUICustomCSS = css })
	rec := brandingGet(t, s, webui.CSSPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", webui.CSSPath, rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != ":root{--color-brand-600:#800000}" {
		t.Errorf("body = %q", got)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if !s.branding.current().CustomCSS {
		t.Error("the branding does not tell the page to load the stylesheet")
	}

	// A path that names nothing is reported and then ignored: the page
	// links to a stylesheet only when there is one to link to.
	missing := brandingServer(t, func(c *Config) { c.WebUICustomCSS = filepath.Join(dir, "nope.css") })
	if missing.branding.current().CustomCSS {
		t.Error("the page is told to load a stylesheet that does not exist")
	}
}

func TestBrandingAssets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "af.svg"), []byte("<svg/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "uc.png"), []byte("\x89PNG"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Same-origin with the whole UI, so what it will serve is an
	// allowlist of types that cannot run: this one is not on it.
	if err := os.WriteFile(filepath.Join(dir, "evil.html"), []byte("<script>x</script>"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Reachable only by leaving the directory.
	outside := filepath.Join(t.TempDir(), "secret.svg")
	if err := os.WriteFile(outside, []byte("<svg>secret</svg>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.svg")); err != nil {
		t.Fatal(err)
	}

	s := brandingServer(t, func(c *Config) { c.WebUIBrandingDir = dir })

	rec := brandingGet(t, s, "/branding/af.svg")
	if rec.Code != http.StatusOK || rec.Body.String() != "<svg/>" {
		t.Errorf("GET /branding/af.svg = %d %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("Content-Type = %q", ct)
	}
	if rec := brandingGet(t, s, "/branding/sub/uc.png"); rec.Code != http.StatusOK {
		t.Errorf("GET /branding/sub/uc.png = %d", rec.Code)
	}

	for _, path := range []string{
		"/branding/evil.html",
		"/branding/link.svg",
		"/branding/sub",
		"/branding/",
		"/branding/nope.svg",
	} {
		if rec := brandingGet(t, s, path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d %q, want 404", path, rec.Code, rec.Body.String())
		}
	}

	// A path that climbs out of the directory. The mux normalizes one
	// that arrives in the URL, so it is put straight on the request to
	// reach the handler the way a traversal would have to.
	for _, name := range []string{"../secret.svg", "..%2fsecret.svg", "/etc/hosts", "sub/../../secret.svg"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/branding/x.svg", nil)
		req.URL.Path = brandingAssetPrefix + name
		rec := httptest.NewRecorder()
		s.handleBrandingAsset(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET /branding/%s = %d %q, want 404", name, rec.Code, rec.Body.String())
		}
	}

	// And nothing at all is served when no directory is configured.
	if rec := brandingGet(t, brandingServer(t, nil), "/branding/af.svg"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /branding/af.svg with no directory = %d", rec.Code)
	}
}

// Branding is reloadable: an operator trying a logo out should not have
// to restart the access point's API between attempts.
func TestBrandingReconfigure(t *testing.T) {
	s := brandingServer(t, nil)
	if !s.branding.current().IsDefault() {
		t.Fatal("the test server did not start unbranded")
	}
	before := s.branding.current().Rev

	s.SetWebUISiteName("ATLAS AF")
	s.SetWebUIFooterLogos(`[{"src":"/branding/af.svg","alt":"ATLAS AF"}]`)
	b := s.branding.current()
	if b.SiteName != "ATLAS AF" || len(b.FooterLogos) != 1 {
		t.Fatalf("after the reconfigure: %+v", b)
	}
	if b.Rev == before {
		t.Error("the revision did not move, so the rendered pages would stay as they were")
	}

	// A list that does not parse keeps the band that was working.
	s.SetWebUIFooterLogos(`[{"src":"/branding/af.svg"}]`)
	if got := s.branding.current().FooterLogos; got != nil {
		t.Errorf("an unparseable list left %+v in the footer", got)
	}

	// And emptying everything puts the pages back as they shipped.
	s.SetWebUISiteName("")
	s.SetWebUIFooterLogos("")
	if !s.branding.current().IsDefault() {
		t.Errorf("after clearing: %+v", s.branding.current())
	}
}
