//go:build embed_frontend

package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEmbedded_BrandingIsInjected covers the chain the unit tests cannot:
// Next's real exported markup, the embed, and the SPA handler splicing a
// site's branding into it. The injection is a few assumptions about that
// markup -- that there is a <title>, an icon <link> and a </head> -- and
// only the real export can say whether they still hold.
func TestEmbedded_BrandingIsInjected(t *testing.T) {
	b, err := Build(Options{
		SiteName:    "UChicago ATLAS Analysis Facility",
		FooterLogos: `[{"src":"/branding/af.svg","alt":"ATLAS AF"}]`,
		Favicon:     "/branding/af.svg",
		CustomCSS:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	b.Rev = 3
	h := NewSPAHandler(WithBranding(func() Branding { return b }))

	for _, path := range []string{"/", "/jobs", "/jobs/12.0"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "<title>UChicago ATLAS Analysis Facility</title>") {
			t.Errorf("GET %s: the exported title was not replaced", path)
		}
		if !strings.Contains(body, `window.__HTCONDOR_BRANDING__={"site_name":"UChicago ATLAS Analysis Facility"`) {
			t.Errorf("GET %s: the page does not carry the branding", path)
		}
		if n := strings.Count(body, `rel="icon"`); n != 1 || !strings.Contains(body, `<link rel="icon" href="/branding/af.svg"/>`) {
			t.Errorf("GET %s: icon links = %d", path, n)
		}
		if !strings.Contains(body, `<link rel="stylesheet" href="/branding.css?rev=3"/></head>`) {
			t.Errorf("GET %s: the site stylesheet is not last in the head", path)
		}
	}

	// A page served to an unconfigured deployment is the export, byte
	// for byte.
	plain := NewSPAHandler(WithBranding(DefaultBranding))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	plain.ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "__HTCONDOR_BRANDING__") {
		t.Error("an unconfigured deployment's pages carry an injected global")
	}
	if !strings.Contains(w.Body.String(), "<title>HTCondor Access Point</title>") {
		t.Error("the shipped title is gone")
	}

	// Assets are not pages: nothing is spliced into the JavaScript.
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/icon.svg", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "__HTCONDOR_BRANDING__") {
		t.Errorf("GET /icon.svg = %d, branded = %v", w.Code, strings.Contains(w.Body.String(), "__HTCONDOR_BRANDING__"))
	}
}
