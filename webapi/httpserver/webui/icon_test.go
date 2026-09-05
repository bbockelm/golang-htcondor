package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestIconIsServed covers the whole chain: Next emits app/icon.svg into the
// static export, the export is copied into dist, and the SPA handler serves
// it as a file rather than falling through to index.html — which is what a
// browser asking for /icon.svg would otherwise silently receive.
func TestIconIsServed(t *testing.T) {
	if !IsEmbedded() {
		t.Skip("frontend not embedded in this build")
	}
	h := NewSPAHandler()
	req := httptest.NewRequest(http.MethodGet, "/icon.svg", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /icon.svg = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "<!DOCTYPE html>") {
		t.Fatalf("/icon.svg fell through to index.html instead of serving the icon")
	}
	if !strings.Contains(body, "svg") || !strings.Contains(body, "ce1f44") {
		t.Errorf("served body is not the HTCondor mark: %.120s", body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "svg") {
		t.Errorf("Content-Type = %q, want an SVG type", ct)
	}
}
