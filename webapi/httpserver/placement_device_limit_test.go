package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// deviceCodeRequest sends one request to a legacy device-code endpoint from
// the client address addr.
func (h *deviceHarness) deviceCodeRequest(t *testing.T, c *http.Cookie, method, target, addr string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	if method != http.MethodGet {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	req.RemoteAddr = addr
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// Each lookup of a user code is a guess at one, so the legacy lookup spends
// the same per-session budget as the device verification page: once it is
// spent, further lookups are refused, from any address, and so are denials.
func TestPlacementDeviceLookupIsRateLimited(t *testing.T) {
	h := newDeviceHarness(t)
	_, uc := h.issue(t)
	c := h.placementCookie(t, aliceIdentity)
	lookup := "/api/v1/placement/me/device/" + uc

	for i := range sshConsentBurst {
		addr := fmt.Sprintf("192.0.2.%d:1234", i+1)
		if code := h.deviceCodeRequest(t, c, http.MethodGet, lookup, addr); code != http.StatusOK {
			t.Fatalf("lookup %d = %d, want 200", i+1, code)
		}
	}
	if code := h.deviceCodeRequest(t, c, http.MethodGet, lookup, "198.51.100.1:1234"); code != http.StatusTooManyRequests {
		t.Errorf("lookup %d = %d, want 429", sshConsentBurst+1, code)
	}
	if code := h.deviceCodeRequest(t, c, http.MethodPost, lookup+"/deny", "198.51.100.2:1234"); code != http.StatusTooManyRequests {
		t.Errorf("deny after the budget is spent = %d, want 429", code)
	}
}

// Denying names a code too, so guessing through deny spends the budget.
func TestPlacementDeviceDenyIsRateLimited(t *testing.T) {
	h := newDeviceHarness(t)
	c := h.placementCookie(t, aliceIdentity)
	deny := "/api/v1/placement/me/device/BCDF-GHJK/deny"

	for i := range sshConsentBurst {
		addr := fmt.Sprintf("192.0.2.%d:1234", i+1)
		if code := h.deviceCodeRequest(t, c, http.MethodPost, deny, addr); code != http.StatusNotFound {
			t.Fatalf("deny %d = %d, want 404", i+1, code)
		}
	}
	if code := h.deviceCodeRequest(t, c, http.MethodPost, deny, "198.51.100.1:1234"); code != http.StatusTooManyRequests {
		t.Errorf("deny %d = %d, want 429", sshConsentBurst+1, code)
	}
}
