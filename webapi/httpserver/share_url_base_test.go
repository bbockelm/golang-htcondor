package httpserver

import (
	"context"
	"net/http/httptest"
	"testing"
)

// TestShareURLBasePrefersRequestHostOverGuess is the regression. A share
// link generated on a pod came back as
//
//	http://htcondor-api-6f9c86677f-sg8cj:8080/api/v1/share/output?t=...
//
// which is the pod's own name and resolves nowhere outside the cluster,
// so the link could not be opened by the person it was generated for.
//
// The cause was not missing configuration. When HTTP_API_BASE_URL is
// unset the server GUESSES a base URL from FULL_HOSTNAME and the listen
// port, and shareURLBase preferred that guess over the Host the caller
// actually reached the server at -- the one value that is right by
// construction.
func TestShareURLBasePrefersRequestHostOverGuess(t *testing.T) {
	h := &Handler{
		// What loadHTTPBaseURL derives inside a pod.
		httpBaseURL:         "http://htcondor-api-6f9c86677f-sg8cj:8080",
		httpBaseURLExplicit: false,
	}

	r := httptest.NewRequestWithContext(context.Background(), "POST", "/api/v1/jobs/1.0/output/share", nil)
	r.Host = "ap40-api.osgdev.chtc.io"
	r.Header.Set("X-Forwarded-Proto", "https")

	got := h.shareURLBase(r)
	if want := "https://ap40-api.osgdev.chtc.io"; got != want {
		t.Errorf("shareURLBase() = %q, want %q", got, want)
	}
}

// TestShareURLBaseHonorsExplicitConfig keeps the other half: an operator
// who sets HTTP_API_BASE_URL means it, and it must win even when the
// caller arrives by a different name.
func TestShareURLBaseHonorsExplicitConfig(t *testing.T) {
	h := &Handler{
		httpBaseURL:         "https://canonical.example.org",
		httpBaseURLExplicit: true,
	}

	r := httptest.NewRequestWithContext(context.Background(), "POST", "/x", nil)
	r.Host = "some-other-name.internal:8080"

	if got, want := h.shareURLBase(r), "https://canonical.example.org"; got != want {
		t.Errorf("shareURLBase() = %q, want %q", got, want)
	}
}

// TestShareURLBaseUsesForwardedHost covers the proxied path, which is how
// the deployment actually receives requests.
func TestShareURLBaseUsesForwardedHost(t *testing.T) {
	h := &Handler{httpBaseURL: "http://pod-name:8080"}

	r := httptest.NewRequestWithContext(context.Background(), "POST", "/x", nil)
	r.Host = "pod-name:8080"
	r.Header.Set("X-Forwarded-Host", "ap40-api.osgdev.chtc.io")
	r.Header.Set("X-Forwarded-Proto", "https")

	if got, want := h.shareURLBase(r), "https://ap40-api.osgdev.chtc.io"; got != want {
		t.Errorf("shareURLBase() = %q, want %q", got, want)
	}
}

// TestShareURLBaseFallsBackWhenHostMissing checks the degenerate case
// still produces a syntactically usable URL rather than one with an
// empty authority.
func TestShareURLBaseFallsBackWhenHostMissing(t *testing.T) {
	h := &Handler{httpBaseURL: "http://derived:8080"}

	r := httptest.NewRequestWithContext(context.Background(), "POST", "/x", nil)
	r.Host = ""

	if got, want := h.shareURLBase(r), "http://derived:8080"; got != want {
		t.Errorf("shareURLBase() = %q, want %q", got, want)
	}
}
