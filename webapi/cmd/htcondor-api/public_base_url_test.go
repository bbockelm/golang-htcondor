package main

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// TestPublicBaseURLDoesNotGuess is the regression at its source. A share
// link generated on a pod came back as
//
//	http://htcondor-api-6f9c86677f-sg8cj:8080/api/v1/share/output?t=...
//
// because loadHTTPBaseURL falls back to FULL_HOSTNAME plus the listen
// port, and that value was handed to everything that builds a URL for a
// client. Inside a container FULL_HOSTNAME is the pod name.
//
// Six consumers were affected: share links, MCP download links, the RFC
// 9728 resource_metadata hint, the Jupyter tunnel WebSocket URL, the
// origin Jupyter is told to accept, and the CORS echo check. Each guards
// on the value being non-empty and falls back to the requesting client's
// Host, so returning "" is what lets all six do the right thing.
func TestPublicBaseURLDoesNotGuess(t *testing.T) {
	cfg := config.NewEmpty()
	// The value that produced the bug: a pod name the server can resolve
	// for itself and nobody else can.
	cfg.Set("FULL_HOSTNAME", "htcondor-api-6f9c86677f-sg8cj")

	if got := publicBaseURL(cfg); got != "" {
		t.Errorf("publicBaseURL() = %q with no HTTP_API_BASE_URL set; must be empty so callers fall back to the request Host", got)
	}

	// loadHTTPBaseURL still derives, deliberately: the OAuth2 issuer and
	// the demo-mode IDP URLs need a non-empty value. Pinning that here
	// records that the two are different on purpose.
	if got := loadHTTPBaseURL(cfg, ":8080", false); got == "" {
		t.Error("loadHTTPBaseURL() is empty; the issuer path needs a derived value")
	}
}

// TestPublicBaseURLHonorsConfig keeps the other half.
func TestPublicBaseURLHonorsConfig(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("FULL_HOSTNAME", "htcondor-api-6f9c86677f-sg8cj")
	cfg.Set("HTTP_API_BASE_URL", "https://ap40-api.osgdev.chtc.io/")

	// Trailing slash trimmed so callers can append a path safely.
	if got, want := publicBaseURL(cfg), "https://ap40-api.osgdev.chtc.io"; got != want {
		t.Errorf("publicBaseURL() = %q, want %q", got, want)
	}
}
