package httpserver

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func pingTestServer(t *testing.T, interval time.Duration) *Handler {
	t.Helper()
	signingKeyPath := filepath.Join(t.TempDir(), "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("writing the signing key: %v", err)
	}
	srv, err := NewServer(Config{
		ScheddName:     "test-schedd",
		ScheddAddr:     "127.0.0.1:0",
		SigningKeyPath: signingKeyPath,
		TrustDomain:    "test.htcondor.org",
		UIDDomain:      "test.htcondor.org",
		OAuth2DBPath:   filepath.Join(t.TempDir(), "sessions.db"),
		PingInterval:   interval,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv.Handler
}

// TestPingIntervalZeroDisablesPinging holds the field to the contract
// its doc comment states: "0 = disabled".
//
// It matters to a deployment that holds no local HTCondor credential —
// authentication is per-request, from a forwarded token — so the
// periodic ping has nothing to authenticate with and can never succeed.
// Left running it does nothing but fail, and /readyz reports down
// forever on a server that is answering requests perfectly well.
func TestPingIntervalZeroDisablesPinging(t *testing.T) {
	h := pingTestServer(t, 0)

	if h.pingInterval != 0 {
		t.Errorf("PingInterval 0 left an interval of %v; the ping loop starts on any positive value", h.pingInterval)
	}
	if h.pingHealth != nil {
		t.Error("PingInterval 0 still built a pingHealth tracker")
	}

	// /readyz has to stay usable with pinging off: it reports what it
	// can check rather than failing the deployment.
	snap := h.pingHealth.snapshot()
	if snap.Status == "down" || snap.Status == "unknown" {
		t.Errorf("with pinging disabled /readyz reports %q, which a load balancer treats as unhealthy", snap.Status)
	}
}

// TestPingIntervalDefaultsWhenUnspecified: an explicit positive interval
// is honored, and the shipped daemon passes one, so turning the zero
// value into "off" does not turn pinging off for it.
func TestPingIntervalHonorsExplicitValue(t *testing.T) {
	h := pingTestServer(t, 45*time.Second)

	if h.pingInterval != 45*time.Second {
		t.Errorf("pingInterval = %v, want 45s", h.pingInterval)
	}
	if h.pingHealth == nil {
		t.Fatal("an enabled ping needs its health tracker")
	}
}
