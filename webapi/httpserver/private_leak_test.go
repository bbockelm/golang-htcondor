package httpserver

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestWatchSSERedactsPrivate is the mirror/SSE leak regression guard: a job ad
// carrying a private (secret) attribute -- a running job stores its ClaimId, and
// job streams may be intermixed with slot ads bearing Capability -- must never
// appear in the server-sent-events frame delivered to a client.
func TestWatchSSERedactsPrivate(t *testing.T) {
	ad, err := classad.Parse(`[ ClusterId=1; ProcId=0; Owner="alice"; JobStatus=2; ClaimId="SECRET-CLAIM-XYZ"; Capability="SECRET-CAP-XYZ" ]`)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder() // implements http.Flusher
	if err := writeWatchSSE(rec, rec, "upsert", "1.0", ad, []byte("cursor-1"), ""); err != nil {
		t.Fatalf("writeWatchSSE: %v", err)
	}
	body := rec.Body.String()

	for _, secret := range []string{"ClaimId", "SECRET-CLAIM-XYZ", "Capability", "SECRET-CAP-XYZ"} {
		if strings.Contains(body, secret) {
			t.Errorf("SSE frame leaked %q:\n%s", secret, body)
		}
	}
	// Sanity: public attributes are still delivered.
	if !strings.Contains(body, "Owner") || !strings.Contains(body, "alice") {
		t.Errorf("SSE frame dropped public attributes:\n%s", body)
	}
}

// TestJobAdJSONRedactsPrivate guards the HTTP/JSON endpoints (GET /api/v1/jobs,
// /collector/ads, history): json.Marshal of a job ad must not carry secrets,
// since every such endpoint marshals the ad directly.
func TestJobAdJSONRedactsPrivate(t *testing.T) {
	ad, err := classad.Parse(`[ ClusterId=1; Owner="bob"; ClaimId="SECRET-123"; _condor_priv_note="SECRET-456" ]`)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(ad)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"ClaimId", "SECRET-123", "_condor_priv_note", "SECRET-456"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("job ad JSON leaked %q: %s", secret, b)
		}
	}
	if !strings.Contains(string(b), "bob") {
		t.Errorf("job ad JSON dropped public attribute: %s", b)
	}
}
