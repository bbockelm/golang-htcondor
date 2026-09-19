package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
)

// shareTestHandler builds the smallest Handler that can answer the share
// endpoints' guard clauses: a signer and a signing key path, no schedd.
// Every case here is refused before anything would query one.
func shareTestHandler(t *testing.T) *Handler {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "POOL")
	if err := os.WriteFile(keyPath, []byte("test pool signing key"), 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	key, err := shareurl.KeyFromSigningKeyFile(keyPath)
	if err != nil {
		t.Fatalf("derive share key: %v", err)
	}
	signer, err := shareurl.NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return &Handler{
		logger:         testLogger(t),
		shareSigner:    signer,
		signingKeyPath: keyPath,
		uidDomain:      "example.org",
		trustDomain:    "example.org",
	}
}

func mintToken(t *testing.T, h *Handler, kind shareurl.Kind, exp time.Time) string {
	t.Helper()
	tok, err := h.signShareToken(shareurl.Payload{
		Cluster: 42, Proc: 0, Owner: "alice", Exp: exp.Unix(), Kind: kind,
	})
	if err != nil {
		t.Fatalf("signShareToken: %v", err)
	}
	return tok
}

// The kinds must not be interchangeable at the HTTP layer: a download
// URL that could be redeemed as an upload would let anyone holding it
// write into the job instead of only reading from it.
func TestSharedInputRejectsAnOutputToken(t *testing.T) {
	h := shareTestHandler(t)
	tok := mintToken(t, h, shareurl.KindOutput, time.Now().Add(time.Hour))

	w := httptest.NewRecorder()
	h.handleSharedInput(w, httptest.NewRequest(http.MethodPut, "/api/v1/share/input?t="+tok, strings.NewReader("x")))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an output token was accepted for upload: status %d, body %s", w.Code, w.Body.String())
	}
	// The refusal must not say which check failed.
	if body := w.Body.String(); strings.Contains(strings.ToLower(body), "kind") ||
		strings.Contains(strings.ToLower(body), "output") {
		t.Fatalf("the refusal leaks why it failed: %s", body)
	}
}

func TestSharedInputRejectsAnExpiredToken(t *testing.T) {
	h := shareTestHandler(t)
	tok := mintToken(t, h, shareurl.KindInput, time.Now().Add(-time.Minute))

	w := httptest.NewRecorder()
	h.handleSharedInput(w, httptest.NewRequest(http.MethodPut, "/api/v1/share/input?t="+tok, strings.NewReader("x")))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an expired token was accepted: status %d", w.Code)
	}
}

func TestSharedInputRejectsATamperedToken(t *testing.T) {
	h := shareTestHandler(t)
	tok := []byte(mintToken(t, h, shareurl.KindInput, time.Now().Add(time.Hour)))
	tok[0] ^= 0x01

	w := httptest.NewRecorder()
	h.handleSharedInput(w, httptest.NewRequest(http.MethodPut, "/api/v1/share/input?t="+string(tok), strings.NewReader("x")))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a tampered token was accepted: status %d", w.Code)
	}
}

func TestSharedInputRequiresAToken(t *testing.T) {
	h := shareTestHandler(t)
	w := httptest.NewRecorder()
	h.handleSharedInput(w, httptest.NewRequest(http.MethodPut, "/api/v1/share/input", strings.NewReader("x")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a tokenless upload got status %d, want 400", w.Code)
	}
}

func TestSharedInputRejectsAGet(t *testing.T) {
	h := shareTestHandler(t)
	tok := mintToken(t, h, shareurl.KindInput, time.Now().Add(time.Hour))
	w := httptest.NewRecorder()
	h.handleSharedInput(w, httptest.NewRequest(http.MethodGet, "/api/v1/share/input?t="+tok, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on the upload endpoint got status %d, want 405", w.Code)
	}
}

// Without a signing key the redeem path cannot mint the owner's JWT, so
// both ends must refuse rather than hand out a URL nobody can use.
func TestShareEndpointsRefuseWithoutASigningKey(t *testing.T) {
	h := shareTestHandler(t)
	tok := mintToken(t, h, shareurl.KindInput, time.Now().Add(time.Hour))
	h.signingKeyPath = ""

	w := httptest.NewRecorder()
	h.handleSharedInput(w, httptest.NewRequest(http.MethodPut, "/api/v1/share/input?t="+tok, strings.NewReader("x")))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("redeem without a signing key got status %d, want 501", w.Code)
	}

	w = httptest.NewRecorder()
	h.handleJobInputShare(w, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/42.0/input/share", nil), "42.0")
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("mint without a signing key got status %d, want 501", w.Code)
	}
}

func TestJobInputShareRejectsAGet(t *testing.T) {
	h := shareTestHandler(t)
	w := httptest.NewRecorder()
	h.handleJobInputShare(w, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/42.0/input/share", nil), "42.0")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on the mint endpoint got status %d, want 405", w.Code)
	}
}

// The TTL knob is policy, and the upload window is deliberately wider
// than the download one; an over-long request is clamped, not refused.
func TestRequestedTTLIsOptionalAndClamped(t *testing.T) {
	body := strings.NewReader(`{"ttl_seconds": 999999}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/42.0/input/share", body)
	if got := shareurl.ClampTTL(shareurl.KindInput, requestedTTL(r)); got != shareurl.MaxInputTTL {
		t.Fatalf("clamped TTL = %v, want %v", got, shareurl.MaxInputTTL)
	}

	// No body at all is the common case and must not be an error.
	r = httptest.NewRequest(http.MethodPost, "/api/v1/jobs/42.0/input/share", nil)
	if got := shareurl.ClampTTL(shareurl.KindInput, requestedTTL(r)); got != shareurl.DefaultInputTTL {
		t.Fatalf("default TTL = %v, want %v", got, shareurl.DefaultInputTTL)
	}

	// Garbage in the optional knob falls back to the default rather than
	// failing a request that is otherwise fine.
	r = httptest.NewRequest(http.MethodPost, "/api/v1/jobs/42.0/input/share", strings.NewReader("{not json"))
	if got := shareurl.ClampTTL(shareurl.KindInput, requestedTTL(r)); got != shareurl.DefaultInputTTL {
		t.Fatalf("TTL from a malformed body = %v, want the default %v", got, shareurl.DefaultInputTTL)
	}
}

// The upload URL must be redeemable at the path it names, and carry a
// token this server accepts. Guards against a future edit changing one
// side of the pair.
func TestMintedURLPointsAtTheRedeemEndpoint(t *testing.T) {
	h := shareTestHandler(t)
	h.httpBaseURL = "https://ap.example.org"
	exp := time.Now().Add(time.Hour)
	tok := mintToken(t, h, shareurl.KindInput, exp)
	url := "https://ap.example.org/api/v1/share/input?t=" + tok

	const prefix = "https://ap.example.org/api/v1/share/input?t="
	if !strings.HasPrefix(url, prefix) {
		t.Fatalf("URL %q does not point at the redeem endpoint", url)
	}
	got, err := h.verifyShareToken(strings.TrimPrefix(url, prefix), shareurl.KindInput)
	if err != nil {
		t.Fatalf("this server could not verify its own URL: %v", err)
	}
	if got.Cluster != 42 || got.Proc != 0 || got.Owner != "alice" {
		t.Fatalf("token round-tripped to %+v", *got)
	}
}

// The response shape is what a caller codes against. expected_files is
// per-proc, because the allow-set is: two procs of one cluster can list
// different inputs, and a single shared list would be wrong for one of
// them.
func TestShareInputResponseCarriesPerProcExpectedFiles(t *testing.T) {
	raw, err := json.Marshal(ShareInputResponse{
		ClusterID: 42, Owner: "alice", Count: 2,
		Uploads: []ShareInputUpload{
			{JobID: "42.0", URL: "https://x/api/v1/share/input?t=a", ExpectedFiles: []string{"run.sh", "a.csv"}},
			{JobID: "42.1", URL: "https://x/api/v1/share/input?t=b", ExpectedFiles: []string{"run.sh", "b.csv"}},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back struct {
		Count   int `json:"count"`
		Uploads []struct {
			JobID         string   `json:"job_id"`
			URL           string   `json:"url"`
			ExpectedFiles []string `json:"expected_files"`
		} `json:"uploads"`
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Count != 2 || len(back.Uploads) != 2 {
		t.Fatalf("the upload list did not survive the round trip: %s", raw)
	}
	if back.Uploads[0].ExpectedFiles[1] == back.Uploads[1].ExpectedFiles[1] {
		t.Fatalf("the two procs' allow-sets were collapsed: %s", raw)
	}
	for i, u := range back.Uploads {
		if u.JobID == "" || u.URL == "" {
			t.Fatalf("upload %d lost its identity: %s", i, raw)
		}
	}
}
