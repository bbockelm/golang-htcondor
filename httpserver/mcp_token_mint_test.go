package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	"golang.org/x/crypto/hkdf"
)

// htcondorSignatureValid is a deliberately INDEPENDENT reimplementation
// of HTCondor's IDTOKEN signing path (the one the schedd verifies
// against): unscramble the on-disk key, double it for the POOL key, run
// HKDF, then HMAC-SHA256 over header.payload. Because it re-derives the
// constants itself rather than calling generateMCPAccessJWT, a drift in
// either the minter's HKDF parameters or its POOL-doubling rule makes
// this return false.
func htcondorSignatureValid(t *testing.T, keyDir, keyID, token string) bool {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a 3-part JWT (%d parts)", len(parts))
	}
	scrambled, err := os.ReadFile(filepath.Join(keyDir, keyID)) //nolint:gosec // test key path under t.TempDir()
	if err != nil {
		t.Fatalf("read key %s/%s: %v", keyDir, keyID, err)
	}
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	key := make([]byte, len(scrambled))
	for i := range scrambled {
		key[i] = scrambled[i] ^ deadbeef[i%len(deadbeef)]
	}
	hkdfInput := key
	if keyID == "POOL" {
		hkdfInput = append(append([]byte{}, key...), key...)
	}
	derived := make([]byte, 32)
	if _, err := io.ReadFull(
		hkdf.New(sha256.New, hkdfInput, []byte("htcondor"), []byte("master jwt")),
		derived,
	); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	mac := hmac.New(sha256.New, derived)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(parts[2]))
}

// TestGenerateMCPAccessJWTMatchesCedarShape pins that our local minter
// produces tokens signed identically to cedar's security.GenerateJWT —
// the library the schedd uses to verify IDTOKENs. We can't byte-compare
// the two tokens (random jti, our extra nbf claim), so instead we prove
// both are signed by the same HTCondor key derivation: an independent
// verifier must accept BOTH. The integration suite proves the schedd
// accepts our tokens end to end; this is the fast unit-level guard that
// pinpoints signing drift without spinning up a daemon.
func TestGenerateMCPAccessJWTMatchesCedarShape(t *testing.T) {
	keyDir := t.TempDir()
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i*7 + 1)
	}
	if err := writeKey(filepath.Join(keyDir, "POOL"), keyBytes); err != nil {
		t.Fatalf("writeKey: %v", err)
	}

	const sub = "alice@example.com"
	iat := time.Now().Unix()
	exp := iat + 300

	ours, err := generateMCPAccessJWT(keyDir, "POOL", sub, testTrustDomain, iat, exp, []string{"READ", "WRITE"})
	if err != nil {
		t.Fatalf("generateMCPAccessJWT: %v", err)
	}
	ref, err := security.GenerateJWT(keyDir, "POOL", sub, testTrustDomain, iat, exp, []string{"READ", "WRITE"})
	if err != nil {
		t.Fatalf("security.GenerateJWT: %v", err)
	}

	// Sanity check: the independent verifier must accept cedar's OWN
	// token. If it doesn't, the verifier is wrong and the assertion
	// below would be meaningless.
	if !htcondorSignatureValid(t, keyDir, "POOL", ref) {
		t.Fatal("independent verifier rejected cedar's reference token; the verifier is wrong")
	}
	// The real assertion: our minted token verifies under the identical
	// HTCondor key derivation, so the schedd will accept its signature.
	if !htcondorSignatureValid(t, keyDir, "POOL", ours) {
		t.Error("minted token signature does not verify under HTCondor key derivation; minter has drifted from cedar")
	}
}
