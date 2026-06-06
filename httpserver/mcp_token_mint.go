package httpserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// nbfClockSkewLeeway backdates the `nbf` (not-before) claim on minted
// IDTOKENs. The schedd rejects a token whose nbf is in its future, and
// we've observed even ~1s of clock skew between this server and the
// schedd cause spurious rejections; backdating by a few seconds
// absorbs that skew without meaningfully widening the token's validity.
const nbfClockSkewLeeway = 10 * time.Second

// generateMCPAccessJWT mints an HTCondor-compatible JWT identical in
// shape to cedar's security.GenerateJWT output, PLUS a backdated `nbf`
// claim (see nbfClockSkewLeeway). We replicate cedar's logic locally
// (rather than calling its GenerateJWT) for one reason: cedar's API
// doesn't let us set nbf / arbitrary claims. When that's fixed
// upstream this function should collapse to a thin wrapper.
//
// The signing path is BYTE-IDENTICAL to cedar's:
//
//  1. Read scrambled key from keyDir/keyID
//  2. XOR-unscramble with 0xdeadbeef
//  3. If keyID == "POOL", duplicate the key bytes (an HTCondor
//     quirk required for HKDF input)
//  4. Derive a 32-byte HMAC key via HKDF(input, "htcondor",
//     "master jwt")
//  5. HS256(header || "." || payload, derived_key)
//
// Any deviation here would produce a token the schedd refuses to
// verify; this function is tested against cedar's reference output
// in TestGenerateMCPAccessJWTMatchesCedarShape.
func generateMCPAccessJWT(
	keyDir, keyID, subject, issuer string,
	issuedAt, expiration int64,
	authzLimits []string,
) (string, error) {
	// Read and unscramble the signing key — same on-disk format as
	// HTCondor's passwords.d/ entries.
	keyPath := filepath.Join(keyDir, keyID)
	scrambled, err := os.ReadFile(keyPath) //nolint:gosec // operator-controlled path
	if err != nil {
		return "", fmt.Errorf("read signing key %s: %w", keyPath, err)
	}
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	signingKey := make([]byte, len(scrambled))
	for i := range scrambled {
		signingKey[i] = scrambled[i] ^ deadbeef[i%len(deadbeef)]
	}

	// POOL key duplication: HTCondor's POOL key derivation requires
	// the input to be doubled before HKDF. See cedar/security for
	// the original implementation.
	hkdfInputKey := signingKey
	if keyID == "POOL" {
		hkdfInputKey = make([]byte, len(signingKey)*2)
		copy(hkdfInputKey, signingKey)
		copy(hkdfInputKey[len(signingKey):], signingKey)
	}

	// Random jti (16 bytes hex) — same as cedar.
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	jti := hex.EncodeToString(jtiBytes)

	// JWT header — alg/typ/kid. Schedd reads kid to find the
	// matching key in its passwords.d/.
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
		"kid": keyID,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Payload. Standard HTCondor IDTOKEN claims. `nbf` is backdated by
	// nbfClockSkewLeeway so the schedd doesn't reject the token over
	// small clock differences. Key insertion order doesn't matter —
	// JSON objects are unordered — but we use a map literal for clarity.
	payload := map[string]any{
		"sub": subject,
		"jti": jti,
		"iat": issuedAt,
		"nbf": issuedAt - int64(nbfClockSkewLeeway.Seconds()),
		"exp": expiration,
	}
	if issuer != "" {
		payload["iss"] = issuer
	}
	if len(authzLimits) > 0 {
		scopes := make([]string, len(authzLimits))
		for i, limit := range authzLimits {
			scopes[i] = "condor:/" + limit
		}
		payload["scope"] = strings.Join(scopes, " ")
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Derive the HMAC key the same way cedar's GenerateJWT (and,
	// crucially, the schedd's verifier) does it. Deviating from
	// these constants — info / salt / output length — would
	// produce a signature the schedd rejects.
	signData := headerB64 + "." + payloadB64
	const keyStrengthBytes = 32
	jwtKey := make([]byte, keyStrengthBytes)
	hkdfReader := hkdf.New(sha256.New, hkdfInputKey, []byte("htcondor"), []byte("master jwt"))
	if _, err := io.ReadFull(hkdfReader, jwtKey); err != nil {
		return "", fmt.Errorf("derive JWT key: %w", err)
	}

	mac := hmac.New(sha256.New, jwtKey)
	mac.Write([]byte(signData))
	signature := mac.Sum(nil)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signData + "." + signatureB64, nil
}
