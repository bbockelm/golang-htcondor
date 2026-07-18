package httpserver

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ory/fosite"
)

// These tests cover the gap that let the "claude.ai keeps presenting
// an expired token, schedd 200s on a JSON-RPC error, no refresh ever
// fires" bug ship. Two things needed coverage:
//
//   1. classifyUnknownToken — the heuristic that decides whether a
//      fosite-rejected token should be forwarded to the schedd (real
//      pool IDTOKEN) or surfaced as a 401 (our own expired token, or
//      something we don't recognize). The OLD heuristic was "JWT-
//      shaped → forward", which mismapped every OAuth2 access token
//      we issue. The NEW heuristic compares the `iss` claim.
//
//   2. The WWW-Authenticate header on 401 must include the RFC 9728
//      `resource_metadata` parameter when httpBaseURL is set, so
//      MCP-spec clients can discover the authorization server and
//      kick off a refresh.

// makeJWT builds a syntactically valid JWT with the requested issuer.
// Signature uses a throwaway HS256 key; the classifier never
// verifies, so the key value doesn't matter — only the claims do.
func makeJWT(t *testing.T, issuer string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   "alice",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	s, err := tok.SignedString([]byte("classifier-test-throwaway-key"))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return s
}

// testTrustDomain is the TRUST_DOMAIN value all classifier tests
// use. Constant so the iss-comparison paths can refer to it as
// "iss matches TRUST_DOMAIN" without re-stating it everywhere.
const testTrustDomain = "ap40.example.com"

// classifierTestHandler constructs the smallest Handler that can run
// classifyUnknownToken: an OAuth2Provider with just the issuer set
// and a fixed trust domain. No DB, no storage — those aren't touched
// by the classifier. Pass an empty idpIssuer to simulate a server
// running without OAuth2 (the oauth2Provider stays nil).
func classifierTestHandler(idpIssuer string) *Handler {
	h := &Handler{trustDomain: testTrustDomain}
	if idpIssuer != "" {
		h.oauth2Provider = &OAuth2Provider{
			config: &fosite.Config{AccessTokenIssuer: idpIssuer},
		}
	}
	return h
}

// TestClassifyUnknownTokenOurIDPRejected pins the bug-fix invariant:
// a JWT whose `iss` matches our OAuth2 issuer must NOT be forwarded
// to the schedd just because fosite rejected it. The classifier
// returns tokenClassOurIDP and the caller's branch logic turns that
// into a 401, which is what kicks claude.ai into a refresh flow.
func TestClassifyUnknownTokenOurIDPRejected(t *testing.T) {
	h := classifierTestHandler("https://ap40.example.com")
	tok := makeJWT(t, "https://ap40.example.com")
	got := h.classifyUnknownToken(tok)
	if got != tokenClassOurIDP {
		t.Errorf("classifyUnknownToken with our-IDP iss = %v, want tokenClassOurIDP", got)
	}
}

// TestClassifyUnknownTokenPoolIDToken confirms that a JWT whose iss
// matches TRUST_DOMAIN is still classified as a pool IDTOKEN that
// the caller should hand to the schedd for verification. This is
// the legitimate fall-through path — `condor_token_*`-fetched
// tokens from CLI users, etc.
func TestClassifyUnknownTokenPoolIDToken(t *testing.T) {
	h := classifierTestHandler("https://ap40.example.com")
	tok := makeJWT(t, "ap40.example.com")
	got := h.classifyUnknownToken(tok)
	if got != tokenClassPoolIDToken {
		t.Errorf("classifyUnknownToken with TRUST_DOMAIN iss = %v, want tokenClassPoolIDToken", got)
	}
}

// TestClassifyUnknownTokenForeignIssuer confirms that a JWT issued
// by some third party (e.g. an upstream Google/Okta OIDC) gets
// 401'd rather than silently shipped to the schedd. This is the
// "anything we don't recognize is an auth failure" rule.
func TestClassifyUnknownTokenForeignIssuer(t *testing.T) {
	h := classifierTestHandler("https://ap40.example.com")
	tok := makeJWT(t, "https://login.example.org")
	got := h.classifyUnknownToken(tok)
	if got != tokenClassUnknownIssuer {
		t.Errorf("classifyUnknownToken with foreign iss = %v, want tokenClassUnknownIssuer", got)
	}
}

// TestClassifyUnknownTokenUnparseable covers the case where the
// presented Authorization value doesn't even decode as a JWT —
// gibberish, an opaque-token cookie someone pasted by mistake, etc.
// Must NOT panic and must NOT forward to the schedd.
func TestClassifyUnknownTokenUnparseable(t *testing.T) {
	h := classifierTestHandler("https://ap40.example.com")
	for _, garbage := range []string{
		"",
		"not.a.jwt",
		"abc.def",
		"completelyrandomstring",
	} {
		got := h.classifyUnknownToken(garbage)
		if got != tokenClassUnparseable && got != tokenClassUnknownIssuer {
			t.Errorf("classifyUnknownToken(%q) = %v, want unparseable or unknown-issuer",
				garbage, got)
		}
	}
}

// TestClassifyTokenWithTrustDomainIssuerForwards confirms a genuine
// external IDTOKEN (e.g. condor_token_fetch output from a CLI user),
// whose iss==TRUST_DOMAIN, is forwarded to the schedd for signature
// verification rather than 401'd. Our own MCP clients don't reach this
// path — they present an opaque fosite token — so this is purely the
// external-pool-token case.
func TestClassifyTokenWithTrustDomainIssuerForwards(t *testing.T) {
	h := classifierTestHandler("https://ap40.example.com")
	tok := makeJWT(t, testTrustDomain)
	got := h.classifyUnknownToken(tok)
	if got != tokenClassPoolIDToken {
		t.Errorf("iss==TRUST_DOMAIN classified as %v, want tokenClassPoolIDToken", got)
	}
}

// TestGenerateMCPAccessJWTBackdatesNotBefore confirms our local minter
// (a) backdates the `nbf` claim by nbfClockSkewLeeway so the schedd
// won't reject the token over small clock skew, (b) carries the
// expected diagnostic claims, and (c) no longer stamps the retired
// token_use marker.
func TestGenerateMCPAccessJWTBackdatesNotBefore(t *testing.T) {
	// We need a passwords.d/-style key file on disk. Use a fixed
	// 32-byte payload — the minter XOR-unscrambles with 0xdeadbeef
	// then runs HKDF; any bytes work for inspecting the claims.
	keyDir := t.TempDir()
	keyPath := keyDir + "/POOL"
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i)
	}
	if err := writeKey(keyPath, keyBytes); err != nil {
		t.Fatalf("writeKey: %v", err)
	}

	iat := time.Now().Unix()
	token, err := generateMCPAccessJWT(keyDir, "POOL",
		"alice@example.com", testTrustDomain,
		iat, iat+3600, []string{"READ"})
	if err != nil {
		t.Fatalf("generateMCPAccessJWT: %v", err)
	}

	// Decode the claims directly to inspect nbf / token_use, which
	// inspectToken doesn't surface.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)

	nbf, ok := claims["nbf"].(float64)
	if !ok {
		t.Fatalf("minted token missing nbf claim; claims=%v", claims)
	}
	wantNbf := iat - int64(nbfClockSkewLeeway.Seconds())
	if int64(nbf) != wantNbf {
		t.Errorf("nbf = %d, want %d (iat %d backdated by %s)",
			int64(nbf), wantNbf, iat, nbfClockSkewLeeway)
	}
	if _, present := claims["token_use"]; present {
		t.Errorf("minted token still carries retired token_use claim: %v", claims["token_use"])
	}

	// Sanity-check the diagnostic claims survived.
	insp := inspectToken(token)
	if insp.Issuer != testTrustDomain {
		t.Errorf("Issuer = %q, want %q", insp.Issuer, testTrustDomain)
	}
	if insp.Subject != "alice@example.com" {
		t.Errorf("Subject = %q, want alice@example.com", insp.Subject)
	}
	if insp.KeyID != "POOL" {
		t.Errorf("KeyID = %q, want POOL", insp.KeyID)
	}
}

// writeKey writes a synthetic passwords.d/ key in HTCondor's
// 0xdeadbeef-scrambled format. Just enough to drive
// generateMCPAccessJWT in tests without depending on the cedar
// key-generation helpers.
func writeKey(path string, keyBytes []byte) error {
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	scrambled := make([]byte, len(keyBytes))
	for i := range keyBytes {
		scrambled[i] = keyBytes[i] ^ deadbeef[i%len(deadbeef)]
	}
	return os.WriteFile(path, scrambled, 0o600)
}

// TestInspectTokenExtractsDiagnosticFields pins the
// inspector that drives the "OAuth2 introspection rejected token"
// log line's iss / sub / kid fields. Operators rely on these to
// triage in production (they don't have the Bearer header in hand);
// a refactor that quietly drops them would re-create the original
// "we have no idea what was presented" problem.
func TestInspectTokenExtractsDiagnosticFields(t *testing.T) {
	// Build a JWT with iss, sub, AND a header.kid so we exercise
	// every field the inspector reports.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "ap40.example.com",
		Subject:   "alice@example.com",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	tok.Header["kid"] = "POOL"
	signed, err := tok.SignedString([]byte("inspector-test-key"))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	got := inspectToken(signed)
	if got.Issuer != "ap40.example.com" {
		t.Errorf("Issuer = %q, want ap40.example.com", got.Issuer)
	}
	if got.Subject != "alice@example.com" {
		t.Errorf("Subject = %q, want alice@example.com", got.Subject)
	}
	if got.KeyID != "POOL" {
		t.Errorf("KeyID = %q, want POOL", got.KeyID)
	}
}

// TestInspectTokenZeroValueOnGarbage confirms inspectToken returns
// the zero value (not a panic / partial population) when handed
// something that doesn't parse. The auth log path tolerates empty
// fields — they're themselves a signal — but a panic in the log
// path would mask the actual failure with a 500.
func TestInspectTokenZeroValueOnGarbage(t *testing.T) {
	for _, bad := range []string{
		"",
		"not.a.jwt",
		"abc",
		"....",
	} {
		got := inspectToken(bad)
		if got.Issuer != "" || got.Subject != "" || got.KeyID != "" {
			t.Errorf("inspectToken(%q) = %+v, want zero value", bad, got)
		}
	}
}

// TestClassifyUnknownTokenNoOAuth2Provider covers a degraded
// configuration: OAuth2 is disabled, so an "our IDP" check is
// impossible. The classifier still needs to behave: TRUST_DOMAIN
// matches still route as pool IDTOKEN, everything else is
// unknown-issuer. The old code would have happily forwarded
// anything 3-dot to the schedd here too.
func TestClassifyUnknownTokenNoOAuth2Provider(t *testing.T) {
	h := classifierTestHandler("")
	if got := h.classifyUnknownToken(makeJWT(t, "ap40.example.com")); got != tokenClassPoolIDToken {
		t.Errorf("no-oauth, TRUST_DOMAIN iss: got %v, want tokenClassPoolIDToken", got)
	}
	if got := h.classifyUnknownToken(makeJWT(t, "https://random.example")); got != tokenClassUnknownIssuer {
		t.Errorf("no-oauth, foreign iss: got %v, want tokenClassUnknownIssuer", got)
	}
}

// TestWWWAuthenticateIncludesResourceMetadata pins the RFC 9728
// addition: when httpBaseURL is set, the WWW-Authenticate header
// must carry a `resource_metadata="<base>/.well-known/oauth-protected-resource"`
// parameter. claude.ai's MCP client reads that to discover the
// authorization server and trigger refresh; without it the client
// either errors out or stops talking.
//
// Verified against writeOAuthError (the 401 path) because that's
// the only emitter on the auth-failure code path and it's the one
// the MCP handler invokes.
func TestWWWAuthenticateIncludesResourceMetadata(t *testing.T) {
	server, err := NewServer(Config{
		Logger:       newTestLogger(t),
		EnableMCP:    true,
		OAuth2DBPath: filepath.Join(t.TempDir(), "rfc9728.db"),
		OAuth2Issuer: "https://ap40.example.com",
		HTTPBaseURL:  "https://ap40.example.com",
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	rr := httptest.NewRecorder()
	server.writeOAuthError(rr, 401, "invalid_token", "expired")
	h := rr.Header().Get("WWW-Authenticate")
	if h == "" {
		t.Fatalf("missing WWW-Authenticate header")
	}
	wantSubstring := `resource_metadata="https://ap40.example.com/.well-known/oauth-protected-resource"`
	if !strings.Contains(h, wantSubstring) {
		t.Errorf("WWW-Authenticate missing %s\nfull header: %s", wantSubstring, h)
	}
	// Also confirm the legacy RFC 6750 pieces are still there — the
	// MCP spec wants resource_metadata IN ADDITION TO, not instead of,
	// realm/error/error_description.
	for _, want := range []string{
		`Bearer`,
		`realm=`,
		`error="invalid_token"`,
		`error_description="expired"`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("WWW-Authenticate missing legacy field %q\nfull header: %s", want, h)
		}
	}
}

// TestWWWAuthenticateOmitsResourceMetadataWhenNoBaseURL confirms we
// don't emit a malformed/relative `resource_metadata` value when the
// operator hasn't configured a public base URL. The header still
// includes RFC 6750 fields so clients that don't understand RFC 9728
// still get something usable.
func TestWWWAuthenticateOmitsResourceMetadataWhenNoBaseURL(t *testing.T) {
	server, err := NewServer(Config{
		Logger:       newTestLogger(t),
		EnableMCP:    true,
		OAuth2DBPath: filepath.Join(t.TempDir(), "no-base.db"),
		OAuth2Issuer: "https://ap40.example.com",
		// HTTPBaseURL deliberately empty.
		ScheddName: "test-schedd",
		ScheddAddr: "127.0.0.1:9618",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	rr := httptest.NewRecorder()
	server.writeOAuthError(rr, 401, "invalid_token", "expired")
	h := rr.Header().Get("WWW-Authenticate")
	if strings.Contains(h, "resource_metadata") {
		t.Errorf("WWW-Authenticate carried resource_metadata despite empty httpBaseURL: %s", h)
	}
	if !strings.Contains(h, "Bearer") || !strings.Contains(h, "realm=") {
		t.Errorf("WWW-Authenticate missing legacy fields when no base URL is set: %s", h)
	}
}
