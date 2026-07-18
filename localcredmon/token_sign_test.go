package localcredmon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// TestRefreshAccessTokenSigning exercises the golang-jwt signing path for both
// RSA (RS256) and ECDSA (ES256) keys and verifies the emitted .use file is a
// valid JWT carrying the expected SciToken claims.
func TestRefreshAccessTokenSigning(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	cases := []struct {
		name    string
		key     interface{}
		alg     string
		keyFunc jwt.Keyfunc
	}{
		{
			name:    "RS256",
			key:     rsaKey,
			alg:     "RS256",
			keyFunc: func(*jwt.Token) (interface{}, error) { return &rsaKey.PublicKey, nil },
		},
		{
			name:    "ES256",
			key:     ecKey,
			alg:     "ES256",
			keyFunc: func(*jwt.Token) (interface{}, error) { return &ecKey.PublicKey, nil },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lc := &LocalCredmon{
				config: Config{
					PrivateKey:    tc.key,
					Issuer:        "https://issuer.example.org",
					Audience:      []string{"https://collector.example.org"},
					TokenLifetime: 20 * time.Minute,
					AuthzTemplate: "read:/user/{username} write:/user/{username}",
					Logger:        log.New(io.Discard, "", 0),
				},
			}

			useFile := filepath.Join(t.TempDir(), "cred.use")
			if err := lc.refreshAccessToken("alice", "", useFile); err != nil {
				t.Fatalf("refreshAccessToken: %v", err)
			}

			//nolint:gosec // useFile is a temp path this test just wrote
			raw, err := os.ReadFile(useFile)
			if err != nil {
				t.Fatalf("read use file: %v", err)
			}

			claims := jwt.MapClaims{}
			tok, err := jwt.ParseWithClaims(string(raw), claims, tc.keyFunc,
				jwt.WithValidMethods([]string{tc.alg}))
			if err != nil {
				t.Fatalf("parse/verify token: %v", err)
			}
			if !tok.Valid {
				t.Fatal("token reported invalid")
			}

			if got := claims["sub"]; got != "alice" {
				t.Errorf("sub = %v, want alice", got)
			}
			if got := claims["iss"]; got != "https://issuer.example.org" {
				t.Errorf("iss = %v, want issuer", got)
			}
			if got := claims["ver"]; got != "scitoken:2.0" {
				t.Errorf("ver = %v, want scitoken:2.0", got)
			}
			if got := claims["scope"]; got != "read:/user/alice write:/user/alice" {
				t.Errorf("scope = %v, want templated scope", got)
			}
			// Single-element audience is emitted as a bare string.
			if got := claims["aud"]; got != "https://collector.example.org" {
				t.Errorf("aud = %v, want single string audience", got)
			}
		})
	}
}
