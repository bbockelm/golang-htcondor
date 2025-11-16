package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Helper function to create a test JWT token
func createTestJWTToken(validForSeconds int) string {
	// Create JWT header with kid (key ID)
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"kid": "POOL",
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Create JWT payload with current timestamps
	now := time.Now().Unix()
	payload := map[string]interface{}{
		"sub": "alice@test.domain",
		"iss": "test.domain",
		"iat": now,
		"exp": now + int64(validForSeconds),
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Create signature
	tokenData := headerB64 + "." + payloadB64
	poolKeyUnscrambled := []byte("test_pool_signing_key_32_bytes!!")
	signingKey := make([]byte, len(poolKeyUnscrambled)*2)
	copy(signingKey, poolKeyUnscrambled)
	copy(signingKey[len(poolKeyUnscrambled):], poolKeyUnscrambled)

	// Expand the signing key using HKDF
	jwtKey := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, signingKey, []byte("htcondor"), []byte("master jwt"))
	_, _ = io.ReadFull(hkdfReader, jwtKey)

	// Compute HMAC-SHA256 with the expanded key
	mac := hmac.New(sha256.New, jwtKey)
	mac.Write([]byte(tokenData))
	signatureBytes := mac.Sum(nil)[:32]
	signature := base64.RawURLEncoding.EncodeToString(signatureBytes)

	return headerB64 + "." + payloadB64 + "." + signature
}

// Helper function to create an expired test JWT token
func createExpiredTestJWTToken(subject, issuer string) string {
	// Create JWT header with kid (key ID)
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
		"kid": "POOL",
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Create JWT payload with past timestamps (expired)
	past := time.Now().Unix() - 3600 // 1 hour ago
	payload := map[string]interface{}{
		"sub": subject,
		"iss": issuer,
		"iat": past - 600, // issued 10 minutes before expiry
		"exp": past,       // expired 1 hour ago
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Create signature
	signature := base64.RawURLEncoding.EncodeToString([]byte("dummy_signature_for_testing_32bytes"))

	return headerB64 + "." + payloadB64 + "." + signature
}

func TestParseJWTExpiration(t *testing.T) {
	t.Run("ValidToken", func(t *testing.T) {
		token := createTestJWTToken(3600)
		exp, err := parseJWTExpiration(token)
		if err != nil {
			t.Fatalf("Failed to parse JWT expiration: %v", err)
		}

		// Should expire approximately 1 hour from now
		expectedExp := time.Now().Add(3600 * time.Second)
		diff := exp.Sub(expectedExp).Abs()
		if diff > 2*time.Second {
			t.Errorf("Expiration time mismatch: expected around %v, got %v (diff: %v)", expectedExp, exp, diff)
		}
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		token := createExpiredTestJWTToken("alice@test.domain", "test.domain")
		exp, err := parseJWTExpiration(token)
		if err != nil {
			t.Fatalf("Failed to parse JWT expiration: %v", err)
		}

		// Should be in the past
		if !exp.Before(time.Now()) {
			t.Errorf("Expected expiration to be in the past, got %v", exp)
		}
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		_, err := parseJWTExpiration("invalid.token")
		if err == nil {
			t.Error("Expected error for invalid token format")
		}
	})

	t.Run("MissingExpClaim", func(t *testing.T) {
		// Create token without exp claim
		header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
		headerBytes, _ := json.Marshal(header)
		headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

		payload := map[string]interface{}{"sub": "test@test.com"}
		payloadBytes, _ := json.Marshal(payload)
		payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

		token := headerB64 + "." + payloadB64 + ".signature"
		_, err := parseJWTExpiration(token)
		if err == nil {
			t.Error("Expected error for missing exp claim")
		}
	})
}

func TestTokenCache(t *testing.T) {
	t.Run("AddValidToken", func(t *testing.T) {
		cache := NewTokenCache()
		token := createTestJWTToken(3600)

		entry, err := cache.Add(token)
		if err != nil {
			t.Fatalf("Failed to add token to cache: %v", err)
		}

		if entry.Token != token {
			t.Errorf("Token mismatch in cache entry")
		}

		if entry.SessionCache == nil {
			t.Error("SessionCache should not be nil")
		}

		if cache.Size() != 1 {
			t.Errorf("Expected cache size 1, got %d", cache.Size())
		}
	})

	t.Run("AddExpiredToken", func(t *testing.T) {
		cache := NewTokenCache()
		token := createExpiredTestJWTToken("alice@test.domain", "test.domain")

		_, err := cache.Add(token)
		if err == nil {
			t.Error("Expected error when adding expired token")
		}
	})

	t.Run("GetExistingToken", func(t *testing.T) {
		cache := NewTokenCache()
		token := createTestJWTToken(3600)

		_, err := cache.Add(token)
		if err != nil {
			t.Fatalf("Failed to add token: %v", err)
		}

		entry, exists := cache.Get(token)
		if !exists {
			t.Error("Token should exist in cache")
		}

		if entry.Token != token {
			t.Error("Retrieved wrong token from cache")
		}
	})

	t.Run("GetNonExistentToken", func(t *testing.T) {
		cache := NewTokenCache()
		_, exists := cache.Get("nonexistent.token.here")
		if exists {
			t.Error("Should not find non-existent token")
		}
	})

	t.Run("RemoveToken", func(t *testing.T) {
		cache := NewTokenCache()
		token := createTestJWTToken(3600)

		_, err := cache.Add(token)
		if err != nil {
			t.Fatalf("Failed to add token: %v", err)
		}

		cache.Remove(token)

		if cache.Size() != 0 {
			t.Errorf("Expected cache size 0 after removal, got %d", cache.Size())
		}

		_, exists := cache.Get(token)
		if exists {
			t.Error("Token should not exist after removal")
		}
	})

	t.Run("AddDuplicateToken", func(t *testing.T) {
		cache := NewTokenCache()
		token := createTestJWTToken(3600)

		entry1, err := cache.Add(token)
		if err != nil {
			t.Fatalf("Failed to add token: %v", err)
		}

		// Add same token again
		entry2, err := cache.Add(token)
		if err != nil {
			t.Fatalf("Failed to add token second time: %v", err)
		}

		// Should return the same entry
		if entry1 != entry2 {
			t.Error("Expected same entry for duplicate token")
		}

		if cache.Size() != 1 {
			t.Errorf("Expected cache size 1 after duplicate add, got %d", cache.Size())
		}
	})

	t.Run("AutomaticExpiration", func(t *testing.T) {
		cache := NewTokenCache()
		// Create token that expires in 1 second
		token := createTestJWTToken(1)

		_, err := cache.Add(token)
		if err != nil {
			t.Fatalf("Failed to add token: %v", err)
		}

		if cache.Size() != 1 {
			t.Errorf("Expected cache size 1, got %d", cache.Size())
		}

		// Wait for expiration + a bit of time for cleanup
		time.Sleep(1500 * time.Millisecond)

		// Token should be automatically removed
		if cache.Size() != 0 {
			t.Errorf("Expected cache size 0 after expiration, got %d", cache.Size())
		}
	})
}

func TestConfigureSecurityForTokenWithCache(t *testing.T) {
	t.Run("WithSessionCache", func(t *testing.T) {
		token := createTestJWTToken(3600)
		cache := NewTokenCache()
		entry, _ := cache.Add(token)

		config, err := ConfigureSecurityForTokenWithCache(token, entry.SessionCache)
		if err != nil {
			t.Fatalf("Failed to configure security: %v", err)
		}

		if config.Token != token {
			t.Error("Token not set in config")
		}

		if config.SessionCache != entry.SessionCache {
			t.Error("Session cache not set in config")
		}
	})

	t.Run("WithoutSessionCache", func(t *testing.T) {
		token := createTestJWTToken(3600)

		config, err := ConfigureSecurityForTokenWithCache(token, nil)
		if err != nil {
			t.Fatalf("Failed to configure security: %v", err)
		}

		if config.SessionCache != nil {
			t.Error("Session cache should be nil for global cache usage")
		}
	})

	t.Run("EmptyToken", func(t *testing.T) {
		_, err := ConfigureSecurityForTokenWithCache("", nil)
		if err == nil {
			t.Error("Expected error for empty token")
		}
	})
}
