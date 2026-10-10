package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// TestDeviceCodeHandler tests the basic device code handler functionality
func TestDeviceCodeHandler(t *testing.T) {
	// Create temporary database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_device.db")

	// Create storage against the unified app DB.
	storage := NewOAuth2Storage(newTestDB(t, dbPath))

	// Create test client
	clientID := "test-device-client"
	clientSecret := "test-device-secret"
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)

	client := &fosite.DefaultClient{
		ID:         clientID,
		Secret:     hashedSecret,
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
		Scopes:     []string{"openid", "mcp:read", "mcp:write"},
		Public:     false,
	}

	ctx := context.Background()
	if err := storage.CreateClient(ctx, client); err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create config
	config := &fosite.Config{ //nolint:gosec // G101: test issuer URL
		AccessTokenIssuer: "http://localhost:8080",
	}

	// Create device code handler
	handler := NewDeviceCodeHandler(storage, config)

	t.Run("DeviceAuthorizationRequest", func(t *testing.T) {
		// Test device authorization request
		scopes := []string{"openid", "mcp:read", "mcp:write"}
		resp, err := handler.HandleDeviceAuthorizationRequest(ctx, client, scopes, "")
		if err != nil {
			t.Fatalf("Device authorization failed: %v", err)
		}

		if resp.DeviceCode == "" {
			t.Error("Device code is empty")
		}
		if resp.UserCode == "" {
			t.Error("User code is empty")
		}
		if resp.ExpiresIn <= 0 {
			t.Error("ExpiresIn should be positive")
		}
		if resp.VerificationURI == "" {
			t.Error("Verification URI is empty")
		}

		t.Logf("Device code: %s", resp.DeviceCode)
		t.Logf("User code: %s", resp.UserCode)
		t.Logf("Verification URI: %s", resp.VerificationURI)

		// Test polling before authorization (should return pending)
		session := &fosite.DefaultSession{}
		_, err = handler.HandleDeviceAccessRequest(ctx, resp.DeviceCode, session)
		if !errors.Is(err, ErrAuthorizationPending) {
			t.Errorf("Expected ErrAuthorizationPending, got: %v", err)
		}

		// Test approval
		username := "testuser"
		approvalSession := &fosite.DefaultSession{
			Subject: username,
		}
		if err := storage.ApproveDeviceCodeSession(ctx, resp.UserCode, username, approvalSession); err != nil {
			t.Fatalf("Failed to approve device: %v", err)
		}

		// Test polling after authorization (should succeed)
		request, err := handler.HandleDeviceAccessRequest(ctx, resp.DeviceCode, session)
		if err != nil {
			t.Fatalf("Device access request failed after approval: %v", err)
		}

		if request.GetSession().GetSubject() != username {
			t.Errorf("Expected subject %s, got %s", username, request.GetSession().GetSubject())
		}
	})

	t.Run("UserCodeFormat", func(t *testing.T) {
		// Test alphanumeric user code generation
		code, err := handler.generateAlphanumericCode()
		if err != nil {
			t.Fatalf("Failed to generate alphanumeric code: %v", err)
		}
		if len(code) < handler.userCodeLen {
			t.Errorf("Generated code too short: %s", code)
		}
		t.Logf("Generated alphanumeric code: %s", code)

		// Test numeric user code generation
		handler.userCodeFormat = "numeric"
		numCode, err := handler.generateNumericCode()
		if err != nil {
			t.Fatalf("Failed to generate numeric code: %v", err)
		}
		if len(numCode) != handler.userCodeLen {
			t.Errorf("Expected code length %d, got %d", handler.userCodeLen, len(numCode))
		}
		t.Logf("Generated numeric code: %s", numCode)
	})

	t.Run("ExpiredDeviceCode", func(t *testing.T) {
		// Create an expired device code
		scopes := []string{"openid"}
		resp, err := handler.HandleDeviceAuthorizationRequest(ctx, client, scopes, "")
		if err != nil {
			t.Fatalf("Device authorization failed: %v", err)
		}

		// Manually expire it by updating the database
		_, err = storage.db.ExecContext(ctx, `
			UPDATE oauth2_device_codes
			SET expires_at = ?
			WHERE device_code = ?
		`, time.Now().Add(-1*time.Minute), sessionKey(resp.DeviceCode))
		if err != nil {
			t.Fatalf("Failed to expire device code: %v", err)
		}

		// Try to use expired code - it should return wrapped ErrExpiredToken
		session := &fosite.DefaultSession{}
		_, err = handler.HandleDeviceAccessRequest(ctx, resp.DeviceCode, session)
		if err == nil {
			t.Error("Expected error for expired device code, got nil")
		}
		// The error is wrapped with ErrInvalidGrant in the handler
		if !errors.Is(err, fosite.ErrInvalidGrant) && !errors.Is(err, ErrExpiredToken) {
			// Check if it's a wrapped error
			var fositeErr *fosite.RFC6749Error
			if !errors.As(err, &fositeErr) || fositeErr.ErrorField != "invalid_grant" {
				t.Errorf("Expected invalid_grant error for expired token, got: %v (type: %T)", err, err)
			}
		}
	})

	t.Run("DeniedDeviceCode", func(t *testing.T) {
		// Create a device code
		scopes := []string{"openid"}
		resp, err := handler.HandleDeviceAuthorizationRequest(ctx, client, scopes, "")
		if err != nil {
			t.Fatalf("Device authorization failed: %v", err)
		}

		// Deny it
		if err := storage.DenyDeviceCodeSession(ctx, resp.UserCode); err != nil {
			t.Fatalf("Failed to deny device: %v", err)
		}

		// Try to use denied code
		session := &fosite.DefaultSession{}
		_, err = handler.HandleDeviceAccessRequest(ctx, resp.DeviceCode, session)
		if !errors.Is(err, fosite.ErrAccessDenied) {
			t.Errorf("Expected ErrAccessDenied, got: %v", err)
		}
	})
}

// TestDeviceCodeInvalidation tests that device codes can only be used once
func TestDeviceCodeInvalidation(t *testing.T) {
	// Create temporary database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_device_invalidation.db")

	// Create storage against the unified app DB.
	storage := NewOAuth2Storage(newTestDB(t, dbPath))

	// Create test client
	clientSecret, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	client := &fosite.DefaultClient{
		ID:         "test-client",
		Secret:     clientSecret,
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
		Scopes:     []string{"openid"},
	}

	ctx := context.Background()
	if err := storage.CreateClient(ctx, client); err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create config and handler
	config := &fosite.Config{ //nolint:gosec // G101: test issuer URL
		AccessTokenIssuer: "http://localhost:8080",
	}
	handler := NewDeviceCodeHandler(storage, config)

	// Create and approve device code
	resp, err := handler.HandleDeviceAuthorizationRequest(ctx, client, []string{"openid"}, "")
	if err != nil {
		t.Fatalf("Device authorization failed: %v", err)
	}

	username := "testuser"
	approvalSession := &fosite.DefaultSession{Subject: username}
	if err := storage.ApproveDeviceCodeSession(ctx, resp.UserCode, username, approvalSession); err != nil {
		t.Fatalf("Failed to approve device: %v", err)
	}

	// Use device code first time (should succeed)
	session1 := &fosite.DefaultSession{}
	_, err = handler.HandleDeviceAccessRequest(ctx, resp.DeviceCode, session1)
	if err != nil {
		t.Fatalf("First device access request failed: %v", err)
	}

	// Try to use the same device code again (should fail because it's been invalidated)
	session2 := &fosite.DefaultSession{}
	_, err = handler.HandleDeviceAccessRequest(ctx, resp.DeviceCode, session2)
	if err == nil {
		t.Error("Expected error when reusing device code, but got none")
	}
}

// TestDeviceCodeStoredAsHash verifies oauth2_device_codes.device_code
// holds the SHA-256 of the device code handed to the client: the code
// still redeems after approval, and the stored value does not.
func TestDeviceCodeStoredAsHash(t *testing.T) {
	storage := NewOAuth2Storage(newTestDB(t, filepath.Join(t.TempDir(), "device.db")))
	ctx := context.Background()
	client := &fosite.DefaultClient{
		ID:         "device-hash-client",
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
		Scopes:     []string{"openid"},
		Public:     true,
	}
	if err := storage.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	handler := NewDeviceCodeHandler(storage, &fosite.Config{AccessTokenIssuer: "http://localhost:8080"}) //nolint:gosec // G101: test issuer URL

	resp, err := handler.HandleDeviceAuthorizationRequest(ctx, client, []string{"openid"}, "")
	if err != nil {
		t.Fatalf("device authorization: %v", err)
	}
	var stored string
	if err := storage.db.QueryRowContext(ctx,
		`SELECT device_code FROM oauth2_device_codes WHERE user_code = ?`, resp.UserCode).Scan(&stored); err != nil {
		t.Fatalf("query: %v", err)
	}
	sum := sha256.Sum256([]byte(resp.DeviceCode))
	if want := hex.EncodeToString(sum[:]); stored != want {
		t.Fatalf("stored device_code = %q, want sha256(device code) = %q", stored, want)
	}

	if err := storage.ApproveDeviceCodeSession(ctx, resp.UserCode, "alice", &fosite.DefaultSession{Subject: "alice"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// The stored value is not itself a redeemable device code.
	if _, err := handler.HandleDeviceAccessRequest(ctx, stored, &fosite.DefaultSession{}); err == nil {
		t.Fatal("stored device_code was redeemed as a device code")
	}
	req, err := handler.HandleDeviceAccessRequest(ctx, resp.DeviceCode, &fosite.DefaultSession{})
	if err != nil {
		t.Fatalf("device code did not redeem after approval: %v", err)
	}
	if got := req.GetSession().GetSubject(); got != "alice" {
		t.Fatalf("subject = %q, want alice", got)
	}
	// Redeeming marks the row used, which also goes through the hash.
	if _, err := handler.HandleDeviceAccessRequest(ctx, resp.DeviceCode, &fosite.DefaultSession{}); err == nil {
		t.Fatal("device code redeemed twice")
	}
}
