package httpserver

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ory/fosite"
)

func TestJWTAssertionStorage(t *testing.T) {
	// Create temporary database
	tmpfile, err := os.CreateTemp("", "oauth2_jwt_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()
	_ = tmpfile.Close()

	storage, err := NewOAuth2Storage(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer func() { _ = storage.Close() }()

	ctx := context.Background()
	jti := "test-jti-12345"
	exp := time.Now().Add(1 * time.Hour)

	// Test 1: JTI should not exist initially
	err = storage.ClientAssertionJWTValid(ctx, jti)
	if err != nil {
		t.Errorf("Expected no error for new JTI, got: %v", err)
	}

	// Test 2: Store JTI
	err = storage.SetClientAssertionJWT(ctx, jti, exp)
	if err != nil {
		t.Fatalf("Failed to store JTI: %v", err)
	}

	// Test 3: JTI should now be detected as used
	err = storage.ClientAssertionJWTValid(ctx, jti)
	if !errors.Is(err, fosite.ErrJTIKnown) {
		t.Errorf("Expected ErrJTIKnown for used JTI, got: %v", err)
	}

	// Test 4: Different JTI should still be valid
	err = storage.ClientAssertionJWTValid(ctx, "different-jti")
	if err != nil {
		t.Errorf("Expected no error for different JTI, got: %v", err)
	}

	// Test 5: Expired JTI should be cleaned up and not detected
	expiredJTI := "expired-jti"
	pastExp := time.Now().Add(-1 * time.Hour)
	err = storage.SetClientAssertionJWT(ctx, expiredJTI, pastExp)
	if err != nil {
		t.Fatalf("Failed to store expired JTI: %v", err)
	}

	// Trigger cleanup by storing another JTI
	err = storage.SetClientAssertionJWT(ctx, "trigger-cleanup", time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("Failed to store cleanup trigger JTI: %v", err)
	}

	// Expired JTI should not be detected anymore
	err = storage.ClientAssertionJWTValid(ctx, expiredJTI)
	if err != nil {
		t.Errorf("Expected no error for expired JTI after cleanup, got: %v", err)
	}
}

func TestJWTAssertionConcurrency(t *testing.T) {
	// Create temporary database
	tmpfile, err := os.CreateTemp("", "oauth2_jwt_concurrency_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()
	_ = tmpfile.Close()

	storage, err := NewOAuth2Storage(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer func() { _ = storage.Close() }()

	ctx := context.Background()
	jti := "concurrent-jti"
	exp := time.Now().Add(1 * time.Hour)

	// Store JTI
	err = storage.SetClientAssertionJWT(ctx, jti, exp)
	if err != nil {
		t.Fatalf("Failed to store JTI: %v", err)
	}

	// Test concurrent validation (simulating multiple requests with same JTI)
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			err := storage.ClientAssertionJWTValid(ctx, jti)
			if !errors.Is(err, fosite.ErrJTIKnown) {
				t.Errorf("Expected ErrJTIKnown, got: %v", err)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
