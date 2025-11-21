package htcondor

import (
	"testing"
)

// TestPingResult tests the PingResult structure
func TestPingResult(t *testing.T) {
	result := &PingResult{
		AuthMethod:     "IDTOKENS",
		User:           "testuser@example.com",
		SessionID:      "test-session-123",
		ValidCommands:  "ALL",
		Encryption:     true,
		Authentication: true,
	}

	if result.AuthMethod != "IDTOKENS" {
		t.Errorf("Expected AuthMethod 'IDTOKENS', got '%s'", result.AuthMethod)
	}

	if result.User != "testuser@example.com" {
		t.Errorf("Expected User 'testuser@example.com', got '%s'", result.User)
	}

	if !result.Authentication {
		t.Error("Expected Authentication to be true")
	}

	if !result.Encryption {
		t.Error("Expected Encryption to be true")
	}
}
