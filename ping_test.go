package htcondor

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
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

// TestWrapScheddConnectErrorStaleSock pins the diagnostic added on top of a
// connection-reset against a shared-port address. Without this, the error
// message would be the raw "connection reset by peer" — true but unhelpful,
// since the operator can't tell whether the schedd is down or has just
// restarted with a new sock= ID.
func TestWrapScheddConnectErrorStaleSock(t *testing.T) {
	const sharedPortAddr = "<128.105.68.62:9618?sock=schedd_7942_2140>"
	original := fmt.Errorf("authentication handshake failed: failed to parse server response: read tcp 10.0.0.1:42402->128.105.68.62:9618: read: connection reset by peer")

	wrapped := wrapScheddConnectError(sharedPortAddr, original)
	if wrapped == nil {
		t.Fatal("wrapScheddConnectError returned nil")
	}

	msg := wrapped.Error()

	// The hint must mention the shared-port restart hypothesis and the
	// remediation ("re-query the collector"). These are the bits the
	// operator needs to act on; the test pins both so a future copy edit
	// doesn't accidentally drop them.
	if !strings.Contains(msg, "sock=schedd_7942_2140") {
		t.Errorf("wrapped error should mention the stale sock id, got: %s", msg)
	}
	if !strings.Contains(msg, "re-query the collector") {
		t.Errorf("wrapped error should suggest re-querying the collector, got: %s", msg)
	}
	if !strings.Contains(msg, "the daemon likely restarted") {
		t.Errorf("wrapped error should mention daemon restart, got: %s", msg)
	}

	// Critically: errors.Is on the original error must still work. Callers
	// (and especially session-resumption fallbacks) rely on the chain.
	if !errors.Is(wrapped, original) {
		t.Error("wrapped error must preserve original via %w")
	}
}

func TestWrapScheddConnectErrorPlainAddress(t *testing.T) {
	// Connection reset on a non-shared-port address gets the original
	// wording — the stale-sock hint would be misleading.
	const plainAddr = "<127.0.0.1:9618>"
	original := fmt.Errorf("read: connection reset by peer")

	wrapped := wrapScheddConnectError(plainAddr, original)
	if wrapped == nil {
		t.Fatal("wrapScheddConnectError returned nil")
	}
	msg := wrapped.Error()
	if strings.Contains(msg, "sock=") {
		t.Errorf("plain-address wrapping should not mention sock=, got: %s", msg)
	}
	if !strings.Contains(msg, "failed to connect and authenticate to schedd at") {
		t.Errorf("expected baseline wording preserved, got: %s", msg)
	}
}

func TestWrapScheddConnectErrorOtherFailure(t *testing.T) {
	// Connection refused on a shared-port address is *not* the stale-sock
	// case — that's "schedd is down" and the wrapper should not invent
	// reasons. We just want the original wording preserved.
	const sharedPortAddr = "<127.0.0.1:9618?sock=schedd_42_99>"
	original := fmt.Errorf("dial tcp 127.0.0.1:9618: connect: connection refused")

	wrapped := wrapScheddConnectError(sharedPortAddr, original)
	msg := wrapped.Error()
	if strings.Contains(msg, "the daemon likely restarted") {
		t.Errorf("connection-refused should not get the restart hint, got: %s", msg)
	}
}

func TestWrapScheddConnectErrorNil(t *testing.T) {
	if wrapScheddConnectError("anything", nil) != nil {
		t.Error("nil err must wrap to nil err")
	}
}

func TestLooksLikeConnReset(t *testing.T) {
	if looksLikeConnReset(nil) {
		t.Error("nil should not be a reset")
	}
	if !looksLikeConnReset(fmt.Errorf("read: connection reset by peer")) {
		t.Error("substring match should detect reset")
	}
	if !looksLikeConnReset(fmt.Errorf("wrapped: %w", syscall.ECONNRESET)) {
		t.Error("errors.Is should see through %%w to ECONNRESET")
	}
	if looksLikeConnReset(fmt.Errorf("connection refused")) {
		t.Error("refused must not be classified as reset")
	}
}
