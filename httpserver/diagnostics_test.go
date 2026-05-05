package httpserver

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"

	"github.com/bbockelm/cedar/security"
)

// fakeNetTimeout implements the timeout-error interface so tests can exercise
// the timeout path without standing up a real network operation.
type fakeNetTimeout struct{ msg string }

func (e *fakeNetTimeout) Error() string { return e.msg }
func (e *fakeNetTimeout) Timeout() bool { return true }

func TestClassifyConnectionError(t *testing.T) {
	const (
		sharedPortAddr = "<128.105.68.62:9618?addrs=128.105.68.62-9618&alias=ap40.uw.osg-htc.org&noUDP&sock=schedd_7942_2140>"
		plainAddr      = "<127.0.0.1:9618>"
	)

	cases := []struct {
		name        string
		addr        string
		err         error
		wantClass   connErrorClass
		wantHintSub string // substring expected in Hint, "" to skip the check
		wantSockID  string // expected SharedPort value, "" to skip
	}{
		{
			name:      "nil error",
			addr:      sharedPortAddr,
			err:       nil,
			wantClass: connErrorOther,
		},
		{
			name:        "no compatible auth methods",
			addr:        plainAddr,
			err:         fmt.Errorf("authentication handshake failed: authentication phase failed: no compatible authentication methods found"),
			wantClass:   connErrorNoCompatibleAuth,
			wantHintSub: "client and server share no auth methods",
		},
		{
			name:        "connection reset on shared-port address (the pelican-style stale-sock case)",
			addr:        sharedPortAddr,
			err:         fmt.Errorf("authentication handshake failed: failed to parse server response: read tcp 10.0.0.1:42402->128.105.68.62:9618: read: connection reset by peer"),
			wantClass:   connErrorStaleSock,
			wantHintSub: "shared-port address",
			wantSockID:  "schedd_7942_2140",
		},
		{
			name:        "connection reset wrapping syscall.ECONNRESET",
			addr:        sharedPortAddr,
			err:         fmt.Errorf("wrapper: %w", &fakeWrappedSyscall{err: syscall.ECONNRESET}),
			wantClass:   connErrorStaleSock,
			wantHintSub: "shared-port address",
			wantSockID:  "schedd_7942_2140",
		},
		{
			name:        "connection reset on plain (non-shared-port) address",
			addr:        plainAddr,
			err:         fmt.Errorf("read tcp: read: connection reset by peer"),
			wantClass:   connErrorOther,
			wantHintSub: "connection reset",
		},
		{
			name:        "connection refused",
			addr:        plainAddr,
			err:         fmt.Errorf("dial tcp 127.0.0.1:9618: connect: connection refused"),
			wantClass:   connErrorRefused,
			wantHintSub: "not listening",
		},
		{
			name:        "context deadline exceeded",
			addr:        plainAddr,
			err:         fmt.Errorf("operation: context deadline exceeded"),
			wantClass:   connErrorTimeout,
			wantHintSub: "timed out",
		},
		{
			name:        "i/o timeout via Timeout() interface",
			addr:        plainAddr,
			err:         &fakeNetTimeout{msg: "i/o timeout on read"},
			wantClass:   connErrorTimeout,
			wantHintSub: "timed out",
		},
		{
			name:      "unrelated error stays generic",
			addr:      plainAddr,
			err:       fmt.Errorf("some other failure mode"),
			wantClass: connErrorOther,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := classifyConnectionError(tc.addr, tc.err)
			if d.Class != tc.wantClass {
				t.Errorf("Class = %q, want %q", d.Class, tc.wantClass)
			}
			if tc.wantHintSub != "" && !strings.Contains(d.Hint, tc.wantHintSub) {
				t.Errorf("Hint = %q, want substring %q", d.Hint, tc.wantHintSub)
			}
			if tc.wantSockID != "" && d.SharedPort != tc.wantSockID {
				t.Errorf("SharedPort = %q, want %q", d.SharedPort, tc.wantSockID)
			}
		})
	}
}

// fakeWrappedSyscall lets us produce an errors.Is-able error that wraps a
// syscall.Errno without dialing a real socket.
type fakeWrappedSyscall struct{ err error }

func (e *fakeWrappedSyscall) Error() string { return e.err.Error() }
func (e *fakeWrappedSyscall) Unwrap() error { return e.err }

func TestIsConnectionResetError(t *testing.T) {
	if isConnectionResetError(nil) {
		t.Errorf("nil should not be a reset")
	}
	if !isConnectionResetError(fmt.Errorf("read: connection reset by peer")) {
		t.Errorf("substring match should detect reset")
	}
	if !isConnectionResetError(&fakeWrappedSyscall{err: syscall.ECONNRESET}) {
		t.Errorf("errors.Is should detect ECONNRESET")
	}
	if isConnectionResetError(fmt.Errorf("some unrelated error")) {
		t.Errorf("non-reset should not be detected as reset")
	}
}

func TestSummarizeAuthMethods(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		fields := summarizeAuthMethods(nil)
		if len(fields) != 2 || fields[0] != "security_config" || fields[1] != "<nil>" {
			t.Errorf("nil config should produce security_config=<nil>, got %v", fields)
		}
	})

	t.Run("populated config", func(t *testing.T) {
		// tokenSentinel is the marker value the test expects NEVER to
		// appear in summarizeAuthMethods's output. Pulled into a const
		// rather than a struct literal field so gosec G101 doesn't see
		// a `Token: "..."` pattern that looks like a hardcoded
		// credential — this isn't a credential, it's the bait the test
		// uses to verify the redaction guarantee.
		const tokenSentinel = "TOKEN-LEAK-CANARY-NOT-A-REAL-TOKEN" //nolint:gosec // marker, not a credential
		// gosec G101 also flags the struct-literal `Token: ...` line
		// itself; the const above isn't enough to dodge it on newer
		// gosec releases. Suppress at the literal too — same
		// rationale: this is a test sentinel, not a real secret.
		cfg := &security.SecurityConfig{ //nolint:gosec
			AuthMethods: []security.AuthMethod{security.AuthSSL, security.AuthToken},
			TrustDomain: "test.example.org",
			TokenFile:   "/etc/condor/tokens/server.token",
			Token:       tokenSentinel,
		}
		fields := summarizeAuthMethods(cfg)
		// Convert to map for easier assertion
		m := fieldsToMap(t, fields)
		if got := m["client_auth_methods"]; got != "SSL,TOKEN" {
			t.Errorf("client_auth_methods = %q, want %q", got, "SSL,TOKEN")
		}
		if got := m["trust_domain"]; got != "test.example.org" {
			t.Errorf("trust_domain = %q, want %q", got, "test.example.org")
		}
		if got := m["token_file"]; got != "/etc/condor/tokens/server.token" {
			t.Errorf("token_file = %q, want %q", got, "/etc/condor/tokens/server.token")
		}
		// Critical: the actual Token bytes must NEVER appear in the summary.
		// Only the boolean "present" flag should be there.
		for _, v := range fields {
			if s, ok := v.(string); ok && s == tokenSentinel {
				t.Errorf("Token contents leaked into summary fields: %v", fields)
			}
		}
		if got := m["inline_token_present"]; got != true {
			t.Errorf("inline_token_present = %v, want true", got)
		}
	})
}

// fieldsToMap converts an alternating key/value []any (the slog format) into
// a map[string]any so tests can assert on individual fields without indexing.
func fieldsToMap(t *testing.T, fields []any) map[string]any {
	t.Helper()
	if len(fields)%2 != 0 {
		t.Fatalf("fields has odd length %d, want even (slog k/v pairs)", len(fields))
	}
	m := make(map[string]any, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		k, ok := fields[i].(string)
		if !ok {
			t.Fatalf("field %d is not a string key: %v", i, fields[i])
		}
		m[k] = fields[i+1]
	}
	return m
}

func TestSchedSharedPortInfo(t *testing.T) {
	info := scheddSharedPortInfo("<127.0.0.1:9618?sock=schedd_42_99>")
	if !info.IsSharedPort {
		t.Errorf("expected IsSharedPort=true")
	}
	if info.SharedPortID != "schedd_42_99" {
		t.Errorf("SharedPortID = %q, want %q", info.SharedPortID, "schedd_42_99")
	}
}

// Sanity check that errors.Is still works through our diagnostic — we never
// rewrap, but if a future change does, this test will fail and force us to
// preserve the chain.
func TestClassifyDoesNotConsumeError(t *testing.T) {
	original := fmt.Errorf("authentication handshake failed: authentication phase failed: no compatible authentication methods found")
	wrapper := fmt.Errorf("outer: %w", original)
	d := classifyConnectionError("<127.0.0.1:9618>", wrapper)
	if d.Class != connErrorNoCompatibleAuth {
		t.Errorf("Class = %q, want %q", d.Class, connErrorNoCompatibleAuth)
	}
	// errors.Is must still see through to the original
	if !errors.Is(wrapper, original) {
		t.Errorf("errors.Is should still see original after classification")
	}
}
