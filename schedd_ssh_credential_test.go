package htcondor

import (
	"context"
	"testing"

	"github.com/bbockelm/cedar/security"
)

// The caller's credential must not become this daemon's credential.
//
// A request context carries the JWT the API server minted for the browser
// session, signed with the server's own key. GetSecurityConfigOrDefault
// prefers whatever is on the context, so a config built from a request
// context inherits that token -- and the CCB leg of ssh-to-job performs a
// fresh handshake with a pool broker, which has no such key and rejects it.
// Detaching the credential is what makes that leg authenticate as the
// daemon, using the pool token the broker does recognise.
func TestWithoutSecurityConfigDropsTheCallerCredential(t *testing.T) {
	callers := &security.SecurityConfig{
		Token:       "a.browser.session.jwt",
		AuthMethods: []security.AuthMethod{security.AuthToken},
	}
	ctx := WithSecurityConfig(context.Background(), callers)

	if _, ok := GetSecurityConfigFromContext(ctx); !ok {
		t.Fatal("precondition failed: the caller credential is not on the context, so this proves nothing")
	}

	stripped := WithoutSecurityConfig(ctx)
	if got, ok := GetSecurityConfigFromContext(stripped); ok {
		t.Errorf("the caller credential survived: token=%q", got.Token)
	}
}

// Detaching the credential must not detach the deadline: the shell open is
// bounded by a timeout, and losing it would turn a fast failure into a hang.
func TestWithoutSecurityConfigKeepsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(WithSecurityConfig(context.Background(),
		&security.SecurityConfig{Token: "t"}))
	stripped := WithoutSecurityConfig(ctx)

	select {
	case <-stripped.Done():
		t.Fatal("context is already done before cancel")
	default:
	}

	cancel()
	select {
	case <-stripped.Done():
	default:
		t.Error("cancelling the parent did not cancel the stripped context")
	}
}

// The credential this path actually relies on is the schedd-minted ClaimID,
// installed as a session on the config. Detaching the caller's token must
// leave that intact -- it is what the starter resumes on, and dropping it
// would break ssh-to-job everywhere, not just behind CCB.
func TestStarterConfigKeepsTheClaimIDSessionWithoutTheCallerToken(t *testing.T) {
	ctx := WithSecurityConfig(context.Background(), &security.SecurityConfig{
		Token:       "a.browser.session.jwt",
		AuthMethods: []security.AuthMethod{security.AuthToken},
	})
	cache := security.NewSessionCache()

	// Through the real constructor, so this covers the call site and not
	// just the helper it calls: reverting it to pass ctx fails here.
	secConfig, err := starterSecurityConfig(ctx, "<10.0.0.1:9618>", cache)
	if err != nil {
		t.Fatalf("failed to build the starter security config: %v", err)
	}

	if secConfig.Token == "a.browser.session.jwt" {
		t.Error("the caller's token reached the starter security config")
	}
	if secConfig.SessionCache != cache {
		t.Error("the ClaimID session cache was not installed; the starter has nothing to resume on")
	}
}

// Without the fix the caller's token is exactly what a config built from the
// request context carries. Stated as a test so the mechanism is on record
// rather than only in a commit message.
func TestRequestContextOtherwiseSuppliesTheCredential(t *testing.T) {
	const callerToken = "a.browser.session.jwt" //nolint:gosec // G101: not a real credential
	ctx := WithSecurityConfig(context.Background(), &security.SecurityConfig{
		Token:       callerToken,
		AuthMethods: []security.AuthMethod{security.AuthToken},
	})

	secConfig, err := NewClientSecurityConfig(ctx, "", "<10.0.0.1:9618>",
		startSSHDCommand, "CLIENT", security.NewSessionCache())
	if err != nil {
		t.Fatalf("failed to build the security config: %v", err)
	}
	if secConfig.Token != callerToken {
		t.Skipf("context no longer supplies the credential (token=%q); this test documents why the strip exists", secConfig.Token)
	}
}
