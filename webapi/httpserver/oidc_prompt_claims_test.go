package httpserver

import (
	"testing"
	"time"

	"github.com/ory/fosite/token/jwt"
)

// promptRejection reports why fosite would refuse to issue an ID token
// for the given prompt, or "" if it would succeed. It mirrors
// handler/openid/strategy_jwt.go: any non-empty prompt requires a
// non-zero auth_time, and none/login additionally constrain how
// auth_time relates to requested_at.
func promptRejection(claims *jwt.IDTokenClaims, prompt string) string {
	if prompt == "" {
		return ""
	}
	if claims.AuthTime.IsZero() {
		return "auth_time is missing in id token claims"
	}
	switch prompt {
	case "none":
		if !claims.AuthTime.Equal(claims.RequestedAt) && claims.AuthTime.After(claims.RequestedAt) {
			return "auth_time happened after the authorization request was registered"
		}
	case "login":
		if !claims.AuthTime.Equal(claims.RequestedAt) && claims.AuthTime.Before(claims.RequestedAt) {
			return "auth_time happened before the authorization request was registered"
		}
	}
	return ""
}

// TestSessionClaimsSatisfyEveryPrompt is the regression. An OIDC client
// may send any prompt value, and each one that fosite special-cases
// reads a different claim relationship. Getting one of them wrong is not
// a validation error the client can act on -- it is an opaque HTTP 500
// server_error from the token endpoint.
func TestSessionClaimsSatisfyEveryPrompt(t *testing.T) {
	claims := newSession("alice", "htcondor-mcp").Claims

	if claims.AuthTime.IsZero() {
		t.Fatal("auth_time is zero; no prompt at all can be honored")
	}
	if claims.RequestedAt.IsZero() {
		t.Fatal("requested_at is zero; fosite reads this claim but never sets it")
	}

	for _, prompt := range []string{"", "consent", "select_account", "login", "none"} {
		if why := promptRejection(claims, prompt); why != "" {
			t.Errorf("prompt=%q would be rejected: %s", prompt, why)
		}
	}
}

// TestPromptRejectionModelMatchesFosite checks this file's model of
// fosite against the two failures actually observed in production, so a
// green run above is meaningful rather than vacuous.
func TestPromptRejectionModelMatchesFosite(t *testing.T) {
	now := time.Now().UTC()

	// The originally reported failure: no auth_time at all.
	noAuthTime := &jwt.IDTokenClaims{Subject: "alice", RequestedAt: now}
	if why := promptRejection(noAuthTime, "consent"); why != "auth_time is missing in id token claims" {
		t.Errorf("missing auth_time: got %q", why)
	}

	// The state this change fixes: auth_time set, requested_at left zero.
	noRequestedAt := &jwt.IDTokenClaims{Subject: "alice", AuthTime: now}
	if why := promptRejection(noRequestedAt, "none"); why == "" {
		t.Error("prompt=none accepted with a zero requested_at; the model does not match fosite")
	}
	// ...while the laxer prompts were unaffected, which is why only
	// prompt=none was still broken.
	if why := promptRejection(noRequestedAt, "consent"); why != "" {
		t.Errorf("prompt=consent should have been fine with a zero requested_at, got %q", why)
	}
}

// TestSessionAuthTimeMatchesClaim keeps the two copies of the same fact
// in agreement. Session.AuthTime is the authoritative one that
// reauthorizeRefreshGrant measures the grant cap from; the claim is what
// the client and fosite see.
func TestSessionAuthTimeMatchesClaim(t *testing.T) {
	s := newSession("alice", "htcondor-mcp")
	if !s.AuthTime.Equal(s.Claims.AuthTime) {
		t.Errorf("Session.AuthTime %v != Claims.AuthTime %v", s.AuthTime, s.Claims.AuthTime)
	}
}
