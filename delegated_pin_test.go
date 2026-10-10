package htcondor

import (
	"context"
	"testing"

	"github.com/bbockelm/cedar/security"
)

// A caller's credential must reach CEDAR pinned: the token it was
// given, or an error. Decided here, from the origin the transport
// already marked, rather than asked of each place that builds a
// config -- a per-config field is a thing to remember at every call
// site, and the record is that it does not get remembered.
func TestACallersConfigIsPinnedToItsOwnCredential(t *testing.T) {
	ctx := WithUserRequest(context.Background(), "test request")
	ctx = WithSecurityConfig(ctx, &security.SecurityConfig{Token: "the-callers-token"})

	got, err := GetSecurityConfigOrDefault(ctx, nil, 509, "CLIENT", "schedd.example.edu")
	if err != nil {
		t.Fatalf("GetSecurityConfigOrDefault: %v", err)
	}
	if !got.DelegatedCredential {
		t.Error("a caller's credential was not pinned; CEDAR may substitute one of this host's own")
	}
	if got.Token != "the-callers-token" {
		t.Errorf("Token = %q, want the caller's", got.Token)
	}
}

// Every route gets this without doing anything, which is the point.
// A handler that attaches a credential and forgets to say anything
// else still produces a pinned config, because the marking happens at
// the transport and the pinning happens here.
func TestPinningDoesNotDependOnTheCallSiteRemembering(t *testing.T) {
	// Exactly what an HTTP handler ends up with: marked once, on the
	// way in, by code no route touches.
	ctx := WithUserRequest(context.Background(), "HTTP request GET /api/v1/jobs")
	ctx = WithSecurityConfig(ctx, &security.SecurityConfig{Token: "t"})

	for _, command := range []int{509, 519, 1112} {
		got, err := GetSecurityConfigOrDefault(ctx, nil, command, "CLIENT", "peer")
		if err != nil {
			t.Fatalf("command %d: %v", command, err)
		}
		if !got.DelegatedCredential {
			t.Errorf("command %d produced an unpinned config", command)
		}
	}
}

// The daemon's own work is not pinned: it has no caller credential to
// pin to, and discovery across its token files is exactly what it
// wants.
func TestTheDaemonsOwnWorkIsNotPinned(t *testing.T) {
	// WithDaemonCredential detaches any credential, so this reaches
	// the fallback rather than the branch above -- which is the
	// behaviour being relied on, so assert it rather than assume it.
	ctx := WithDaemonCredential(context.Background(), "test plumbing")
	if _, ok := GetSecurityConfigFromContext(ctx); ok {
		t.Error("daemon work should carry no caller credential")
	}
}

// The pin does not disturb the copy semantics the caller relies on:
// the config on the context is not mutated by handing one out.
func TestPinningDoesNotMutateTheContextsConfig(t *testing.T) {
	original := &security.SecurityConfig{Token: "t"}
	ctx := WithUserRequest(context.Background(), "test request")
	ctx = WithSecurityConfig(ctx, original)

	if _, err := GetSecurityConfigOrDefault(ctx, nil, 509, "CLIENT", "peer"); err != nil {
		t.Fatalf("GetSecurityConfigOrDefault: %v", err)
	}

	if original.DelegatedCredential {
		t.Error("the config held on the context was modified")
	}
}
