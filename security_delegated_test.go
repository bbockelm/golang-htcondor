package htcondor

import (
	"context"
	"testing"

	"github.com/bbockelm/cedar/security"
)

// TestDelegatedSecurityConfigNeverOffersFS is the unit-level guard for
// the fail-open reported against query_jobs.
//
// A token passed to NewClientSecurityConfig means "act as whoever holds
// this token". FS cannot do that: it identifies the connection by the OS
// process, which for a service is the service account. Cedar negotiates
// in the SERVER's preference order, so leaving FS in the offered list
// lets an ordinary access-point schedd — SEC_DEFAULT_AUTHENTICATION_
// METHODS = FS,TOKEN — pick FS and map the connection to that account
// while the forwarded token goes unused.
//
// Downstream that is not a subtle degradation. Anything asking the
// schedd "who is this connection?" gets the service account, and on an
// access point that account is a queue superuser, for which the schedd
// drops owner filtering entirely: a "my jobs" query returns every user's
// jobs. Ordering alone does not prevent it — only removing FS does.
func TestDelegatedSecurityConfigNeverOffersFS(t *testing.T) {
	cfg, err := NewClientSecurityConfig(context.Background(), "a.token.value", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatalf("NewClientSecurityConfig: %v", err)
	}

	for _, m := range cfg.AuthMethods {
		if m == security.AuthFS {
			t.Errorf("a delegated config must not offer FS; got %v", cfg.AuthMethods)
		}
	}
	if len(cfg.AuthMethods) == 0 || cfg.AuthMethods[0] != security.AuthToken {
		t.Errorf("TOKEN must be offered first so the caller's credential is what identifies the connection; got %v", cfg.AuthMethods)
	}
	if cfg.Token != "a.token.value" {
		t.Errorf("the supplied token did not reach the config: %q", cfg.Token)
	}
}

// TestUndelegatedSecurityConfigKeepsConfiguredMethods: with no token
// there is nobody to act for, so the connection is the daemon's own and
// the configured methods stand. Stripping FS there would break every
// local same-host call that legitimately authenticates as the process.
func TestUndelegatedSecurityConfigKeepsConfiguredMethods(t *testing.T) {
	cfg, err := NewClientSecurityConfig(context.Background(), "", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatalf("NewClientSecurityConfig: %v", err)
	}
	var sawFS bool
	for _, m := range cfg.AuthMethods {
		if m == security.AuthFS {
			sawFS = true
		}
	}
	if !sawFS {
		t.Errorf("without a token the daemon's own methods should be intact, including FS; got %v", cfg.AuthMethods)
	}
}
