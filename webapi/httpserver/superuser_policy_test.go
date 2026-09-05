package httpserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

type fakeSuperUsers struct {
	users []string
	err   error
	calls int
}

func (f *fakeSuperUsers) QueueSuperUsers(_ context.Context) ([]string, error) {
	f.calls++
	return f.users, f.err
}

func newTestPolicy(t *testing.T, src queueSuperUserSource) *superuserPolicy {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return newSuperuserPolicy(src, "example.org", "", time.Hour, logger)
}

// TestImpersonationIdentityPrefersTheActor is the point of the whole policy:
// when the admin is themselves a queue superuser, act as them, so the schedd's
// own log names the human rather than a shared account.
func TestImpersonationIdentityPrefersTheActor(t *testing.T) {
	src := &fakeSuperUsers{users: []string{"root", "root@example.org", "condor", "condor@example.org", "bob@example.org"}}
	p := newTestPolicy(t, src)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	t.Run("actor who is a queue superuser acts as themselves", func(t *testing.T) {
		id, isSuper := p.ImpersonationIdentity("bob")
		if id != "bob@example.org" || !isSuper {
			t.Errorf("got (%q, %v), want (bob@example.org, true)", id, isSuper)
		}
	})

	t.Run("actor who is not falls back to condor", func(t *testing.T) {
		id, isSuper := p.ImpersonationIdentity("carol")
		if id != "condor@example.org" || isSuper {
			t.Errorf("got (%q, %v), want (condor@example.org, false)", id, isSuper)
		}
	})

	t.Run("already-qualified actor matches", func(t *testing.T) {
		id, isSuper := p.ImpersonationIdentity("bob@example.org")
		if id != "bob@example.org" || !isSuper {
			t.Errorf("got (%q, %v)", id, isSuper)
		}
	})

	t.Run("matching is case insensitive", func(t *testing.T) {
		// HTCondor treats identities case-insensitively in several
		// places; a config listing "Bob" must not silently fail to match.
		id, isSuper := p.ImpersonationIdentity("BOB")
		if !isSuper {
			t.Errorf("got (%q, %v), want a superuser match", id, isSuper)
		}
	})
}

// TestImpersonationIdentityNeverPollsPerAction pins the requirement that the
// schedd is not consulted on the path of an action.
func TestImpersonationIdentityNeverPollsPerAction(t *testing.T) {
	src := &fakeSuperUsers{users: []string{"bob@example.org"}}
	p := newTestPolicy(t, src)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	before := src.calls
	for i := 0; i < 100; i++ {
		p.ImpersonationIdentity("bob")
		p.ImpersonationIdentity("carol")
	}
	if src.calls != before {
		t.Errorf("ImpersonationIdentity contacted the schedd %d times; it must read the cache only",
			src.calls-before)
	}
}

// TestUnreadableSetFallsBackWithoutGuessing covers the case where the schedd
// has never answered. Guessing at HTCondor's compiled-in default here would
// silently decide who may act as whom.
func TestUnreadableSetFallsBackWithoutGuessing(t *testing.T) {
	src := &fakeSuperUsers{err: errors.New("schedd unreachable")}
	p := newTestPolicy(t, src)
	if err := p.Refresh(context.Background()); err == nil {
		t.Fatalf("expected the refresh error to surface")
	}

	// Even for root, which is a superuser in every stock config.
	id, isSuper := p.ImpersonationIdentity("root")
	if isSuper {
		t.Errorf("must not claim superuser status from an unread set")
	}
	if id != "condor@example.org" {
		t.Errorf("identity = %q, want the fallback", id)
	}
}

// TestRefreshErrorKeepsThePreviousSet: a blip must not demote every admin.
func TestRefreshErrorKeepsThePreviousSet(t *testing.T) {
	src := &fakeSuperUsers{users: []string{"bob@example.org"}}
	p := newTestPolicy(t, src)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	src.err = errors.New("transient")
	src.users = nil
	if err := p.Refresh(context.Background()); err == nil {
		t.Fatalf("expected an error")
	}

	if _, isSuper := p.ImpersonationIdentity("bob"); !isSuper {
		t.Errorf("a failed refresh discarded the previously-known set")
	}
	if _, _, lastErr := p.Status(); lastErr == nil {
		t.Errorf("Status should surface the refresh error")
	}
}

// TestEmptySetIsNotAnError covers QUEUE_SUPER_USERS being unset on the schedd:
// QueueSuperUsers returns (nil, nil), which is a successful read of "I don't
// know the list", and must not be mistaken for "nobody is a superuser" in a
// way that claims anyone is.
func TestEmptySetIsNotAnError(t *testing.T) {
	src := &fakeSuperUsers{users: nil}
	p := newTestPolicy(t, src)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	id, isSuper := p.ImpersonationIdentity("root")
	if isSuper {
		t.Errorf("an empty set must not make anyone a superuser")
	}
	if id != "condor@example.org" {
		t.Errorf("identity = %q, want the fallback", id)
	}
}

func TestPolicyWithoutUIDDomain(t *testing.T) {
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	p := newSuperuserPolicy(&fakeSuperUsers{users: []string{"bob"}}, "", "", time.Hour, logger)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// qualifyUser returns "" for a bare name with no domain, so the actor
	// cannot be resolved and must not be treated as a superuser.
	if _, isSuper := p.ImpersonationIdentity("bob"); isSuper {
		t.Errorf("an unqualifiable actor must not match")
	}
}

// TestSuperuserModeRequiresBothGroupAndSigningKey covers the enablement rule.
// A deployment that sets the group but has no signing key is misconfigured,
// not half-enabled: there would be no credential to act under.
func TestSuperuserModeRequiresBothGroupAndSigningKey(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	for _, tc := range []struct {
		name        string
		group       string
		signingKey  string
		trustDomain string
		want        bool
	}{
		{"group and key", "admins", "/etc/condor/passwords.d/POOL", "example.org", true},
		{"no group", "", "/etc/condor/passwords.d/POOL", "example.org", false},
		{"group but no signing key", "admins", "", "example.org", false},
		{"group but no trust domain", "admins", "/etc/condor/passwords.d/POOL", "", false},
		{"neither", "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{
				logger:         logger,
				uidDomain:      "example.org",
				signingKeyPath: tc.signingKey,
				trustDomain:    tc.trustDomain,
			}
			h.initSuperuserMode(HandlerConfig{SuperuserGroup: tc.group}, logger)
			if got := h.superuserModeAvailable(); got != tc.want {
				t.Errorf("superuserModeAvailable() = %v, want %v", got, tc.want)
			}
			if !tc.want && h.superuserGroup != "" {
				t.Errorf("disabled mode left a group set: %q", h.superuserGroup)
			}
		})
	}
}

// TestSuperuserGroupIsNotTheAdminGroup is a guard against the two knobs being
// quietly collapsed later. Being able to read the admin pages must not confer
// the ability to act as other users.
func TestSuperuserGroupIsNotTheAdminGroup(t *testing.T) {
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	h := &Handler{
		logger:          logger,
		uidDomain:       "example.org",
		signingKeyPath:  "/etc/condor/passwords.d/POOL",
		trustDomain:     "example.org",
		webuiAdminGroup: "web-admins",
	}
	h.initSuperuserMode(HandlerConfig{SuperuserGroup: ""}, logger)
	if h.superuserModeAvailable() {
		t.Errorf("configuring only the admin group enabled superuser mode")
	}
}

// TestFallbackIdentityIsConfigurable covers the knob that lets the fallback
// match how the pool actually runs.
//
// "condor@$(UID_DOMAIN)" is only correct for a schedd running as the condor
// user: real_owner_is_condor recognises the daemon's own OS user, but ONLY
// when personal_condor is false. A personal condor disables that branch, so
// the equivalent identity there is whoever the pool runs as -- and without
// this knob the fallback path could not be exercised outside a system install.
func TestFallbackIdentityIsConfigurable(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	src := &fakeSuperUsers{users: []string{"condor@example.org"}}

	t.Run("empty selects condor", func(t *testing.T) {
		p := newSuperuserPolicy(src, "example.org", "", time.Hour, logger)
		if p.fallback != "condor@example.org" {
			t.Errorf("fallback = %q, want condor@example.org", p.fallback)
		}
	})

	t.Run("a bare name is qualified with the uid domain", func(t *testing.T) {
		p := newSuperuserPolicy(src, "example.org", "poolrunner", time.Hour, logger)
		if p.fallback != "poolrunner@example.org" {
			t.Errorf("fallback = %q, want poolrunner@example.org", p.fallback)
		}
	})

	t.Run("an already-qualified name is left alone", func(t *testing.T) {
		p := newSuperuserPolicy(src, "example.org", "svc@other.org", time.Hour, logger)
		if p.fallback != "svc@other.org" {
			t.Errorf("fallback = %q", p.fallback)
		}
	})

	t.Run("it is what a non-superuser actor gets", func(t *testing.T) {
		p := newSuperuserPolicy(src, "example.org", "poolrunner", time.Hour, logger)
		if err := p.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		id, isSuper := p.ImpersonationIdentity("carol")
		if id != "poolrunner@example.org" || isSuper {
			t.Errorf("got (%q, %v), want the configured fallback", id, isSuper)
		}
	})
}
