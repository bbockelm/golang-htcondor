package httpserver

import (
	"context"
	"errors"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

func TestQualifyUser(t *testing.T) {
	for _, tc := range []struct {
		name, user, domain, want string
	}{
		{"bare name gets the uid domain", "alice", "example.org", "alice@example.org"},
		{"already qualified is left alone", "alice@other.org", "example.org", "alice@other.org"},
		{"no domain available yields nothing", "alice", "", ""},
		{"empty user yields nothing", "", "example.org", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := qualifyUser(tc.user, tc.domain); got != tc.want {
				t.Errorf("qualifyUser(%q, %q) = %q, want %q", tc.user, tc.domain, got, tc.want)
			}
		})
	}
}

func TestScopeAuthzProbes(t *testing.T) {
	probeNames := func(probes []authzProbe) []string {
		out := make([]string, 0, len(probes))
		for _, p := range probes {
			out = append(out, p.name)
		}
		return out
	}

	t.Run("probes only the levels actually held", func(t *testing.T) {
		probes := scopeAuthzProbes([]string{"openid", "offline_access", "mcp:read"})
		if got := strings.Join(probeNames(probes), ","); got != "READ" {
			t.Errorf("probes = %v, want READ only — a read-only grant must not ask about WRITE", got)
		}
	})

	t.Run("write and read together", func(t *testing.T) {
		probes := scopeAuthzProbes([]string{"mcp:read", "mcp:write"})
		if got := strings.Join(probeNames(probes), ","); got != "WRITE,READ" {
			t.Errorf("probes = %v, want WRITE,READ", got)
		}
	})

	t.Run("condor scopes map to the same levels", func(t *testing.T) {
		probes := scopeAuthzProbes([]string{"condor:/WRITE"})
		if len(probes) != 1 || probes[0].name != "WRITE" {
			t.Fatalf("probes = %v, want a single WRITE probe", probeNames(probes))
		}
		if strings.Join(probes[0].scopes, ",") != "condor:/WRITE" {
			t.Errorf("probe carries scopes %v, want condor:/WRITE", probes[0].scopes)
		}
	})

	t.Run("privileged condor scopes are not probed", func(t *testing.T) {
		// mapCondorScopesToAuthz drops these from every minted token, so
		// they confer nothing and probing for them would be noise.
		probes := scopeAuthzProbes([]string{
			"condor:/ADMINISTRATOR", "condor:/CONFIG", "condor:/DAEMON", "condor:/NEGOTIATOR",
		})
		if len(probes) != 0 {
			t.Errorf("probes = %v, want none", probeNames(probes))
		}
	})

	t.Run("no relevant scopes means no probes", func(t *testing.T) {
		if probes := scopeAuthzProbes([]string{"openid"}); len(probes) != 0 {
			t.Errorf("probes = %v, want none", probeNames(probes))
		}
	})
}

// TestOraclesReportNoOpinionWithoutASchedd pins the fail-open contract at the
// edges: a misconfigured oracle must surface an error the caller ignores, not
// a revocation.
func TestOraclesReportNoOpinionWithoutASchedd(t *testing.T) {
	ctx := context.Background()

	t.Run("user record oracle", func(t *testing.T) {
		o := &UserRecordOracle{UIDDomain: "example.org"}
		decision, err := o.Check(ctx, "alice", nil)
		if err == nil {
			t.Fatalf("expected an error with no schedd configured")
		}
		if decision.Status == UserStatusRevoked {
			t.Errorf("a missing schedd must never read as a revocation")
		}
	})

	t.Run("acl oracle", func(t *testing.T) {
		o := &ScheddACLOracle{UIDDomain: "example.org"}
		decision, err := o.Check(ctx, "alice", []string{"mcp:write"})
		if err == nil {
			t.Fatalf("expected an error with no schedd configured")
		}
		if decision.Status == UserStatusRevoked {
			t.Errorf("a missing schedd must never read as a revocation")
		}
	})
}

// TestUserRecordOracleNeedsAQualifiedName pins that an unqualifiable username
// produces no opinion rather than a lookup for a name the schedd cannot key
// on. The check runs before any network call, so no schedd need be reachable.
func TestUserRecordOracleNeedsAQualifiedName(t *testing.T) {
	o := &UserRecordOracle{
		UIDDomain: "",
		Lookup:    func() UserRecordLookup { return &fakeUserRecords{} },
	}
	decision, err := o.Check(context.Background(), "alice", nil)
	if err == nil {
		t.Fatalf("expected an error for a bare username with no UID domain")
	}
	if !strings.Contains(err.Error(), "qualify") {
		t.Errorf("error = %v, want it to name the qualification problem", err)
	}
	if decision.Status == UserStatusRevoked {
		t.Errorf("an unqualifiable name must never read as a revocation")
	}
}

// newOracleTestHandler builds the minimum Handler that buildRevocationOracles
// needs: a logger, and the accessors the oracles close over.
func newOracleTestHandler(t *testing.T) *Handler {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return &Handler{
		logger:    logger,
		uidDomain: "example.org",
		schedd:    htcondor.NewSchedd("test", "127.0.0.1:9618"),
	}
}

func TestBuildRevocationOracles(t *testing.T) {
	h := newOracleTestHandler(t)

	t.Run("nil selects the default set", func(t *testing.T) {
		got := h.buildRevocationOracles(nil)
		if len(got) != 1 || got[0].Name() != "schedd-userrec" {
			t.Errorf("default oracles = %v, want [schedd-userrec]", oracleNames(got))
		}
	})

	t.Run("an explicitly empty slice disables all oracles", func(t *testing.T) {
		// Distinct from nil: an operator who writes an empty list wants
		// none, and must not silently get the defaults back.
		if got := h.buildRevocationOracles([]string{}); len(got) != 0 {
			t.Errorf("oracles = %v, want none", oracleNames(got))
		}
	})

	t.Run("both oracles by name", func(t *testing.T) {
		got := h.buildRevocationOracles([]string{"schedd-userrec", "schedd-acl"})
		if strings.Join(oracleNames(got), ",") != "schedd-userrec,schedd-acl" {
			t.Errorf("oracles = %v", oracleNames(got))
		}
	})

	t.Run("none disables every oracle", func(t *testing.T) {
		// The config system cannot express Go's nil-vs-empty-slice
		// distinction, so "none" is the spelling for "I want none".
		for _, spelling := range []string{"none", "None", "disabled", "disable"} {
			if got := h.buildRevocationOracles([]string{spelling}); len(got) != 0 {
				t.Errorf("%q gave %v, want no oracles", spelling, oracleNames(got))
			}
		}
	})

	t.Run("none mixed with a real oracle keeps the real one", func(t *testing.T) {
		// Contradictory config. Silently disabling everything would be
		// the dangerous reading, so the explicit oracle wins.
		got := h.buildRevocationOracles([]string{"none", "schedd-userrec"})
		if strings.Join(oracleNames(got), ",") != "schedd-userrec" {
			t.Errorf("oracles = %v, want schedd-userrec", oracleNames(got))
		}
	})

	t.Run("strict variant is selectable and names itself", func(t *testing.T) {
		got := h.buildRevocationOracles([]string{"schedd-userrec-strict"})
		if len(got) != 1 || got[0].Name() != "schedd-userrec-strict" {
			t.Fatalf("oracles = %v, want [schedd-userrec-strict]", oracleNames(got))
		}
		o, ok := got[0].(*UserRecordOracle)
		if !ok || !o.Strict {
			t.Errorf("strict flag not set on the built oracle")
		}
	})

	t.Run("unknown names are skipped, not fatal", func(t *testing.T) {
		got := h.buildRevocationOracles([]string{"nope", "schedd-userrec"})
		if strings.Join(oracleNames(got), ",") != "schedd-userrec" {
			t.Errorf("oracles = %v, want just schedd-userrec", oracleNames(got))
		}
	})

	t.Run("names are case and space insensitive", func(t *testing.T) {
		got := h.buildRevocationOracles([]string{"  Schedd-UserRec "})
		if len(got) != 1 {
			t.Errorf("oracles = %v, want schedd-userrec", oracleNames(got))
		}
	})
}

func oracleNames(oracles []RevocationOracle) []string {
	out := make([]string, 0, len(oracles))
	for _, o := range oracles {
		out = append(out, o.Name())
	}
	return out
}

// fakeUserRecords stands in for the schedd so the oracle's treatment of a
// missing record can be tested directly.
type fakeUserRecords struct {
	record *htcondor.UserRecord
	err    error
	asked  string
}

func (f *fakeUserRecords) GetUserRecord(_ context.Context, user string) (*htcondor.UserRecord, error) {
	f.asked = user
	return f.record, f.err
}

// TestUserRecordOracleAbsentRecord pins the single most consequential decision
// in this oracle: what a missing user record means.
//
// The schedd creates records lazily on first submit, so in an ordinary pool
// "no record" means "has never submitted here" and must not revoke — that
// would lock out every new user. In a pool that provisions a record for every
// user with `condor_qusers -add`, absence is a real answer, and Strict opts
// into treating it as one.
func TestUserRecordOracleAbsentRecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		strict bool
		want   UserStatus
	}{
		{"default treats absence as no opinion", false, UserStatusUnknown},
		{"strict treats absence as revoked", true, UserStatusRevoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeUserRecords{record: nil}
			o := &UserRecordOracle{
				Lookup:    func() UserRecordLookup { return fake },
				UIDDomain: "example.org",
				Strict:    tc.strict,
			}
			decision, err := o.Check(context.Background(), "alice", nil)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if decision.Status != tc.want {
				t.Errorf("Status = %v, want %v", decision.Status, tc.want)
			}
			if fake.asked != "alice@example.org" {
				t.Errorf("looked up %q, want the uid-domain-qualified name", fake.asked)
			}
		})
	}
}

// TestUserRecordOracleDisabledRecord covers the ordinary revocation path and
// that the admin's reason reaches the caller.
func TestUserRecordOracleDisabledRecord(t *testing.T) {
	disabled := false
	fake := &fakeUserRecords{record: &htcondor.UserRecord{
		User:          "alice@example.org",
		Enabled:       &disabled,
		DisableReason: "left the lab",
	}}
	o := &UserRecordOracle{
		Lookup:    func() UserRecordLookup { return fake },
		UIDDomain: "example.org",
	}
	decision, err := o.Check(context.Background(), "alice", nil)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Status != UserStatusRevoked {
		t.Errorf("Status = %v, want revoked", decision.Status)
	}
	if decision.Reason != "left the lab" {
		t.Errorf("Reason = %q, want the DisableReason carried through", decision.Reason)
	}
}

// TestUserRecordOracleRecordWithoutEnabled pins that a record that says
// nothing about Enabled is not a denial, even in strict mode: strict only
// changes what *absence of a record* means, not what an unopinionated record
// means. The schedd's own default for an unset Enabled is true.
func TestUserRecordOracleRecordWithoutEnabled(t *testing.T) {
	for _, strict := range []bool{false, true} {
		fake := &fakeUserRecords{record: &htcondor.UserRecord{User: "alice@example.org"}}
		o := &UserRecordOracle{
			Lookup:    func() UserRecordLookup { return fake },
			UIDDomain: "example.org",
			Strict:    strict,
		}
		decision, err := o.Check(context.Background(), "alice", nil)
		if err != nil {
			t.Fatalf("Check(strict=%v): %v", strict, err)
		}
		if decision.Status == UserStatusRevoked {
			t.Errorf("strict=%v: a record with no Enabled statement must not revoke", strict)
		}
	}
}

// TestUserRecordOracleLookupErrorFailsOpen keeps a schedd outage from logging
// everyone out.
func TestUserRecordOracleLookupErrorFailsOpen(t *testing.T) {
	fake := &fakeUserRecords{err: errors.New("schedd unreachable")}
	o := &UserRecordOracle{
		Lookup:    func() UserRecordLookup { return fake },
		UIDDomain: "example.org",
		Strict:    true, // even strict must not revoke on an error
	}
	decision, err := o.Check(context.Background(), "alice", nil)
	if err == nil {
		t.Fatalf("expected the lookup error to surface")
	}
	if decision.Status == UserStatusRevoked {
		t.Errorf("a lookup failure must never read as a revocation")
	}
}
