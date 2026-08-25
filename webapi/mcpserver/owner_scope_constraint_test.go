package mcpserver

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// scopeAdmits evaluates a scoped constraint against a job ad owned by
// the named user, using the real ClassAd engine rather than string
// matching — an escape shows up as a boolean, not as a substring.
func scopeAdmits(t *testing.T, scoped, owner string) bool {
	t.Helper()
	expr, err := classad.ParseExpr(scoped)
	if err != nil {
		t.Fatalf("scoped constraint did not parse: %q: %v", scoped, err)
	}
	ad := classad.New()
	ad.InsertAttrString("Owner", owner)
	ad.InsertAttr("JobStatus", 1)
	ad.InsertAttrString("Cmd", "/bin/true")
	b, _ := expr.Eval(ad).BoolValue()
	return b
}

// TestOwnerScopedConstraintConfinesTheCaller covers the property the
// whole owner-scoping story rests on: whatever the caller passes, the
// result must still be restricted to their own jobs.
//
// The escape cases are the point. ClassAd's `||` binds looser than
// `&&`, so splicing a raw constraint into "(scope) && (c)" does not
// confine it — an unbalanced input closes the scope's parenthesis and
// ORs it away, which is how a crafted constraint would return every
// user's jobs through a tool that reads as owner-scoped.
func TestOwnerScopedConstraintConfinesTheCaller(t *testing.T) {
	cases := []struct {
		name       string
		constraint string
		// matchesAlice says whether this constraint, on its own merits,
		// should match the sample job below. It is false only where the
		// constraint filters the job out for an honest reason, so the
		// "caller still sees their own jobs" check is not asserted
		// against a query that legitimately matches nothing.
		matchesAlice bool
	}{
		{"empty", "", true},
		{"bare true", "true", true},
		{"ordinary", "JobStatus == 1", true},
		{"escape attempt via unbalanced parens", `true) || (true`, true},
		{"escape attempt via or", `JobStatus == 1 || true`, true},
		{"quote injection in the constraint", `Cmd == "a\") || (true"`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ownerScopedConstraint("alice", c.constraint)
			if err != nil {
				// Refusing to build a constraint is an acceptable
				// outcome for a malformed input — the caller turns it
				// into an error. Silently widening is not.
				return
			}
			if !strings.Contains(got, `Owner == "alice"`) {
				t.Fatalf("owner clause missing from %q", got)
			}
			if c.matchesAlice && !scopeAdmits(t, got, "alice") {
				t.Errorf("alice's own jobs are excluded by %q", got)
			}
			if scopeAdmits(t, got, "bob") {
				t.Errorf("ESCAPE: %q admits bob", got)
			}
		})
	}
}

// TestOwnerScopedConstraintEscapesTheOwner: the owner is an identity
// from a token, not a literal we control. A quote in it must not end
// the string early and change what the expression means.
func TestOwnerScopedConstraintEscapesTheOwner(t *testing.T) {
	got, err := ownerScopedConstraint(`alice" || true || "`, "true")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scopeAdmits(t, got, "bob") {
		t.Errorf("ESCAPE via the owner name: %q admits bob", got)
	}
}

// TestOwnerScopedConstraintRequiresAnOwner: no identity means no scope,
// and a scope-less constraint is the whole queue. It must be an error,
// never an empty clause the caller might splice in anyway.
func TestOwnerScopedConstraintRequiresAnOwner(t *testing.T) {
	if got, err := ownerScopedConstraint("", "true"); err == nil {
		t.Errorf("expected an error with no owner, got %q", got)
	}
}
