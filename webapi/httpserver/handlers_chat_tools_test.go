package httpserver

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// scopeAdmits parses a scoped constraint and reports whether it matches a job
// owned by owner. A correctly owner-scoped constraint must admit ONLY the actor's
// own jobs, no matter what the LLM passed — this evaluates that against the real
// ClassAd engine rather than a lexical string check (a lexical check cannot catch
// the `||`/unbalanced-paren bypass and is what let it slip in originally).
func scopeAdmits(t *testing.T, scoped, owner string) bool {
	t.Helper()
	expr, err := classad.ParseExpr(scoped)
	if err != nil {
		t.Fatalf("scoped constraint did not parse: %q: %v", scoped, err)
	}
	ad := classad.New()
	ad.InsertAttrString("Owner", owner)
	ad.InsertAttr("JobStatus", 5)
	b, _ := expr.Eval(ad).BoolValue()
	return b
}

// TestScopeToOwnerConfinesToActor is the security contract: whatever the LLM
// passes, the scoped constraint may match ONLY the actor's own jobs. Evaluated
// against the real classad engine for a battery of benign and hostile inputs.
func TestScopeToOwnerConfinesToActor(t *testing.T) {
	const actor = "alice"
	cases := []string{
		"",                       // owner-only
		"JobStatus == 5",         // benign filter
		`Owner == "bob" || true`, // tautology that tries to widen
		"JobStatus == 5 || 1 == 1",
	}
	for _, c := range cases {
		scoped, err := scopeToOwner(actor, c)
		if err != nil {
			t.Fatalf("scopeToOwner(%q, %q) unexpected error: %v", actor, c, err)
		}
		if scopeAdmits(t, scoped, "bob") {
			t.Errorf("BYPASS: constraint %q admits bob's jobs via %q", c, scoped)
		}
		if scopeAdmits(t, scoped, "carol") {
			t.Errorf("BYPASS: constraint %q admits carol's jobs via %q", c, scoped)
		}
	}

	// Benign self-scoped filters must still see the actor's own jobs.
	for _, c := range []string{"", "JobStatus == 5"} {
		scoped, err := scopeToOwner(actor, c)
		if err != nil {
			t.Fatalf("scopeToOwner(%q, %q): %v", actor, c, err)
		}
		if !scopeAdmits(t, scoped, "alice") {
			t.Errorf("constraint %q wrongly excludes the owner: %q", c, scoped)
		}
	}
}

// TestScopeToOwnerRejectsInjection: a constraint crafted to escape the AND via
// unbalanced parentheses must be REJECTED (not silently widened), so a
// destructive tool (remove_jobs / edit_jobs_by_constraint) fails the call rather
// than acting on every job.
func TestScopeToOwnerRejectsInjection(t *testing.T) {
	injections := []string{
		`true) || (true`,
		`Owner == "bob") || (true`,
		`1) || (JobStatus =?= JobStatus`,
		`JobStatus == 5) || (1 == 1`,
	}
	for _, c := range injections {
		if _, err := scopeToOwner("alice", c); err == nil {
			t.Errorf("scopeToOwner(alice, %q) should have errored (injection), but succeeded", c)
		}
	}
}

// TestScopeToOwnerEscaping keeps the actor-quoting contract: quotes and
// backslashes in the (server-derived) actor are escaped into the literal.
func TestScopeToOwnerEscaping(t *testing.T) {
	cases := []struct {
		actor string
		want  string
	}{
		{`name"with"quote`, `Owner == "name\"with\"quote"`},
		{`back\slash`, `Owner == "back\\slash"`},
	}
	for _, tc := range cases {
		got, err := scopeToOwner(tc.actor, "")
		if err != nil {
			t.Fatalf("scopeToOwner(%q, \"\"): %v", tc.actor, err)
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("scopeToOwner(%q, \"\") = %q, missing %q", tc.actor, got, tc.want)
		}
	}
}

func TestClassadBalanced(t *testing.T) {
	for _, bad := range []string{`true) || (true`, `Owner == "bob") || (true`, `) || (`} {
		if _, err := classadBalanced(bad); err == nil {
			t.Errorf("classadBalanced(%q) should have errored", bad)
		}
	}
	for _, good := range []string{`true`, `JobStatus == 5`, `Owner == "bob" || true`} {
		if _, err := classadBalanced(good); err != nil {
			t.Errorf("classadBalanced(%q) errored: %v", good, err)
		}
	}
}
