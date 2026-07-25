package mcpserver

import (
	"context"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// admits parses a scoped constraint and reports whether it matches a job owned
// by owner (with a representative JobStatus). A scoped constraint must never
// admit a job the caller does not own.
func admits(t *testing.T, scoped, owner string) bool {
	t.Helper()
	expr, err := classad.ParseExpr(scoped)
	if err != nil {
		t.Fatalf("scoped constraint did not parse: %q: %v", scoped, err)
	}
	ad := classad.New()
	ad.InsertAttrString("Owner", owner)
	ad.InsertAttr("JobStatus", 2)
	b, _ := expr.Eval(ad).BoolValue()
	return b
}

// TestScopeToOwnerNoBypass is the regression test for the owner-scoping bypass:
// a crafted constraint must not escape the owner filter via '||' precedence or
// unbalanced parentheses. In every case the scoped result may admit only the
// authenticated caller's own jobs.
func TestScopeToOwnerNoBypass(t *testing.T) {
	s := &Server{} // no adminUsers -> "alice" is a normal, owner-scoped user
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice")

	bypassAttempts := []string{
		`true) || (true`,
		`Owner == "bob") || (true`,
		`1) || (JobStatus =?= JobStatus`,
		`true || Owner == "bob"`,     // balanced but tautological
		`JobStatus == 2 || 1 == 1`,   // balanced tautology
	}
	for _, c := range bypassAttempts {
		scoped, ok := s.scopeToOwner(ctx, c)
		if !ok {
			t.Fatalf("authenticated caller unexpectedly rejected for %q", c)
		}
		if admits(t, scoped, "bob") {
			t.Errorf("BYPASS: constraint %q admits bob's jobs via %q", c, scoped)
		}
		if admits(t, scoped, "carol") {
			t.Errorf("BYPASS: constraint %q admits carol's jobs via %q", c, scoped)
		}
	}

	// Legitimate self-scoped constraints must still see the owner's own jobs.
	for _, c := range []string{``, `true`, `JobStatus == 2`} {
		scoped, _ := s.scopeToOwner(ctx, c)
		if !admits(t, scoped, "alice") {
			t.Errorf("legit constraint %q wrongly excludes the owner: %q", c, scoped)
		}
		if admits(t, scoped, "bob") {
			t.Errorf("legit constraint %q leaks bob: %q", c, scoped)
		}
	}
}

// TestScopeToOwnerAdminBypass confirms admins keep the constraint as-is (they are
// trusted for cross-user troubleshooting).
func TestScopeToOwnerAdminBypass(t *testing.T) {
	s := &Server{adminUsers: map[string]struct{}{"root": {}}}
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "root")
	scoped, ok := s.scopeToOwner(ctx, `JobStatus == 5`)
	if !ok || scoped != `JobStatus == 5` {
		t.Errorf("admin constraint = %q (ok=%v), want unchanged", scoped, ok)
	}
}

// TestScopeToOwnerUnauthenticated: no authenticated user -> refused.
func TestScopeToOwnerUnauthenticated(t *testing.T) {
	s := &Server{}
	if _, ok := s.scopeToOwner(context.Background(), "true"); ok {
		t.Error("unauthenticated caller must be refused (ok=false)")
	}
}

func TestClassadBalanced(t *testing.T) {
	// Unbalanced / injection inputs are rejected.
	for _, bad := range []string{`true) || (true`, `Owner == "bob") || (true`, `) || (`} {
		if _, err := classadBalanced(bad); err == nil {
			t.Errorf("classadBalanced(%q) should have errored", bad)
		}
	}
	// Valid expressions round-trip to a balanced form.
	for _, good := range []string{`true`, `JobStatus == 2`, `true || Owner == "bob"`} {
		if _, err := classadBalanced(good); err != nil {
			t.Errorf("classadBalanced(%q) errored: %v", good, err)
		}
	}
}

// TestJobsMirrorScopeNoBypass exercises the exact owner-scope string tryJobsFromDB
// builds for the mirror ("(safe) && (Owner == \"user\")"), proving the same
// injection cannot widen the mirror read.
func TestJobsMirrorScopeNoBypass(t *testing.T) {
	for _, c := range []string{`true) || (true`, `Owner == "bob") || (true`, `true`, `JobStatus == 2`, `true || Owner == "bob"`} {
		safe, err := classadBalanced(c)
		if err != nil {
			continue // rejected -> tryJobsFromDB falls back to the schedd (safe)
		}
		scoped := "(" + safe + ") && (Owner == " + classadStringLit("alice") + ")"
		if admits(t, scoped, "bob") {
			t.Errorf("BYPASS in jobs mirror scope: %q -> %q admits bob", c, scoped)
		}
	}
}
