package httpserver

import (
	"strings"
	"testing"
)

// TestScopeToOwner pins the contract that whatever the LLM passes
// as a constraint, the chat layer's owner-scoping wraps it so the
// server-issued query ALWAYS evaluates Owner == "<actor>" first.
// This is the primary defense against an LLM being prompted into
// "show me all jobs" — the LLM cannot escape the wrapper.
func TestScopeToOwner(t *testing.T) {
	cases := []struct {
		name           string
		actor          string
		llmConstraint  string
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:          "empty constraint produces owner-only filter",
			actor:         "alice",
			llmConstraint: "",
			mustContain:   []string{`Owner == "alice"`},
		},
		{
			name:          "non-empty constraint AND-wrapped with owner",
			actor:         "alice",
			llmConstraint: "JobStatus == 5",
			mustContain:   []string{`Owner == "alice"`, `JobStatus == 5`, "&&"},
		},
		{
			name:          "LLM-supplied owner-override is neutralized by AND-wrap",
			actor:         "alice",
			llmConstraint: `Owner == "bob" || true`,
			// The AND-wrapper means the result is
			//   (Owner == "alice") && (Owner == "bob" || true)
			// → still requires Owner == "alice", so the LLM's
			// attempt to widen the scope can't take effect.
			mustContain: []string{`Owner == "alice"`, `&&`},
		},
		{
			name:          "double-quote in actor is escaped",
			actor:         `name"with"quote`,
			llmConstraint: "",
			mustContain:   []string{`Owner == "name\"with\"quote"`},
		},
		{
			name:          "backslash in actor is escaped",
			actor:         `back\slash`,
			llmConstraint: "",
			mustContain:   []string{`Owner == "back\\slash"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scopeToOwner(tc.actor, tc.llmConstraint)
			for _, want := range tc.mustContain {
				if !strings.Contains(got, want) {
					t.Errorf("scopeToOwner(%q, %q) = %q, missing %q",
						tc.actor, tc.llmConstraint, got, want)
				}
			}
			for _, banned := range tc.mustNotContain {
				if strings.Contains(got, banned) {
					t.Errorf("scopeToOwner(%q, %q) = %q, must not contain %q",
						tc.actor, tc.llmConstraint, got, banned)
				}
			}
		})
	}
}

// TestScopeToOwnerWrapperIsAtomic is the high-level invariant: no
// matter what the LLM passes, the resulting constraint includes
// `Owner == "<actor>"` as an unconditional clause that ANDs with
// everything else. We can't prove this without a real classad
// evaluator, so the test asserts the structural property — the
// whole LLM constraint is wrapped in parens, which means an OR at
// the top level of the LLM-supplied string can never short-circuit
// the leading owner clause.
func TestScopeToOwnerWrapperIsAtomic(t *testing.T) {
	// Pathological LLM output: tries to inject a `||` so the
	// resulting expression is "Owner==alice || everything-else".
	//
	// scopeToOwner wraps the LLM clause in parens, so the resulting
	// string is "(Owner == \"alice\") && (... || ...)" — the OR
	// is contained inside the right-hand operand of the AND and
	// can't override the owner clause.
	got := scopeToOwner("alice", `1 == 1 || Owner == "bob"`)

	// Lexical check: the owner clause is followed by `) && (` or
	// equivalent — confirming the LLM's text is parenthesized.
	if !strings.HasPrefix(got, `(Owner == "alice") && (`) {
		t.Errorf("scopeToOwner output missing the protective wrap: %q", got)
	}
	if !strings.HasSuffix(got, `)`) {
		t.Errorf("scopeToOwner output not closed by paren: %q", got)
	}
}
