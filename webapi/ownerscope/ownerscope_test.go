package ownerscope

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestConstrainConfines evaluates the scoped constraint against another
// user's job: no input may make it match.
func TestConstrainConfines(t *testing.T) {
	other, err := classad.ParseOld("User = \"bob@d\"\nOwner = \"bob\"\nJobStatus = 2")
	if err != nil {
		t.Fatal(err)
	}
	mine, err := classad.ParseOld("User = \"alice@d\"\nOwner = \"alice\"\nJobStatus = 2")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{
		"", "true", "TRUE", "JobStatus == 2",
		"true || true",
		`User == "bob@d" || true`,
		"(true) || (true)",
		`MY.User =!= "alice@d" || true`,
	} {
		got, err := Constrain("User", "alice@d", c)
		if err != nil {
			t.Errorf("%q: %v", c, err)
			continue
		}
		expr, err := classad.ParseExpr(got)
		if err != nil {
			t.Fatalf("%q produced unparseable %q", c, got)
		}
		if v, err := expr.Eval(other).BoolValue(); err == nil && v {
			t.Errorf("%q -> %q matches another user's job", c, got)
		}
		if c == "" || c == "JobStatus == 2" {
			if v, err := expr.Eval(mine).BoolValue(); err != nil || !v {
				t.Errorf("%q -> %q does not match the caller's own job", c, got)
			}
		}
	}
	for _, bad := range []string{"true) || (true", "(", `User == "x`} {
		if got, err := Constrain("User", "alice@d", bad); err == nil {
			t.Errorf("%q accepted as %q; an unparseable constraint must be refused", bad, got)
		}
	}
	if _, err := Constrain("User", "", "true"); err == nil {
		t.Error("an empty owner must be refused, not scoped to User == \"\"")
	}
	if got, _ := Constrain("Owner", `a"b\c`, ""); got != `Owner == "a\"b\\c"` {
		t.Errorf("escaping: %s", got)
	}
}
