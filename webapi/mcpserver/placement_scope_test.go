package mcpserver

import (
	"context"
	"errors"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/ownerscope"
)

// A placementd account outside UID_DOMAIN shares its Owner with the local
// user of the same name. Its queries are confined by User, and what is
// filed under the bare name -- watches, interactive sessions, share URLs
// -- is refused to it.
func TestPlacementdAccountScopedByUser(t *testing.T) {
	s := &Server{uidDomain: "uid.example"}
	placed := ownerscope.WithUserScope(htcondor.WithAuthenticatedUser(context.Background(), "alice@course.example"))

	scope, ok := s.ownerScope(placed, tierRead)
	if !ok || scope.Owner != "alice@course.example" {
		t.Fatalf("ownerScope = %+v, %v", scope, ok)
	}
	for name, got := range map[string]func() (string, error){
		"scopeToOwner":          func() (string, error) { return s.scopeToOwner(placed, "JobStatus == 1", tierRead) },
		"ownerScopedConstraint": func() (string, error) { return ownerScopedConstraint(scope, "JobStatus == 1") },
	} {
		c, err := got()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for user, want := range map[string]bool{"alice@course.example": true, "alice@uid.example": false} {
			if admitsUser(t, c, user) != want {
				t.Errorf("%s = %q admits %s: %v, want %v", name, c, user, !want, want)
			}
		}
	}

	if _, err := s.watchActor(placed); !errors.Is(err, errOutsideUIDDomain) {
		t.Errorf("watchActor = %v, want errOutsideUIDDomain", err)
	}
	if _, err := s.localJobCaller(placed); !errors.Is(err, errOutsideUIDDomain) {
		t.Errorf("localJobCaller = %v, want errOutsideUIDDomain", err)
	}

	// The same name, not assigned by the placementd: Owner, as before.
	local := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.example")
	if c, err := s.scopeToOwner(local, "", tierRead); err != nil || c != `Owner == "alice"` {
		t.Errorf("a local caller's scope = %q, %v", c, err)
	}
	if _, err := s.watchActor(local); err != nil {
		t.Errorf("watchActor refused a local caller: %v", err)
	}
}

// admitsUser evaluates c against a job of user, whose Owner is the part
// before the "@".
func admitsUser(t *testing.T, c, user string) bool {
	t.Helper()
	ad, err := classad.ParseOld(`User = "` + user + `"` + "\nOwner = \"alice\"\nJobStatus = 1")
	if err != nil {
		t.Fatal(err)
	}
	expr, err := classad.ParseExpr(c)
	if err != nil {
		t.Fatalf("%q does not parse: %v", c, err)
	}
	b, _ := expr.Eval(ad).BoolValue()
	return b
}
