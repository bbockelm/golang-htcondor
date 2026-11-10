package interactive

import (
	"context"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/submitpolicy"
)

// A ClassAd expression may span lines and still parse, but requirements
// is spliced onto one submit-file line, where a line break would start a
// command of the caller's choosing. Such a session is refused before
// anything is submitted; a one-line expression still reaches the job.
func TestCreateRefusesRequirementsWithALineBreak(t *testing.T) {
	const multiLine = "true ||\nfoo =?= bar"
	if _, err := classad.ParseExpr(multiLine); err != nil {
		t.Fatalf("fixture: %q must parse as ClassAd, or this proves nothing: %v", multiLine, err)
	}

	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "multi", Requirements: multiLine}); err == nil {
		t.Error("requirements with a line break was accepted")
	}
	if n := len(schedd.submittedFiles()); n != 0 {
		t.Fatalf("%d submit file(s) reached the schedd", n)
	}

	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "single", Requirements: "TARGET.HasDocker"}); err != nil {
		t.Fatalf("one-line requirements refused: %v", err)
	}
	files := schedd.submittedFiles()
	if len(files) != 1 || !strings.Contains(files[0], "TARGET.HasDocker") {
		t.Errorf("one-line requirements did not reach the submit file: %q", files)
	}
}

// Caller submit lines are the user's; one that sets, as a custom
// attribute, an attribute the site overrides control is refused before
// the schedd sees it.
func TestCreateRefusesSubmitLinesThatBeatAnOverride(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{
		SubmitPolicy: submitpolicy.Policy{Overrides: "accounting_group = grp_site"},
	})
	_, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "acct",
		SubmitLines: `+AccountingGroup = "evil"`})
	if err == nil {
		t.Error("submit lines setting +AccountingGroup were accepted under an accounting_group override")
	}
	if n := len(schedd.submittedFiles()); n != 0 {
		t.Fatalf("%d submit file(s) reached the schedd", n)
	}
}
