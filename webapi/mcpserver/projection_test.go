package mcpserver

import (
	"context"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestListingToolsDeclareABoundedDefault is the regression test for a
// bug that shipped for a year without anyone noticing.
//
// The tools' `projection` documentation named a default set — "Default:
// ClusterId, ProcId, Owner, JobStatus, ..." — from the commit that
// introduced them. No code ever applied it. An unprojected query sends
// no Projection, and the schedd answers with the whole ad: 71
// attributes and 2.1KB of JSON for a trivial /bin/sleep job, far more
// for a real one carrying Environment and transfer lists. So every
// listing quietly returned everything while claiming otherwise, and a
// caller reading the description had no reason to set a projection.
//
// A row cap does not help: capping 500 rows of unbounded columns bounds
// nothing. What makes the claim testable is that the description is now
// GENERATED from the same list the code applies, so this checks the
// property that failed — the promise and the behavior come from one
// place — rather than re-typing the list in a third.
func TestListingToolsDeclareABoundedDefault(t *testing.T) {
	sets := map[string][]string{
		"jobs":      defaultJobAttrs,
		"history":   defaultHistoryAttrs,
		"epochs":    defaultEpochAttrs,
		"transfers": defaultTransferAttrs,
	}
	for name, attrs := range sets {
		t.Run(name, func(t *testing.T) {
			if len(attrs) == 0 {
				t.Fatal("a working set that is empty is the bug: an empty projection means every attribute")
			}
			// Bounded, and recognizably so. The point is a working set,
			// not a second way to spell "everything".
			if len(attrs) > 40 {
				t.Errorf("working set has %d attributes, which is not a working set", len(attrs))
			}
			// Identity has to survive, or a caller cannot act on a row.
			for _, need := range []string{"ClusterId", "ProcId"} {
				if !contains(attrs, need) {
					t.Errorf("working set omits %s, so rows cannot be acted on", need)
				}
			}
			// The expensive fields are the whole reason for a default.
			for _, banned := range []string{"Environment", "Requirements", "TransferInput"} {
				if contains(attrs, banned) {
					t.Errorf("working set includes %s, which is exactly what makes an ad large", banned)
				}
			}

			// The documentation must describe this list, not another
			// one. Generated, so it cannot drift — asserted here so a
			// future hand-written description fails loudly.
			desc := describeProjection(attrs)
			for _, a := range attrs {
				if !strings.Contains(desc, a) {
					t.Errorf("description does not mention %s, which the code applies", a)
				}
			}
		})
	}
}

// TestProjectionOrDefaultResolution: the three ways a caller can leave
// the projection, and what each has to produce.
func TestProjectionOrDefaultResolution(t *testing.T) {
	t.Run("unset gets the working set", func(t *testing.T) {
		got, note := projectionOrDefault(nil, defaultJobAttrs)
		if len(got) != len(defaultJobAttrs) {
			t.Errorf("unset projection = %v, want the working set", got)
		}
		if note != "" {
			t.Errorf("a default projection should need no explanation, got %q", note)
		}
	})

	t.Run("explicit is honored", func(t *testing.T) {
		got, _ := projectionOrDefault([]string{"Owner"}, defaultJobAttrs)
		if len(got) != 1 || got[0] != "Owner" {
			t.Errorf("explicit projection = %v, want [Owner]", got)
		}
	})

	t.Run("star means everything, and says what that costs", func(t *testing.T) {
		got, note := projectionOrDefault([]string{"*"}, defaultJobAttrs)
		// nil projection is how "no Projection attribute" reaches the
		// schedd, which is what returns the whole ad.
		if got != nil {
			t.Errorf(`["*"] should send no projection, got %v`, got)
		}
		if !strings.Contains(note, "expensive") && !strings.Contains(note, "kilobytes") {
			t.Errorf("asking for everything should say what it costs, got %q", note)
		}
	})
}

// TestDefaultAttrsForMatchesTheRecord: epochs and transfers are not
// jobs. Handing them the job working set would return rows that are
// mostly empty, which looks like missing data rather than a wrong
// projection.
func TestDefaultAttrsForMatchesTheRecord(t *testing.T) {
	if !contains(defaultAttrsFor(htcondor.HistorySourceJobEpoch), "EpochNumber") {
		t.Error("epoch records without EpochNumber cannot be told apart")
	}
	if !contains(defaultAttrsFor(htcondor.HistorySourceTransfer), "TransferType") {
		t.Error("transfer records without TransferType cannot be told apart")
	}
	if !contains(defaultAttrsFor(htcondor.HistorySourceJobHistory), "CompletionDate") {
		t.Error("completed jobs without CompletionDate lose when they finished")
	}
}

// TestToolDescriptionsCarryTheirDefaults walks the advertised catalog
// and checks every projection description names real attributes. This
// is the check that would have caught the original bug from the
// outside: the catalog is what a model reads.
func TestToolDescriptionsCarryTheirDefaults(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	s := &Server{schedd: htcondor.NewSchedd("test_schedd", "127.0.0.1:1"), logger: logger}

	listed, ok := s.handleListTools(context.Background(), nil).(map[string]interface{})
	if !ok {
		t.Fatal("tools/list did not return an object")
	}
	tools, ok := listed["tools"].([]Tool)
	if !ok {
		t.Fatalf("tools/list has no tool slice: %#v", listed)
	}

	checked := 0
	for _, tool := range tools {
		schema, ok := tool.InputSchema["properties"].(map[string]interface{})
		if !ok {
			continue
		}
		proj, ok := schema["projection"].(map[string]interface{})
		if !ok {
			continue
		}
		desc, _ := proj["description"].(string)
		checked++
		if !strings.Contains(desc, "ClusterId") {
			t.Errorf("%s: projection description names no default attributes: %q", tool.Name, desc)
		}
		if !strings.Contains(desc, "expensive") {
			t.Errorf("%s: projection description does not warn what ['*'] costs: %q", tool.Name, desc)
		}
	}
	if checked == 0 {
		t.Fatal("no tool advertises a projection; this test is checking nothing")
	}
	t.Logf("checked %d tools advertising a projection", checked)
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
