package mcpserver

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/htcondor/golang-htcondor/webapi/issues"
)

// A schema's typed fields are only checked where a test produces a value
// for them, and most results tests assert on are empty ones. These
// fixtures populate the nested trees that no other test reaches, so the
// published types are checked against real values rather than against
// nothing. See schema_assert_test.go for the net these sit inside.

// declaredLeaves walks a published schema and returns every typed leaf
// path, in the same spelling populatedLeaves uses: ".a.b[].c".
func declaredLeaves(node map[string]interface{}, path string, out map[string]string) {
	switch node["type"] {
	case "object":
		props, _ := node["properties"].(map[string]interface{})
		for name, raw := range props {
			if child, ok := raw.(map[string]interface{}); ok {
				declaredLeaves(child, path+"."+name, out)
			}
		}
	case "array":
		if items, ok := node["items"].(map[string]interface{}); ok {
			declaredLeaves(items, path+"[]", out)
		}
	case "string", "integer", "number", "boolean":
		out[path] = node["type"].(string)
	}
	// A node with no "type" is deliberately open (an ad, a free-form
	// map); there is nothing to pin.
}

// populatedLeaves walks a marshalled payload and returns every path that
// carried an actual scalar. An empty array or object contributes nothing:
// that is the whole point -- an empty result typechecks against any
// element schema, correct or not.
func populatedLeaves(v interface{}, path string, out map[string]bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			populatedLeaves(child, path+"."+k, out)
		}
	case []interface{}:
		for _, child := range t {
			populatedLeaves(child, path+"[]", out)
		}
	case nil:
	default:
		out[path] = true
	}
}

// assertEveryDeclaredFieldPopulated fails naming each typed field of the
// tool's schema that the payload left without a value, so a fixture that
// stops covering part of the tree says so instead of quietly passing.
func assertEveryDeclaredFieldPopulated(t *testing.T, tool string, structured interface{}) {
	t.Helper()
	schema := outputSchemaFor(tool)
	if schema == nil {
		t.Fatalf("tool %q publishes no output schema", tool)
	}
	declared := map[string]string{}
	declaredLeaves(schema, "", declared)

	raw, err := json.Marshal(structured)
	if err != nil {
		t.Fatalf("%s: marshalling the payload: %v", tool, err)
	}
	var instance interface{}
	if err := json.Unmarshal(raw, &instance); err != nil {
		t.Fatalf("%s: unmarshalling the payload: %v", tool, err)
	}
	populated := map[string]bool{}
	populatedLeaves(instance, "", populated)

	var missing []string
	for path := range declared {
		if !populated[path] {
			missing = append(missing, path+" ("+declared[path]+")")
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%s: the fixture leaves %d declared field(s) without a value, so their published "+
			"types are unchecked; populate them here:\n  %v", tool, len(missing), missing)
	}
}

// fullyPopulatedCluster is one issues.Cluster with every nested list
// non-empty, so each published type under sections[].clusters[] is
// checked against a real value.
func fullyPopulatedCluster() issues.Cluster {
	return issues.Cluster{
		Kind:     issues.KindHold,
		Template: "Error from slot1@node*.example.edu: Failed to open '*' as standard output: *",
		Count:    2536,
		Users:    7,
		TopUsers: []issues.OwnerCount{{Owner: "alice", Count: 1800}, {Owner: "bob", Count: 736}},
		Schedds:  []issues.ScheddCount{{Schedd: "ap2001.chtc.wisc.edu", Count: 2536}},
		Codes: []issues.CodeCount{
			{Code: 13, SubCode: 2, Label: "Failed to initialize user log", Count: 2500},
			{Code: 6, SubCode: 0, Count: 36},
		},
		FirstSeen: 1763200000,
		LastSeen:  1763203600,
		Timeline:  []int{0, 12, 480, 1200, 844},
		Examples: []issues.Example{{
			Cluster: 4815162,
			Proc:    23,
			Schedd:  "ap2001.chtc.wisc.edu",
			Owner:   "alice",
			Batch:   "fold-run-7",
			At:      1763203100,
			Message: "Failed to open '/home/alice/out/run7.log' as standard output: No such file or directory",
		}},
		Facets: []issues.FacetSpread{{
			Name:     "MachineAttrGLIDEIN_ResourceName0",
			Distinct: 1,
			Top:      []issues.FacetValue{{Value: "WISC-PATH-EP", Count: 2536}},
		}},
		Variants: []issues.Variant{
			{Template: "Failed to open '*' as standard output: *", Count: 2500},
			{Template: "Failed to open '*' as standard error: *", Count: 36},
		},
	}
}

// TestAnalyzeIssuesPopulatedSectionValidates pins the published types of
// the analyze_issues cluster tree -- the widest in this server, and the
// one no other test ever fills in. Every result the suite produced for
// this tool before this fixture carried `"sections": []`, which
// typechecks against any element schema at all, right or wrong.
//
// It drives issueSectionResult, the same mapping the handler uses, so
// what is validated here is what a client receives.
func TestAnalyzeIssuesPopulatedSectionValidates(t *testing.T) {
	cluster := fullyPopulatedCluster()
	section := issueSectionView{
		kind:     issues.KindHold,
		title:    "Holds",
		total:    2536,
		users:    7,
		clusters: []issues.Cluster{cluster},
	}
	structured := map[string]interface{}{
		"window_seconds": int64(3600),
		"bucket_seconds": int64(3600) / issuesTimelineBuckets,
		"granularity":    0.4,
		"include_ended":  true,
		"source":         "schedd",
		"truncated":      false,
		"notes":          []string{"searched 2 access points"},
		"sections": []map[string]interface{}{
			issueSectionResult(section, []issues.Cluster{cluster}),
		},
	}

	validateStructured(t, "analyze_issues", structured)
	assertEveryDeclaredFieldPopulated(t, "analyze_issues", structured)
}
