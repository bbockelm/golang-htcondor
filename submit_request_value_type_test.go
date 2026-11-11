package htcondor

import (
	"strings"
	"testing"
)

// TestRequestResourceClauseFollowsTheValueType pins which request_<tag>
// values put a clause in Requirements.
//
// condor_submit EVALUATES the request and switches on the TYPE of the
// result (SubmitHash::SetRequirements, through LookupType), not on what
// the submit file wrote. Only a number or undefined asks for a count,
// and only a string asks for a pattern; a boolean, a list, a nested ad
// or an error constrains nothing.
//
// Go tested the written expression for a literal instead, so anything
// that was not one got the count clause -- `request_gpus = !0` put
// `TARGET.Gpus >= RequestGpus` on a job condor_submit leaves
// unconstrained, and `request_gpus = 1 - 1` asked for a GPU where
// `request_gpus = 0` asks for none.
//
// `request_gpus = undefined` is not one of these cases: both sides read
// it as "no request at all" and write no attribute, so there is nothing
// to switch on. The undefined branch is reached by an attribute that IS
// written and evaluates to undefined.
func TestRequestResourceClauseFollowsTheValueType(t *testing.T) {
	count := "(TARGET.Gpus >= RequestGpus)"
	pattern := "regexp(RequestGpus, TARGET.Gpus)"

	for _, tc := range []struct {
		value string
		want  string // "" means no clause at all
	}{
		{"1", count},
		{"0.5", count},
		{"1 + 1", count},
		{"NoSuchThing", count}, // evaluates to undefined, which is not a number
		{"RequestCpus", count}, // evaluates to an integer on this ad

		{"0", ""},
		{"-1", ""},
		{"1 - 1", ""}, // evaluated, so it is the same as 0

		{`"x"`, pattern},
		{`strcat("a","b")`, pattern}, // evaluated, so it is the same as "ab"
		{`""`, ""},

		{"!0", ""},    // boolean
		{"true", ""},  // boolean
		{"{1}", ""},   // list
		{"[a=1]", ""}, // nested ad
		{"1/0", ""},   // error
	} {
		t.Run(tc.value, func(t *testing.T) {
			ad := adFor(t, "executable = /bin/true\nrequest_gpus = "+tc.value+"\nqueue\n")
			req := ad["Requirements"]
			hasCount := strings.Contains(req, "TARGET.Gpus >= RequestGpus")
			hasPattern := strings.Contains(req, "regexp(RequestGpus")
			switch tc.want {
			case count:
				if !hasCount {
					t.Errorf("Requirements = %s, want the count clause", req)
				}
			case pattern:
				if !hasPattern {
					t.Errorf("Requirements = %s, want the pattern clause", req)
				}
			default:
				if hasCount || hasPattern {
					t.Errorf("Requirements = %s, want no clause for RequestGpus", req)
				}
			}
		})
	}
}
