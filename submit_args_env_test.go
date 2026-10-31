package htcondor

import (
	"strings"
	"testing"
)

// adString renders what the job ad holds for a string attribute: the ClassAd
// text escapes an embedded double quote, which the wanted values here do not.
func adString(want string) string {
	return `"` + strings.ReplaceAll(want, `"`, `\"`) + `"`
}

// TestArgumentsAttributeNameFollowsTheInput pins which of the two attribute
// names a job's command line lands in.
//
// Args is V1 -- split on whitespace, a backslash escapes a quote -- and
// Arguments is V2, where single quotes group an argument containing spaces.
// The starter splits the two differently, so the NAME is semantic: writing
// the V1 name around a V2 string hands the job a different command line.
//
// The empty case is the one that was wrong. A submit file that says nothing
// about arguments gets `Arguments = ""`, the V2 name, because an empty
// ArgList was never V1 input; Go wrote `Args = ""`.
func TestArgumentsAttributeNameFollowsTheInput(t *testing.T) {
	for _, tc := range []struct{ name, src, attr, want string }{
		{"nothing said", "", "Arguments", ""},
		{"empty value", "arguments = ", "Arguments", ""},
		{"V1 input", "arguments = a b c", "Args", "a b c"},
		{"V1 under the attribute name", "args = x y", "Args", "x y"},
		{"V1 backslash escape", `arguments = a\"b`, "Args", `a"b`},
		{"V2 input", `arguments = "a b c"`, "Arguments", "a b c"},
		{"V2 regrouped per character", `arguments = "a 'b c' d"`, "Arguments", "a b' 'c d"},
		// Canonicalised as it is parsed: the doubled space is one
		// separator, not part of an argument.
		{"V1 doubled space", "arguments = a  b", "Args", "a b"},
		{"V2 doubled space", `arguments = "a  b"`, "Arguments", "a b"},
		{"arguments2 is always V2", `arguments2 = "a b"`, "Arguments", "a b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := adFor(t, "executable = /bin/true\n"+tc.src+"\nqueue\n")
			if got := ad[tc.attr]; got != adString(tc.want) {
				t.Errorf("%s = %s, want %q", tc.attr, got, tc.want)
			}
			other := "Args"
			if tc.attr == "Args" {
				other = "Arguments"
			}
			if got, ok := ad[other]; ok {
				t.Errorf("%s = %s as well; only one of the two is written", other, got)
			}
		})
	}

	// Both keywords at once needs allow_arguments_v1, and then V2 wins.
	mustReject(t, "executable = /bin/true\narguments = a b\narguments2 = \"c d\"\nqueue\n")
	ad := adFor(t, "executable = /bin/true\narguments = a b\narguments2 = \"c d\"\nallow_arguments_v1 = true\nqueue\n")
	if got := ad["Arguments"]; got != `"c d"` {
		t.Errorf("Arguments = %s, want the arguments2 value", got)
	}
}

// TestEnvironmentIsReEncoded pins that the environment is converted rather
// than passed through.
//
// The submit file writes V1 (`A=1;B=2`, delimiter auto-detected) or V2 (the
// list in double quotes); the ad carries Environment in V2 RAW, where each
// entry is quoted per CHARACTER -- `A=x y` is stored as `A=x' 'y` -- or Env
// in V1 raw with an EnvDelim beside it. Storing the submit text as the
// attribute loses the environment quietly: the job runs, with variables named
// things like `"PATH`.
//
// The sort and the de-duplication are not cosmetic either. C++ holds the
// variables in a std::map, so the attribute it writes is in name order with
// a repeated name collapsed to its last value, whatever order the submit file
// used -- and anything comparing a Go-built ad with a condor_submit-built one
// reads the text, not the set.
func TestEnvironmentIsReEncoded(t *testing.T) {
	for _, tc := range []struct{ name, src, attr, want string }{
		{"nothing said", "", "Environment", ""},
		{"V1 becomes V2", "environment = A=1;B=2", "Environment", "A=1 B=2"},
		{"V1 is sorted by name", "environment = B=2;A=1", "Environment", "A=1 B=2"},
		{"a repeated name keeps its last value", "environment = A=1;A=2", "Environment", "A=2"},
		{"the delimiter can be announced", "environment = |A=1|B=2", "Environment", "A=1 B=2"},
		{"V2 input", `environment = "A=1 B=2"`, "Environment", "A=1 B=2"},
		{"V2 value with a space", `environment = "A='x y' B=2"`, "Environment", "A=x' 'y B=2"},
		{"environment2 is always V2", `environment2 = "A=1 B=2"`, "Environment", "A=1 B=2"},
		{"the env keyword prefers V1", "env = A=1;B=2", "Env", "A=1;B=2"},
		{"the env keyword with a V2 value does not", `env = "A=1 B=2"`, "Environment", "A=1 B=2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := adFor(t, "executable = /bin/true\n"+tc.src+"\nqueue\n")
			if got := ad[tc.attr]; got != adString(tc.want) {
				t.Errorf("%s = %s, want %q", tc.attr, got, tc.want)
			}
		})
	}

	// The V1 attribute comes with the delimiter that was used, which is how
	// the reader knows how to split it back apart.
	ad := adFor(t, "executable = /bin/true\nenv = A=1;B=2\nqueue\n")
	if got := ad["EnvDelim"]; got != `";"` {
		t.Errorf("EnvDelim = %s, want \";\"", got)
	}

	// An entry that is not NAME=VALUE is a submit error, not a variable.
	mustReject(t, "executable = /bin/true\nenvironment = \"PLAIN\"\nqueue\n")
	mustReject(t, "executable = /bin/true\nenvironment = A=1;PLAIN\nqueue\n")
	mustReject(t, "executable = /bin/true\nenvironment = A=1\nenvironment2 = \"B=2\"\nqueue\n")
}
