package htcondor

import (
	"strings"
	"testing"
)

// TestItemListIsExpandedBeforeItIsSplit pins that an inline `queue ... in (...)`
// list is expanded as one piece of text and cut afterwards, rather than cut
// first and expanded piece by piece. The two differ whenever expanding changes
// where the cuts fall, which the fuzzer found with `queue in(0 $())`: the
// empty macro was one item here and none under condor_submit.
//
// Every expectation was measured against HTCondor's own parser (SubmitHash).
func TestItemListIsExpandedBeforeItIsSplit(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{{
		name: "a macro expanding to nothing is no item",
		src:  "A=\nqueue in(0 $(A))",
		want: []string{`"0"`},
	}, {
		name: "an undefined macro is no item",
		src:  "queue in(0 $(nosuch))",
		want: []string{`"0"`},
	}, {
		name: "an empty reference is no item",
		src:  "queue in(0 $())",
		want: []string{`"0"`},
	}, {
		name: "an empty reference first is no item",
		src:  "queue in($() 0)",
		want: []string{`"0"`},
	}, {
		name: "every item empty leaves the one that is not",
		src:  "queue in($() $() z)",
		want: []string{`"z"`},
	}, {
		name: "a macro holding two words is two items",
		src:  "A=x y\nqueue in($(A) b)",
		want: []string{`"x"`, `"y"`, `"b"`},
	}, {
		name: "a macro holding a comma list is two items",
		src:  "A=x,y\nqueue in($(A) b)",
		want: []string{`"x"`, `"y"`, `"b"`},
	}, {
		name: "a macro holding one word is one item",
		src:  "A=x\nqueue in($(A) b)",
		want: []string{`"x"`, `"b"`},
	}, {
		name: "an empty macro inside a word splits nothing",
		src:  "queue in(a$()b c)",
		want: []string{`"ab"`, `"c"`},
	}, {
		name: "a list with no macros is unchanged",
		src:  "queue in(0 1)",
		want: []string{`"0"`, `"1"`},
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := argsOf(t, "executable = /bin/sleep\narguments = $(item)\n"+c.src+"\n")
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("%q queued %v, want %v", c.src, got, c.want)
			}
		})
	}
}
