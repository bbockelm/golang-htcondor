//go:build libcondor_utils

package fuzzsubmit

import (
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// TestSimpleKeywordTableMatchesOracle checks the Go parser's copy of
// HTCondor's simple submit-keyword table against the table the linked
// libcondor_utils actually carries.
//
// The Go table is what decides, for every keyword SubmitHash hands to
// do_simple_commands, which job attribute the value lands in and what shape it
// takes there -- string, list, boolean, integer or expression, with or without
// the surrounding quotes. Transcribing that by hand is only safe if something
// checks the transcription, and HTCondor's own table is the only authority:
// get_submit_keywords() returns it, flags and all.
//
// A keyword added upstream fails this test as a missing row, which is the
// point: it is cheaper to add the row than to find out from a job ad that a
// setting went nowhere.
func TestSimpleKeywordTableMatchesOracle(t *testing.T) {
	requireOracle(t)

	type row struct {
		attr string
		opts int
	}
	want := make(map[string]row)
	for _, kw := range oracle.Keywords() {
		// do_simple_commands stops at the first f_special keyword; the
		// rest are each handled by their own SetXXX method and are not
		// this table's business.
		if kw.Key == "" || kw.Opts&oracle.KeySpecial != 0 {
			continue
		}
		want[kw.Key] = row{attr: kw.Attr, opts: kw.Opts}
	}

	got := make(map[string]row)
	for _, kw := range htcondor.SimpleSubmitKeywords() {
		if _, dup := got[kw.Key]; dup {
			t.Errorf("%s appears twice in the Go table", kw.Key)
		}
		got[kw.Key] = row{attr: kw.Attr, opts: kw.Opts}
	}

	for key, w := range want {
		g, ok := got[key]
		if !ok {
			t.Errorf("%s is in HTCondor's table (%s, opts %#x) and not in the Go one: the setting is dropped", key, w.attr, w.opts)
			continue
		}
		if g != w {
			t.Errorf("%s: Go has (%s, opts %#x), HTCondor has (%s, opts %#x)", key, g.attr, g.opts, w.attr, w.opts)
		}
	}
	for key, g := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("%s is in the Go table (%s, opts %#x) and is not a non-special keyword of HTCondor's", key, g.attr, g.opts)
		}
	}
}

// TestSimpleKeywordValueShapes pins one keyword per value-type flag against
// the oracle, on a submit file written for that keyword alone.
//
// The table check above proves the Go side has the right flags; this proves
// the flags are ACTED on -- that f_as_list really canonicalizes separators,
// that a plain f_as_string really does not, that f_strip_quotes removes the
// quotes and that the integer and boolean types are read the way HTCondor
// reads them. Each case names the flag it stands for, so a shape that stops
// being applied fails here with the flag's name rather than as one more
// attribute in a sweep.
func TestSimpleKeywordValueShapes(t *testing.T) {
	requireOracle(t)

	cases := []struct {
		name string
		body string
	}{
		{"f_as_list canonicalizes separators", "email_attributes = Owner,  JobStatus ,QDate"},
		{"f_as_string keeps the value verbatim", "encrypt_input_files = a.txt, b.txt,  c.txt"},
		{"f_strip_quotes drops the surrounding quotes", `batch_name = "nightly run"`},
		{"f_strip_quotes leaves an unquoted value alone", "batch_name = nightly"},
		{"f_as_bool reads a word", "run_as_owner = TRUE"},
		{"f_as_bool reads an expression", "skip_if_dataflow = 2 > 1"},
		{"f_as_int reads an expression", "core_size = 3 * 7"},
		{"f_as_uint reads a plain number", "dagman_job_id = 42"},
		{"f_as_expr keeps the expression", "max_job_retirement_time = 3600 * 2"},
		{"an empty value sets nothing", "batch_name ="},
		{"f_alt_name defers to the primary spelling", "max_idle = 3\nmaterialize_max_idle = 9"},
		{"f_alt_name is used when the primary is absent", "materialize_max_idle = 9"},
		{"the attribute name is a second spelling", "JobPrio = 7"},
		{"the submit command outranks the attribute name", "priority = 3\nJobPrio = 7"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := "executable = /bin/true\n" + tc.body + "\nqueue\n"
			fresh, _, skip := check(t, text)
			if skip {
				t.Fatalf("not comparable; one side rejected:\n%s", text)
			}
			for _, d := range fresh {
				t.Errorf("%s\n--- submit file ---\n%s", d, text)
			}
		})
	}
}
