package htcondor

import (
	"strings"
	"testing"
)

// The expected values here are what libcondor_utils 26.2.0 produced for the
// same submit files through the differential harness in fuzz/submit, not what
// the Go code happens to do. The two rules they pin both live in
// src/condor_utils/config.cpp:
//
//   - getline_implementation trims the whole line with isspace() before it is
//     split into name and value, so a carriage return never survives to the
//     end of a value and a submit file written on Windows means the same
//     thing as one written on Unix.
//   - a parameter name is the run of characters before the first whitespace
//     or operator, checked against is_valid_param_name(), whose charset is
//     condor_isidchar(): [A-Za-z0-9_./], with no restriction on the first
//     character. A name may therefore start with a digit.

func TestSubmitCarriageReturnsAreNotPartOfValues(t *testing.T) {
	ad := mustJobAd(t, "executable = /bin/sleep\r\nlog = j.log\r\narguments = a b\r\nqueue\r\n")

	cmd, ok := ad.Lookup("Cmd")
	if !ok {
		t.Fatal("Cmd missing from the job ad")
	}
	if got, want := cmd.String(), `"/bin/sleep"`; got != want {
		t.Errorf("Cmd = %s, want %s", got, want)
	}

	// UserLog is resolved against Iwd, so only its tail is fixed here; the
	// carriage return would land at the very end of it.
	log, ok := ad.Lookup("UserLog")
	if !ok {
		t.Fatal("UserLog missing from the job ad")
	}
	if got := log.String(); !strings.HasSuffix(got, `/j.log"`) {
		t.Errorf("UserLog = %s, want it to end in /j.log", got)
	}
}

// A carriage return that is not at the end of the line is not trailing
// whitespace, and HTCondor keeps it.
func TestSubmitInteriorCarriageReturnIsKept(t *testing.T) {
	ad := mustJobAd(t, "executable = /bin/sl\reep\nqueue\n")

	expr, ok := ad.Lookup("Cmd")
	if !ok {
		t.Fatal("Cmd missing from the job ad")
	}
	// Both unparsers escape it, so the text to compare carries a literal
	// backslash-r: C++ prints Cmd = "/bin/sl\reep" for the same file.
	if got, want := expr.String(), `"/bin/sl\reep"`; got != want {
		t.Errorf("Cmd = %s, want %s", got, want)
	}
}

// A carriage return between the operator and the value is leading whitespace,
// which HTCondor skips.
func TestSubmitLeadingCarriageReturnIsSkipped(t *testing.T) {
	ad := mustJobAd(t, "executable =\r/bin/sleep\nqueue\n")

	expr, ok := ad.Lookup("Cmd")
	if !ok {
		t.Fatal("Cmd missing from the job ad")
	}
	if got, want := expr.String(), `"/bin/sleep"`; got != want {
		t.Errorf("Cmd = %s, want %s", got, want)
	}
}

// A name HTCondor accepts must not take the rest of the file with it. Before
// the lexer knew these names, "0 = x" lexed as a number and the parse stopped
// there -- with no error, because a default reduction had already stored the
// statements read so far -- so every command after it vanished.
func TestSubmitMacroNamesOutsideIdentifierStart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		submit string
	}{
		{"leading digit", "executable = /bin/sleep\n0 = j\nlog = $(0).log\nqueue\n"},
		{"digit then letters", "executable = /bin/sleep\n0abc = j\nlog = $(0abc).log\nqueue\n"},
		{"leading underscore", "executable = /bin/sleep\n_x = j\nlog = $(_x).log\nqueue\n"},
		{"slash", "executable = /bin/sleep\na/b = j\nlog = $(a/b).log\nqueue\n"},
		{"dot", "executable = /bin/sleep\nfoo.bar = j\nlog = $(foo.bar).log\nqueue\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := mustJobAd(t, tc.submit)
			expr, ok := ad.Lookup("UserLog")
			if !ok {
				t.Fatal("UserLog missing: the assignment after the macro was dropped")
			}
			// Resolved against Iwd, so match the tail.
			if got := expr.String(); !strings.HasSuffix(got, `/j.log"`) {
				t.Errorf("UserLog = %s, want it to end in /j.log", got)
			}
		})
	}
}

// The same charset governs a job attribute name. `+Attr` and `MY.Attr` both
// end up as "MY." plus the scanned name, so an attribute may begin with a
// digit too; condor_submit sets `0` and `0.5` for these files.
func TestSubmitAttributeNamesOutsideIdentifierStart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		submit string
		attr   string
	}{
		{"plus digit", "executable = /bin/sleep\n+0 = 7\nqueue\n", "0"},
		{"plus digit then letters", "executable = /bin/sleep\n+0abc = 7\nqueue\n", "0abc"},
		{"plus dotted digits", "executable = /bin/sleep\n+0.5 = 7\nqueue\n", "0.5"},
		{"plus slash", "executable = /bin/sleep\n+a/b = 7\nqueue\n", "a/b"},
		{"my digit", "executable = /bin/sleep\nMY.0 = 7\nqueue\n", "0"},
		{"my digit then letters", "executable = /bin/sleep\nMY.0abc = 7\nqueue\n", "0abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := mustJobAd(t, tc.submit)
			expr, ok := ad.Lookup(tc.attr)
			if !ok {
				t.Fatalf("%s missing from the job ad", tc.attr)
			}
			if got, want := expr.String(), "7"; got != want {
				t.Errorf("%s = %s, want %s", tc.attr, got, want)
			}
		})
	}
}

// A character outside condor_isidchar()'s set makes the name illegal, and
// HTCondor rejects the whole submit file rather than skipping the line. The Go
// parser must report that rather than return a truncated file.
func TestSubmitIllegalMacroNameRejectsTheFile(t *testing.T) {
	if _, err := ParseSubmitFile(strings.NewReader("executable = /bin/sleep\na-b = 1\nlog = j.log\nqueue\n")); err == nil {
		t.Fatal("a-b = 1 was accepted; HTCondor fails the file")
	}
}

// Whatever else a syntax error does, it must not be reported as success with
// the rest of the file missing.
func TestSubmitSyntaxErrorDoesNotTruncateSilently(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/sleep\n&& = 1\nlog = j.log\nqueue\n"))
	if err != nil {
		return
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, map[string]string{})
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	if _, ok := ad.Lookup("UserLog"); !ok {
		t.Fatal("the file parsed without error but lost every command after the bad line")
	}
}
