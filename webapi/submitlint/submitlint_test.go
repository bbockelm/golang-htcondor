package submitlint

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// TestInspectSubmitFileSystemExecutableFatal covers the combination
// that has no working outcome: a machine-owned executable path left at
// the default transfer_executable = true.
func TestInspectSubmitFileSystemExecutableFatal(t *testing.T) {
	for _, exe := range []string{
		"/bin/bash",
		"/usr/bin/python3",
		"/usr/local/bin/analyze",
		"/cvmfs/atlas.cern.ch/repo/sw/setup.sh",
	} {
		insp := Inspect("executable = " + exe + "\nshould_transfer_files = YES\nqueue 1\n")
		if insp.Fatal == nil {
			t.Fatalf("executable = %s with default transfer_executable: expected a fatal diagnostic, got none (warnings: %v)", exe, insp.Warnings)
		}
		msg := insp.Fatal.Error()
		for _, want := range []string{exe, "transfer_executable = False"} {
			if !strings.Contains(msg, want) {
				t.Errorf("executable = %s: fatal message %q does not mention %q", exe, msg, want)
			}
		}
	}
}

// TestInspectSubmitFileSystemExecutableAccepted checks the fatal
// diagnostic does not fire once the caller has done the right thing, and
// that turning the transfer off also turns off the spooling round.
func TestInspectSubmitFileSystemExecutableAccepted(t *testing.T) {
	insp := Inspect("executable = /bin/bash\ntransfer_executable = False\narguments = -c \\\"echo hi\\\"\n" +
		"output = out.txt\nerror = err.txt\nlog = job.log\n" + "queue 1\n")
	if insp.Fatal != nil {
		t.Fatalf("transfer_executable = False should be accepted, got: %v", insp.Fatal)
	}
	if len(insp.Warnings) != 0 {
		t.Errorf("expected no warnings, got %v", insp.Warnings)
	}
	if insp.NeedsSpooling {
		t.Error("a system executable with transfer_executable = False needs no upload_job_input round")
	}
}

// TestInspectSubmitFileRelativeExecutable is the recommended shape: a
// bare filename the caller uploads with upload_job_input.
func TestInspectSubmitFileRelativeExecutable(t *testing.T) {
	insp := Inspect("executable = run.sh\n" + "output = out.txt\nerror = err.txt\nlog = job.log\n" + "queue 1\n")
	if insp.Fatal != nil {
		t.Fatalf("unexpected fatal: %v", insp.Fatal)
	}
	if len(insp.Warnings) != 0 {
		t.Errorf("expected no warnings, got %v", insp.Warnings)
	}
	if !insp.NeedsSpooling {
		t.Error("a transferred executable needs an upload_job_input round")
	}
}

// TestInspectSubmitFileAbsoluteNonSystemExecutable warns rather than
// rejects: uploading a file named after the basename does make this
// submit file work.
func TestInspectSubmitFileAbsoluteNonSystemExecutable(t *testing.T) {
	insp := Inspect("executable = /home/alice/run.sh\n" + "output = out.txt\nerror = err.txt\nlog = job.log\n" + "queue 1\n")
	if insp.Fatal != nil {
		t.Fatalf("a non-system absolute path should warn, not reject: %v", insp.Fatal)
	}
	if len(insp.Warnings) != 1 {
		t.Fatalf("expected exactly one warning, got %v", insp.Warnings)
	}
	if !strings.Contains(insp.Warnings[0], `"run.sh"`) {
		t.Errorf("warning should name the basename to upload, got %q", insp.Warnings[0])
	}
}

// TestInspectSubmitFileUndefinedMacroInArguments is the reported case:
// shell command substitution eaten by the submit parser.
func TestInspectSubmitFileUndefinedMacroInArguments(t *testing.T) {
	raw := "executable = /bin/bash\ntransfer_executable = False\n" +
		"arguments = \"-c 'echo HOST:$(hostname); date +%s'\"\n" +
		"output = out.txt\nerror = err.txt\nlog = job.log\n" + "queue 1\n"
	insp := Inspect(raw)
	if insp.Fatal != nil {
		t.Fatalf("unexpected fatal: %v", insp.Fatal)
	}
	if len(insp.Warnings) != 1 {
		t.Fatalf("expected one warning about $(hostname), got %v", insp.Warnings)
	}
	w := insp.Warnings[0]
	for _, want := range []string{"arguments", "$(hostname)", "empty string", "upload_job_input"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning %q does not mention %q", w, want)
		}
	}
}

// TestWarnUndefinedMacrosQuiet pins down what must NOT be reported:
// macros the submit file defines, live per-job macros, queue variables,
// defaulted references, and $$(...) deferred to matchmaking. Several of
// these lean on the config grammar (comments, line continuations,
// conditional branches, `queue VARS from`), so they double as a check
// that the lint reads the submit file the way the submit parser does.
func TestWarnUndefinedMacrosQuiet(t *testing.T) {
	cases := map[string]string{
		"submit-file macro":    "MyDir = /data\narguments = $(MyDir)/in.txt\nqueue 1\n",
		"case-insensitive":     "MYDIR = /data\narguments = $(mydir)/in.txt\nqueue 1\n",
		"defined after use":    "arguments = $(later)\nlater = fine\nqueue 1\n",
		"defined in if branch": "if defined FOO\n  bar = 1\nendif\narguments = $(bar)\nqueue 1\n",
		"defined in else":      "if false\n  x = 1\nelse\n  bar = 2\nendif\narguments = $(bar)\nqueue 1\n",
		"live macros":          "output = out.$(Cluster).$(Process).txt\nlog = j.$(ProcId).log\nqueue 1\n",
		"item macros":          "arguments = $(ItemIndex) $(Step) $(Row) $(Node) $(Item)\nqueue 1\n",
		"queue vars from file": "arguments = $(sample) $(nevents)\nqueue sample, nevents from samples.txt\n",
		"queue vars in list":   "arguments = $(sample)\nqueue sample in (a, b)\n",
		"defaulted macro":      "arguments = $(extra_args:--verbose)\nqueue 1\n",
		"deferred to match":    "arguments = $$(Cpus) $$([RequestMemory * 2])\nqueue 1\n",
		// `+MyLabel` defines $(MY.MyLabel), not $(MyLabel). Verified
		// against condor_submit, which expands
		// `bare[$(MyLabel)] prefixed[$(MY.MyLabel)]` to
		// `bare[] prefixed["x"]`. This case used to reference the bare
		// name and expect silence, which asserted the opposite of what
		// HTCondor does — and silence about a $(...) that expands to
		// nothing is the one thing this check exists to prevent.
		"plus attribute":       "+MyLabel = \"x\"\narguments = $(MY.MyLabel)\nqueue 1\n",
		"comment":              "# arguments = $(hostname)\narguments = fixed\nqueue 1\n",
		"comment continued":    "# a comment ending in a backslash \\\narguments = fixed\nqueue 1\n",
		"other dollar forms":   "arguments = $ENV(HOME) $(DOLLAR)\nqueue 1\n",
		"macro over two lines": "MyDir = /data\narguments = -c \\\n  \"ls $(MyDir)\"\nqueue 1\n",
	}
	for name, raw := range cases {
		// A submit file the grammar rejects yields no statements and
		// therefore no warnings, which would make these cases pass
		// without exercising anything. Check they really parse.
		if _, err := config.Parse(config.NewLexer(strings.NewReader(raw))); err != nil {
			t.Errorf("%s: submit file does not parse, so the quiet result proves nothing: %v", name, err)
			continue
		}
		if got := warnUndefinedMacros(raw); len(got) != 0 {
			t.Errorf("%s: expected no warnings, got %v", name, got)
		}
	}
}

// TestWarnUndefinedMacrosReported is the mirror of the quiet cases.
// Everything collapses into one warning — an agent that wrote one
// $(...) by mistake usually wrote several — so each case checks which
// references that warning names.
func TestWarnUndefinedMacrosReported(t *testing.T) {
	cases := map[string]struct {
		raw  string
		want []string
	}{
		"command substitution": {
			"arguments = -c \"echo $(hostname)\"\nqueue 1\n",
			[]string{"arguments references $(hostname)"},
		},
		"two names, one key": {
			"arguments = $(hostname) $(whoami)\nqueue 1\n",
			[]string{"arguments references $(hostname), $(whoami)"},
		},
		"same name twice": {
			"arguments = $(hostname) $(hostname)\nqueue 1\n",
			[]string{"arguments references $(hostname). "},
		},
		"two keys": {
			"arguments = $(hostname)\ntransfer_input_files = $(datafile)\nqueue 1\n",
			[]string{"arguments references $(hostname); transfer_input_files references $(datafile)"},
		},
		"plus attribute referenced without its prefix": {
			"+MyLabel = \"x\"\narguments = $(MyLabel)\nqueue 1\n",
			[]string{"arguments references $(MyLabel)"},
		},
		"non-arguments key": {
			"transfer_input_files = $(datafile)\nqueue 1\n",
			[]string{"transfer_input_files references $(datafile)"},
		},
		"line continuation": {
			"arguments = -c \\\n  \"echo $(hostname)\"\nqueue 1\n",
			[]string{"arguments references $(hostname)"},
		},
		"inside if branch": {
			"if true\n  arguments = $(hostname)\nendif\nqueue 1\n",
			[]string{"arguments references $(hostname)"},
		},
		"queue var not listed": {
			"arguments = $(sample)\nqueue 1\n",
			[]string{"arguments references $(sample)"},
		},
		"queue var from another queue statement": {
			"arguments = $(sample)\nqueue other from samples.txt\n",
			[]string{"arguments references $(sample)"},
		},
	}
	for name, tc := range cases {
		got := warnUndefinedMacros(tc.raw)
		if len(got) != 1 {
			t.Errorf("%s: expected exactly one warning, got %d: %v", name, len(got), got)
			continue
		}
		for _, want := range tc.want {
			if !strings.Contains(got[0], want) {
				t.Errorf("%s: warning %q does not contain %q", name, got[0], want)
			}
		}
	}
}

// TestWarnUndefinedMacrosPlural checks the warning does not read as a
// plural when it names a single reference.
func TestWarnUndefinedMacrosPlural(t *testing.T) {
	one := warnUndefinedMacros("arguments = $(hostname)\nqueue 1\n")
	if len(one) != 1 || !strings.Contains(one[0], "defines it,") {
		t.Errorf("single reference should read as singular, got %v", one)
	}
	two := warnUndefinedMacros("arguments = $(hostname) $(whoami)\nqueue 1\n")
	if len(two) != 1 || !strings.Contains(two[0], "defines them,") {
		t.Errorf("two references should read as plural, got %v", two)
	}
}

// TestWarnUndefinedMacrosUnparseable checks the lint stays quiet on a
// submit file the config grammar rejects: Inspect cannot
// build a job ad from it either, so the schedd answers instead.
func TestWarnUndefinedMacrosUnparseable(t *testing.T) {
	// An item list with no closing ')' is still rejected; a whitespace-
	// separated one is not, so it no longer serves as the unparseable case.
	if got := warnUndefinedMacros("arguments = $(hostname)\nqueue 2 sample in (a b\n"); got != nil {
		t.Errorf("expected no warnings from an unparseable submit file, got %v", got)
	}
}

// TestInspectSubmitFileUnparseable checks the conservative fallback: a
// submit file this package cannot parse is passed through to the schedd,
// which is the authority on what it accepts.
func TestInspectSubmitFileUnparseable(t *testing.T) {
	insp := Inspect("queue from ((\n")
	if insp.Fatal != nil {
		t.Errorf("an unparseable submit file must not be rejected locally: %v", insp.Fatal)
	}
	if !insp.NeedsSpooling {
		t.Error("expected the conservative needsSpooling default")
	}
}

// TestUndefinedMacroWarningKnowsTheCustomAttrNamespace: `+Foo = 1`
// defines $(MY.Foo), not $(Foo). The linter has to agree with the
// executor about that, in both directions — otherwise it either warns
// about a macro that works, or stays silent about one that silently
// expands to nothing, which is the single mistake this check exists to
// catch.
func TestUndefinedMacroWarningKnowsTheCustomAttrNamespace(t *testing.T) {
	t.Run("$(MY.Foo) resolves", func(t *testing.T) {
		warnings := warnUndefinedMacros("executable = /bin/true\n+Tag = \"nightly\"\narguments = $(MY.Tag)\nqueue\n")
		if len(warnings) != 0 {
			t.Errorf("warned about a macro that expands: %v", warnings)
		}
	})

	t.Run("$(Foo) does not", func(t *testing.T) {
		warnings := warnUndefinedMacros("executable = /bin/true\n+Tag = \"nightly\"\narguments = $(Tag)\nqueue\n")
		if len(warnings) == 0 {
			t.Fatal("no warning for $(Tag); +Tag defines $(MY.Tag), so $(Tag) expands to an empty string")
		}
		if !strings.Contains(warnings[0], "$(Tag)") {
			t.Errorf("warning does not name the reference: %v", warnings)
		}
	})

	t.Run("a plain macro still resolves", func(t *testing.T) {
		warnings := warnUndefinedMacros("executable = /bin/true\ntag = nightly\narguments = $(tag)\nqueue\n")
		if len(warnings) != 0 {
			t.Errorf("warned about an ordinary submit macro: %v", warnings)
		}
	})
}

// TestInspectNamesAnIneffectiveTransferExecutable pins the diagnostic for a
// trap this repository's own integration tests fell into.
//
// condor_submit turns the executable transfer off only for a
// transfer_executable whose FIRST CHARACTER is 'f' or 'F' -- SetExecutable
// tests exactly that -- so `transfer_executable = NO` leaves the transfer ON
// and a system-path executable is spool-copied from a submit directory that
// has no such file. The job then holds with "Transfer input files failure".
//
// Telling that caller the setting "is not set" sends them looking for a line
// they already wrote, so the message names the value back to them.
func TestInspectNamesAnIneffectiveTransferExecutable(t *testing.T) {
	insp := Inspect("executable = /bin/bash\ntransfer_executable = NO\nqueue 1\n")
	if insp.Fatal == nil {
		t.Fatal("transfer_executable = NO with a system executable should be rejected")
	}
	msg := insp.Fatal.Error()
	for _, want := range []string{"transfer_executable = NO", "does NOT turn the transfer off", "first character"} {
		if !strings.Contains(msg, want) {
			t.Errorf("rejection does not mention %q: %s", want, msg)
		}
	}

	// The wording for a caller who really did write nothing is unchanged.
	insp = Inspect("executable = /bin/bash\nqueue 1\n")
	if insp.Fatal == nil {
		t.Fatal("a system executable with no transfer_executable should be rejected")
	}
	if !strings.Contains(insp.Fatal.Error(), "is not set") {
		t.Errorf("rejection should say the setting is not set: %s", insp.Fatal)
	}
}
