package submitlint

import (
	"strings"
	"testing"
)

// clean is a submit file with nothing wrong with it, used as the base for
// the cases below so each one varies exactly the thing under test.
const clean = "executable = run.sh\noutput = run.out\nerror = run.err\nlog = run.log\nqueue 1\n"

// TestCleanSubmitFileHasNoOutputWarning anchors the rest: if this fires,
// every other case in this file is passing for the wrong reason.
func TestCleanSubmitFileHasNoOutputWarning(t *testing.T) {
	if got := Inspect(clean).Warnings; len(got) != 0 {
		t.Fatalf("a submit file that sets all three streams should warn about nothing, got %v", got)
	}
}

// TestInspectWarnsWhenOutputIsDiscarded is the reported case: an assistant
// asked for a job template wrote one whose stdout and stderr went to
// /dev/null and which had no log, and nothing anywhere said so. The job
// ran, produced nothing anyone could read, and the only way to find out
// what it had printed was to run it again.
func TestInspectWarnsWhenOutputIsDiscarded(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "nothing set at all",
			raw:  "executable = run.sh\nqueue 1\n",
			want: []string{"output is /dev/null", "error is /dev/null", "log is not set"},
		},
		{
			name: "explicit /dev/null",
			raw:  "executable = run.sh\noutput = /dev/null\nerror = /dev/null\nlog = run.log\nqueue 1\n",
			want: []string{"output is /dev/null", "error is /dev/null"},
		},
		{
			name: "output kept, log forgotten",
			raw:  "executable = run.sh\noutput = run.out\nerror = run.err\nqueue 1\n",
			want: []string{"log is not set", "nothing records when the job started"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warnings := strings.Join(Inspect(tc.raw).Warnings, "\n")
			if warnings == "" {
				t.Fatal("no warning at all for a submit file that discards its output")
			}
			for _, want := range tc.want {
				if !strings.Contains(warnings, want) {
					t.Errorf("warning does not mention %q:\n%s", want, warnings)
				}
			}
			// The caller has to be told what to write instead, not just
			// what is wrong: the whole point is that they cannot see the
			// consequence from the outcome.
			if !strings.Contains(warnings, "run-$(ProcId).out") {
				t.Errorf("warning does not say what to set instead:\n%s", warnings)
			}
		})
	}
}

// TestInspectDoesNotMistakeRealFilesForDevNull guards the check against
// firing on a filename that merely looks like the device.
func TestInspectDoesNotMistakeRealFilesForDevNull(t *testing.T) {
	raw := "executable = run.sh\noutput = dev-null.txt\nerror = /tmp/null\nlog = run.log\nqueue 1\n"
	if got := Inspect(raw).Warnings; len(got) != 0 {
		t.Errorf("real files named like the null device should not warn, got %v", got)
	}
}

// TestInspectWarnsWhenEveryProcWritesTheSameFile: output and error are per
// process, so a fixed name in a multi-process submission means each proc
// overwrites the last and only one survives. This reads to a user as "most
// of my jobs produced nothing" rather than as a submit-file mistake.
func TestInspectWarnsWhenEveryProcWritesTheSameFile(t *testing.T) {
	warnings := strings.Join(Inspect(
		"executable = run.sh\noutput = run.out\nerror = run.err\nlog = run.log\nqueue 10\n").Warnings, "\n")
	for _, want := range []string{"10 processes", "output = run.out", "error = run.err", "$(ProcId)"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("collision warning does not mention %q:\n%s", want, warnings)
		}
	}
}

// TestProcVaryingNamesDoNotWarn: $(ProcId) in the names is the fix the
// warning above asks for, so it has to silence it.
func TestProcVaryingNamesDoNotWarn(t *testing.T) {
	raw := "executable = run.sh\noutput = run-$(ProcId).out\nerror = run-$(ProcId).err\nlog = run.log\nqueue 10\n"
	if got := Inspect(raw).Warnings; len(got) != 0 {
		t.Errorf("per-proc names should not warn, got %v", got)
	}
}

// TestSingleProcFixedNamesDoNotWarn: one process cannot collide with
// itself, and the overwhelming majority of submit files are one process.
func TestSingleProcFixedNamesDoNotWarn(t *testing.T) {
	if got := Inspect(clean).Warnings; len(got) != 0 {
		t.Errorf("a one-process submission should not get the collision warning, got %v", got)
	}
}

// TestQueueFromFileIsNotInspectedAtAll records a real limit rather than a
// choice: `queue <vars> from <file>` cannot be parsed here, because this
// server has no access to the submitting host's filesystem and so cannot
// read the item file. ParseSubmitFile refuses it, and Inspect falls back to
// its conservative answer -- no diagnostics, spooling assumed. Worth a test
// so the silence is known to be this and not a bug in the checks.
func TestQueueFromFileIsNotInspectedAtAll(t *testing.T) {
	insp := Inspect("executable = run.sh\nqueue name from items.txt\n")
	if len(insp.Warnings) != 0 {
		t.Errorf("an unparseable submit file should yield no diagnostics, got %v", insp.Warnings)
	}
	if !insp.NeedsSpooling {
		t.Error("expected the conservative NeedsSpooling default")
	}
}

// TestInlineItemListCounts: `queue 2 name in (a, b)` is four processes, and
// four processes writing one file is exactly the shape the collision check
// exists for -- counting only the literal would have missed it.
func TestInlineItemListCounts(t *testing.T) {
	raw := "executable = run.sh\noutput = run.out\nerror = run.err\nlog = run.log\nqueue 2 name in (a, b)\n"
	warnings := strings.Join(Inspect(raw).Warnings, "\n")
	if !strings.Contains(warnings, "4 processes") {
		t.Errorf("expected the item list to multiply the count:\n%s", warnings)
	}
}

// TestQueueVariableCountsAsVariation: a name built from a queue variable
// differs per process without any $(ProcId) in it, and warning about it
// would be telling the caller to fix something already correct.
func TestQueueVariableCountsAsVariation(t *testing.T) {
	raw := "executable = run.sh\noutput = $(name).out\nerror = $(name).err\nlog = run.log\n" +
		"queue name in (alpha, beta)\n"
	if got := Inspect(raw).Warnings; len(got) != 0 {
		t.Errorf("a queue variable in the name varies per process; got %v", got)
	}
}

// TestInlineRowsCount covers the form the web submission page actually
// posts: `queue <vars> from ((rows))`, one process per row. The config
// grammar cannot parse that form at all, so counting the processes by
// re-reading the text reported 0 and the collision check never fired on
// the page most likely to produce it. The count comes from the submit
// parser's own iterator instead.
func TestInlineRowsCount(t *testing.T) {
	raw := "executable = run.sh\noutput = run.out\nerror = run.err\nlog = run.log\n" +
		"queue name from ((\nalice\nbob\ncarol\n))\n"
	warnings := strings.Join(Inspect(raw).Warnings, "\n")
	if !strings.Contains(warnings, "3 processes") {
		t.Errorf("expected one process per row:\n%s", warnings)
	}
}

// TestInlineRowsVaryingNamesDoNotWarn is the same form done right: the
// row variable in the file name makes it differ per process.
func TestInlineRowsVaryingNamesDoNotWarn(t *testing.T) {
	raw := "executable = run.sh\noutput = $(name).out\nerror = $(name).err\nlog = run.log\n" +
		"queue name from ((\nalice\nbob\n))\n"
	if got := Inspect(raw).Warnings; len(got) != 0 {
		t.Errorf("a row variable in the name varies per process; got %v", got)
	}
}
