package dagman

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/submitpolicy"
)

// diamond is the smallest workflow that exercises every shape Prepare
// cares about: an inline description, a named one, a PRE script and an
// edge.
const diamond = `SUBMIT-DESCRIPTION work {
  executable = /bin/sh
  transfer_executable = false
  arguments = "-c 'echo hi > out.txt'"
  transfer_output_files = out.txt
}
JOB A work
JOB B work
SCRIPT PRE A setup
PARENT A CHILD B
`

func prep(t *testing.T, s Submission) *Prepared {
	t.Helper()
	if s.Dag == "" {
		s.Dag = diamond
	}
	p, err := Prepare(s)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return p
}

// read is the sandbox entry's bytes and mode, through the fs.FS the
// spool path is handed -- not through the struct, so the test fails if
// the FS and the staging disagree.
func read(t *testing.T, p *Prepared, name string) (string, fs.FileMode) {
	t.Helper()
	fsys := p.FS()
	info, err := fs.Stat(fsys, name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	f, err := fsys.Open(name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer func() { _ = f.Close() }()
	body, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if int64(len(body)) != info.Size() {
		t.Errorf("%s: Stat said %d bytes, Open yielded %d -- the spool declares the "+
			"stat'd size and then sends what Open gives it", name, info.Size(), len(body))
	}
	return string(body), info.Mode()
}

func TestPrepareStagesTheDagAndItsFiles(t *testing.T) {
	p := prep(t, Submission{
		Files:      map[string]string{"setup": "#!/bin/sh\n", "notes.txt": "hi\n"},
		Instrument: true,
	})
	if p.DagName != "workflow.dag" {
		t.Errorf("DagName = %q, want the default workflow.dag", p.DagName)
	}
	// Every staged name has to be in the manager job's
	// transfer_input_files, because a file that is not there is SKIPPED
	// at spool time rather than rejected.
	for _, name := range p.Names() {
		if !strings.Contains(p.SubmitFile, name) {
			t.Errorf("%s was staged but the manager job never declares it; it would be silently "+
				"dropped:\n%s", name, p.SubmitFile)
		}
	}
	// A PRE script the parse attributes is executable even with no
	// extension; an input file is not.
	if _, mode := read(t, p, "setup"); mode != 0o755 {
		t.Errorf("the PRE script was staged %o; DAGMan cannot run it", mode)
	}
	if _, mode := read(t, p, "notes.txt"); mode != 0o644 {
		t.Errorf("an input file was staged executable (%o)", mode)
	}
}

// TestPrepareRefusesNamesTheSpoolCannotCarry. A spooled sandbox is one
// flat directory: a name with a path in it does not fail, it ARRIVES
// SOMEWHERE ELSE, which is how two files silently become one.
func TestPrepareRefusesNamesTheSpoolCannotCarry(t *testing.T) {
	for _, tc := range []struct {
		name string
		sub  Submission
		want string
	}{
		{"a directory in a file name", Submission{Files: map[string]string{"in/a.txt": "x"}}, "bare file name"},
		{"a directory in the DAG name", Submission{DagName: "d/w.dag"}, "bare file name"},
		{"a quote DAGMan's lexer would eat", Submission{DagName: `w".dag`}, "quote character"},
		{"whitespace DAGMan's lexer splits on", Submission{DagName: "my workflow.dag"}, "whitespace"},
		{"a newline that ends the command", Submission{Files: map[string]string{"a\nb": "x"}}, "whitespace"},
		{"a file colliding with the DAG itself",
			Submission{Files: map[string]string{"workflow.dag": "x"}}, "collides"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.sub.Dag = diamond
			_, err := Prepare(tc.sub)
			if err == nil {
				t.Fatalf("accepted %#v", tc.sub)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not explain the rule (%q): %v", tc.want, err)
			}
		})
	}
}

// TestPrepareBoundsWhatItHoldsButNotWhatItStreams is the distinction the
// whole upload path rests on: inline text is parsed, linted and
// policy-rewritten and so has to be held, while an upload is streamed
// and is exactly what callers should be using instead.
func TestPrepareBoundsWhatItHoldsButNotWhatItStreams(t *testing.T) {
	big := strings.Repeat("x", DefaultMaxSubmissionBytes)
	if _, err := Prepare(Submission{Dag: diamond, Files: map[string]string{"big.txt": big}}); err == nil {
		t.Fatal("a megabyte of inline text was accepted")
	} else if !strings.Contains(err.Error(), "over the") {
		t.Errorf("the refusal does not name the limit: %v", err)
	}

	// The same bytes as an upload: accepted, and never held.
	p := prep(t, Submission{
		Dag: diamond + "\n",
		Opaque: []OpaqueFile{{
			Name: "big.txt", Size: int64(len(big)),
			Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(big)), nil },
		}},
		Instrument: true,
	})
	got, _ := read(t, p, "big.txt")
	if got != big {
		t.Errorf("the upload was staged as %d bytes, want %d", len(got), len(big))
	}
	if !strings.Contains(p.SubmitFile, "big.txt") {
		t.Errorf("the upload is not in transfer_input_files, so the spool would skip it:\n%s", p.SubmitFile)
	}
}

// TestOpaqueOpensFreshEachTime. The spool path stats a file and then
// reads it, and a reader that has already been drained sends zero bytes
// under a header that promised more.
func TestOpaqueOpensFreshEachTime(t *testing.T) {
	const body = "abcdef"
	p := prep(t, Submission{
		Opaque: []OpaqueFile{{
			Name: "blob.bin", Size: int64(len(body)),
			Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader([]byte(body))), nil },
		}},
		Instrument: true,
	})
	for i := 0; i < 2; i++ {
		if got, _ := read(t, p, "blob.bin"); got != body {
			t.Fatalf("open %d returned %q, want %q", i+1, got, body)
		}
	}
}

// TestOpaqueOpenFailureIsAnOpenError, not a short read: a sandbox that
// cannot be read must fail the spool rather than send a truncated file.
func TestOpaqueOpenFailureIsAnOpenError(t *testing.T) {
	boom := errors.New("the temp file is gone")
	p := prep(t, Submission{
		Opaque: []OpaqueFile{{
			Name: "blob.bin", Size: 4,
			Open: func() (io.ReadCloser, error) { return nil, boom },
		}},
		Instrument: true,
	})
	if _, err := p.FS().Open("blob.bin"); !errors.Is(err, boom) {
		t.Errorf("Open returned %v, want the underlying failure", err)
	}
}

// TestPrepareAppliesSitePolicyExactlyOnce.
//
// Applying it twice is not merely redundant: Policy.Apply checks the
// file first, the first pass leaves the overrides block's own custom
// attributes in it, and the second pass refuses the submission. Prepare
// owns the one application, which is why its callers must submit with
// the door that does NOT apply it again.
func TestPrepareAppliesSitePolicyExactlyOnce(t *testing.T) {
	policy := submitpolicy.Policy{Overrides: `+ProjectName = "site"`}
	p := prep(t, Submission{Policy: policy, Instrument: true})
	if n := strings.Count(p.SubmitFile, "ProjectName"); n != 1 {
		t.Errorf("the manager submit file names ProjectName %d times, want once:\n%s", n, p.SubmitFile)
	}
	if _, err := policy.Apply(p.SubmitFile); err == nil {
		t.Error("a second Apply succeeded; this test's premise is gone and the callers' " +
			"submitApplied split is no longer load-bearing")
	}
	// The inline description gets it too -- that is the shape both
	// surfaces recommend, and it is the one site policy used to miss.
	staged, _ := read(t, p, p.DagName)
	if !strings.Contains(staged, "ProjectName") {
		t.Errorf("site policy never reached the inline submit description:\n%s", staged)
	}
}

// TestPrepareRefusesAnUnreadableSubmitDescription. A .sub file staged
// without being read is a node job that quietly escaped the site's
// overrides, which is worse than a refusal.
func TestPrepareRefusesAnUnreadableSubmitDescription(t *testing.T) {
	sub := Submission{
		Dag:    "JOB A a.sub\n",
		Policy: submitpolicy.Policy{Overrides: `+ProjectName = "site"`},
		Opaque: []OpaqueFile{{
			Name: "a.sub", Size: 1,
			Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("x")), nil },
		}},
	}
	if _, err := Prepare(sub); err == nil {
		t.Fatal("an unread .sub file was staged under a site policy")
	} else if !strings.Contains(err.Error(), "submit policy") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	// With no site policy there is nothing to splice, so it is allowed.
	sub.Policy = submitpolicy.Policy{}
	if _, err := Prepare(sub); err != nil {
		t.Errorf("refused with no policy configured: %v", err)
	}
}

// TestPrepareReportsAFatalWorkflowRatherThanRefusingIt: a dry run has to
// show every fatal finding, and an error return would show one.
func TestPrepareReportsAFatalWorkflowRatherThanRefusingIt(t *testing.T) {
	p := prep(t, Submission{Dag: "INCLUDE gone.dag\nSPLICE S missing.dag\nJOB A a.sub\n"})
	if !p.Report.Fatal() {
		t.Fatalf("a DAG with a missing INCLUDE and a missing SPLICE is not fatal: %v", p.Report.Findings)
	}
	if len(p.Report.Errors()) < 2 {
		t.Errorf("only %d fatal findings reported; both should be: %v",
			len(p.Report.Errors()), p.Report.Errors())
	}
	if p.SubmitFile == "" {
		t.Error("no submit file was built, so a dry run cannot show what would be sent")
	}
}

// TestOpaqueCountsAsSuppliedNotPromised. An upload is PRESENT: it
// satisfies a node's reference and lands in the allow-set, and a name
// nothing references is still worth flagging as a probable typo.
func TestOpaqueCountsAsSuppliedNotPromised(t *testing.T) {
	dag := `JOB A {
  executable = /bin/sh
  transfer_executable = false
  transfer_input_files = genome.fa
}
`
	used := prep(t, Submission{Dag: dag, Instrument: true, Opaque: []OpaqueFile{{
		Name: "genome.fa", Size: 2,
		Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("x\n")), nil },
	}}})
	for _, f := range used.Report.Findings {
		if strings.Contains(f.Message, "genome.fa") {
			t.Errorf("an uploaded file the DAG uses was still reported: %s", f.Message)
		}
	}

	unused := prep(t, Submission{Dag: diamond, Instrument: true, Opaque: []OpaqueFile{{
		Name: "stray.fa", Size: 2,
		Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("x\n")), nil },
	}}})
	var saw bool
	for _, f := range unused.Report.Findings {
		saw = saw || strings.Contains(f.Message, "stray.fa")
	}
	if !saw {
		t.Errorf("an upload nothing references went unreported; it would be silently dropped: %v",
			unused.Report.Findings)
	}
}

// TestPrepareRefusesADuplicateName: the sandbox is flat, so two files
// under one name is one file and a silent loss.
func TestPrepareRefusesADuplicateName(t *testing.T) {
	_, err := Prepare(Submission{
		Dag:   diamond,
		Files: map[string]string{"a.txt": "one"},
		Opaque: []OpaqueFile{{
			Name: "a.txt", Size: 3,
			Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("two")), nil },
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a duplicated name was accepted or misexplained: %v", err)
	}
}

// TestInstrumentOffSaysSo. A caller that turns the graph off and is told
// nothing goes looking for files nobody will write.
func TestInstrumentOffSaysSo(t *testing.T) {
	on := prep(t, Submission{Instrument: true})
	if on.Instrumentation.DotFile == "" || on.Instrumentation.StatusFile == "" {
		t.Fatalf("an instrumented workflow names no files: %+v", on.Instrumentation)
	}
	off := prep(t, Submission{Instrument: false})
	if off.Instrumentation.DotFile != "" {
		t.Errorf("instrument=false still promised a dot file")
	}
	if off.Instrumentation.Skipped == "" {
		t.Error("instrument=false said nothing about there being no graph")
	}
	var told bool
	for _, n := range off.Notes {
		told = told || strings.Contains(n, "instrumentation was turned off")
	}
	if !told {
		t.Errorf("the notes do not mention it: %v", off.Notes)
	}
}

// TestLintReachesTheNodeJobs. The node jobs are the ones that do the
// work; a description that would hold every one of them used to reach
// the queue unexamined, and the hold arrived hours later with nothing to
// connect it to the submission.
func TestLintReachesTheNodeJobs(t *testing.T) {
	p := prep(t, Submission{Dag: "JOB A {\n  executable = /bin/true\n}\n", Instrument: true})
	var saw bool
	for _, n := range p.Notes {
		saw = saw || (strings.Contains(n, "node A") && strings.Contains(n, "warning"))
	}
	if !saw {
		t.Errorf("the node description was never linted: %v", p.Notes)
	}
}

// --- layout -----------------------------------------------------------

type fakeConfig struct {
	vals  map[string]string
	err   error
	calls int
}

func (f *fakeConfig) ConfigVal(_ context.Context, name string) (string, bool, error) {
	f.calls++
	if f.err != nil {
		return "", false, f.err
	}
	v, ok := f.vals[name]
	return v, ok, nil
}

// TestDiscoverLayoutFailsSoft. Discovery costs the defaults when it
// fails, never the workflow -- and an empty BIN must never become
// "/condor_dagman".
func TestDiscoverLayoutFailsSoft(t *testing.T) {
	ctx := context.Background()
	if got := DiscoverLayout(ctx, nil, nil); got != (Layout{}) {
		t.Errorf("a nil reader produced %+v", got)
	}
	if got := DiscoverLayout(ctx, &fakeConfig{err: fmt.Errorf("down")}, nil); got != (Layout{}) {
		t.Errorf("an unreachable schedd produced %+v", got)
	}
	for _, tc := range []struct {
		name string
		vals map[string]string
		want Layout
	}{
		{"unset", map[string]string{}, Layout{}},
		{"not defined", map[string]string{"BIN": "Not defined: BIN"}, Layout{}},
		{"relative BIN is unusable from here", map[string]string{"BIN": "bin"}, Layout{}},
		{"absolute", map[string]string{"BIN": "/opt/condor/bin"}, Layout{BinDir: "/opt/condor/bin"}},
		{"disable port", map[string]string{"DAGMAN_DISABLE_PORT": "True"}, Layout{DisablePort: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DiscoverLayout(ctx, &fakeConfig{vals: tc.vals}, nil); got != tc.want {
				t.Errorf("= %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestLayoutCacheAsksOncePerAccessPoint: two APs in a set need not have
// condor_dagman in the same place, and neither should be asked twice.
func TestLayoutCacheAsksOncePerAccessPoint(t *testing.T) {
	var cache LayoutCache
	asked := map[string]int{}
	for _, ap := range []string{"ap1", "ap2", "ap1", "ap2"} {
		got := cache.Get(context.Background(), ap, func(context.Context) Layout {
			asked[ap]++
			return Layout{BinDir: "/bin/" + ap}
		})
		if got.BinDir != "/bin/"+ap {
			t.Errorf("%s's layout = %q", ap, got.BinDir)
		}
	}
	if asked["ap1"] != 1 || asked["ap2"] != 1 {
		t.Errorf("discovery counts = %v, want once each", asked)
	}
}
