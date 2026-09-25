package dagman

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

const bareDag = `JOB setup setup.sub
JOB work_0 work.sub
JOB work_1 work.sub
JOB gather gather.sub
PARENT setup CHILD work_0 work_1
PARENT work_0 work_1 CHILD gather
`

// dagCommands returns the top-level commands of a DAG text, upper-cased,
// so a test can say what was added without matching whitespace.
func dagCommands(text, keyword string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) > 0 && strings.EqualFold(fields[0], keyword) {
			out = append(out, strings.Join(fields, " "))
		}
	}
	return out
}

func TestInstrumentAppendsBothCommands(t *testing.T) {
	got, instr := Instrument(bareDag, "workflow.dag", nil)

	if instr.DotFile != "workflow.dot" || !instr.AddedDot {
		t.Errorf("dot = %q added=%v, want workflow.dot added", instr.DotFile, instr.AddedDot)
	}
	if instr.StatusFile != "workflow.status" || !instr.AddedStatus {
		t.Errorf("status = %q added=%v, want workflow.status added", instr.StatusFile, instr.AddedStatus)
	}
	if !instr.Added() {
		t.Errorf("Added() is false after adding both commands")
	}

	dot := dagCommands(got, "DOT")
	if len(dot) != 1 || dot[0] != "DOT workflow.dot OVERWRITE" {
		t.Errorf("DOT commands = %v", dot)
	}
	// No UPDATE: the structure is written once, at startup.
	if strings.Contains(strings.ToUpper(dot[0]), "UPDATE") {
		t.Errorf("the DOT command asks for updates: %q", dot[0])
	}
	status := dagCommands(got, "NODE_STATUS_FILE")
	if len(status) != 1 || status[0] != "NODE_STATUS_FILE workflow.status 30" {
		t.Errorf("NODE_STATUS_FILE commands = %v", status)
	}
	if !strings.HasPrefix(got, bareDag) {
		t.Errorf("the author's own text was not left intact at the front:\n%s", got)
	}
}

// TestInstrumentUsesOnlyPortableSyntax is a version-compatibility rule
// with teeth. The instrumented DAG is parsed by whatever condor_dagman
// the access point runs, and an argument that version does not know is
// not ignored: it is a parse error, and the workflow dies before any node
// is submitted. The `JSON`, `CLASSAD` and `COMPACT` arguments to
// NODE_STATUS_FILE were added on 2026-09-11 (HTCONDOR-3928) -- an access
// point one release older fails every DAG that carries them, which was
// observed against a 25.8 harness rather than guessed at.
//
// The assertion is an ALLOWLIST, and deliberately so. Grepping for the
// three tokens that happened to break us once would pass any new
// non-portable token, and as a substring test over the whole command it
// also read the FILE name -- a workflow called json.dag failed a test
// about DAGMan's version. Matching the whole emitted line against the
// exact portable spelling cannot do either.
func TestInstrumentUsesOnlyPortableSyntax(t *testing.T) {
	dotLine := regexp.MustCompile(`^DOT \S+ OVERWRITE$`)
	statusLine := regexp.MustCompile(`^NODE_STATUS_FILE \S+ \d+$`)
	// Named so a DAG whose own name contains a token this test once
	// grepped for cannot pass or fail it by accident.
	for _, dagName := range []string{"workflow.dag", "json.dag", "compact-classad.dag"} {
		got, _ := Instrument(bareDag, dagName, nil)
		for _, line := range dagCommands(got, "DOT") {
			if !dotLine.MatchString(line) {
				t.Errorf("DOT line %q is not the portable spelling `DOT <file> OVERWRITE`", line)
			}
		}
		for _, line := range dagCommands(got, "NODE_STATUS_FILE") {
			if !statusLine.MatchString(line) {
				t.Errorf("NODE_STATUS_FILE line %q is not the portable spelling "+
					"`NODE_STATUS_FILE <file> <seconds>`; an argument added after 2026-09-11 "+
					"(JSON, CLASSAD, COMPACT) is a parse error on an older access point", line)
			}
		}
	}
}

// TestInstrumentRespectsTheAuthor is the rule that keeps this from
// fighting the workflow's own author. DAGMan itself refuses a second
// NODE_STATUS_FILE (Dag::SetNodeStatusFileName warns and keeps the
// first), and a second DOT would silently replace theirs -- so when they
// declared one, theirs is what the reader is told to look for.
func TestInstrumentRespectsTheAuthor(t *testing.T) {
	cases := []struct {
		name       string
		dag        string
		wantDot    string
		wantStatus string
		addedDot   bool
		addedStat  bool
	}{
		{
			name:       "both declared",
			dag:        "DOT mine.dot UPDATE\nNODE_STATUS_FILE mine.status 5 ALWAYS-UPDATE\n" + bareDag,
			wantDot:    "mine.dot",
			wantStatus: "mine.status",
		},
		{
			name:       "only DOT declared",
			dag:        "DOT mine.dot\n" + bareDag,
			wantDot:    "mine.dot",
			wantStatus: "workflow.status",
			addedStat:  true,
		},
		{
			name:       "only NODE_STATUS_FILE declared",
			dag:        bareDag + "NODE_STATUS_FILE mine.status\n",
			wantDot:    "workflow.dot",
			wantStatus: "mine.status",
			addedDot:   true,
		},
		{
			name:       "lower case spelling still counts",
			dag:        "dot mine.dot\nnode_status_file mine.status\n" + bareDag,
			wantDot:    "mine.dot",
			wantStatus: "mine.status",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, instr := Instrument(tc.dag, "workflow.dag", nil)
			if instr.DotFile != tc.wantDot || instr.AddedDot != tc.addedDot {
				t.Errorf("dot = %q added=%v, want %q added=%v",
					instr.DotFile, instr.AddedDot, tc.wantDot, tc.addedDot)
			}
			if instr.StatusFile != tc.wantStatus || instr.AddedStatus != tc.addedStat {
				t.Errorf("status = %q added=%v, want %q added=%v",
					instr.StatusFile, instr.AddedStatus, tc.wantStatus, tc.addedStat)
			}
			if n := len(dagCommands(got, "DOT")); n != 1 {
				t.Errorf("the instrumented DAG has %d DOT commands, want exactly 1", n)
			}
			if n := len(dagCommands(got, "NODE_STATUS_FILE")); n != 1 {
				t.Errorf("the instrumented DAG has %d NODE_STATUS_FILE commands, want exactly 1", n)
			}
			if !tc.addedDot && !tc.addedStat && got != tc.dag {
				t.Errorf("a fully instrumented DAG was rewritten:\n%s", got)
			}
		})
	}
}

// TestInstrumentAvoidsCollisions: a spooled sandbox is one flat
// directory, so a generated name landing on a caller's file would
// overwrite it -- silently, since DAGMan writes the dot file itself.
func TestInstrumentAvoidsCollisions(t *testing.T) {
	staged := map[string]string{
		"workflow.dot":      "not really a graph",
		"workflow.status":   "not really a status file",
		"workflow-1.status": "nor this",
	}
	_, instr := Instrument(bareDag, "workflow.dag", staged)
	if instr.DotFile != "workflow-1.dot" {
		t.Errorf("dot = %q, want workflow-1.dot", instr.DotFile)
	}
	if instr.StatusFile != "workflow-2.status" {
		t.Errorf("status = %q, want workflow-2.status", instr.StatusFile)
	}
	for _, name := range []string{instr.DotFile, instr.StatusFile} {
		if _, clash := staged[name]; clash {
			t.Errorf("%s overwrites a staged file", name)
		}
	}
}

// TestInstrumentDoesNotCollideWithTheDagItself covers the one name that
// is not in the staged map.
func TestInstrumentDoesNotCollideWithTheDagItself(t *testing.T) {
	_, instr := Instrument(bareDag, "workflow.dot", nil)
	if instr.DotFile == "workflow.dot" {
		t.Errorf("the dot file would overwrite the DAG description itself")
	}
}

// TestInstrumentPreservesTheGraph: whatever is appended, DAGMan has to
// see the same workflow. A trailing line continuation is the shape that
// breaks a naive append -- the backslash would swallow the first command
// added.
func TestInstrumentPreservesTheGraph(t *testing.T) {
	for _, tc := range []struct{ name, dag string }{
		{"plain", bareDag},
		{"no trailing newline", strings.TrimRight(bareDag, "\n")},
		{"trailing continuation", bareDag + "PARENT setup CHILD \\\n    gather\n"},
		{"trailing comment", bareDag + "# the end\n"},
		// The two shapes the old code got wrong. A blank or comment line
		// does NOT end a continuation: DagParser::getnextline tests
		// skip_line FIRST and keeps accumulating
		// (src/condor_utils/dag_parser.cpp:218-241), so the dangling
		// logical line swallows the first command appended.
		{"dangling continuation", bareDag + "PARENT setup CHILD gather \\\n"},
		// And this one is why the first is not enough: the first has a
		// parse error of its own that could mask the assertion, while
		// this one is SILENT -- condor_dag_checker reports nothing
		// before or after, and the POST script just quietly gains three
		// arguments.
		{"dangling continuation on a SCRIPT", "JOB a a.sub\nSCRIPT POST a c.sh --keep \\\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := Parse(tc.dag)
			got, _ := Instrument(tc.dag, "workflow.dag", nil)
			after := Parse(got)
			if names(before) != names(after) {
				t.Errorf("node set changed: %q -> %q", names(before), names(after))
			}
			if edges(before) != edges(after) {
				t.Errorf("edge set changed: %q -> %q", edges(before), edges(after))
			}
			if scripts(before) != scripts(after) {
				t.Errorf("a script's command line changed: %q -> %q", scripts(before), scripts(after))
			}
			if len(after.Errors) != len(before.Errors) || len(after.Fatals) != len(before.Fatals) {
				t.Errorf("the instrumented DAG has new parse errors: %+v / %+v", after.Errors, after.Fatals)
			}
		})
	}
}

func TestInstrumentBaseNames(t *testing.T) {
	cases := map[string]string{
		"workflow.dag": "workflow",
		"workflow.DAG": "workflow",
		"workflow":     "workflow",
		"a.b.dag":      "a.b",
		"my flow.dag":  "my_flow",
		"":             "workflow",
	}
	for in, want := range cases {
		if got := InstrumentBase(in); got != want {
			t.Errorf("InstrumentBase(%q) = %q, want %q", in, got, want)
		}
		if got := DotFileName(in); got != want+".dot" {
			t.Errorf("DotFileName(%q) = %q", in, got)
		}
		if got := StatusFileName(in); got != want+".status" {
			t.Errorf("StatusFileName(%q) = %q", in, got)
		}
	}
}

// TestInstrumentNamesAreWhatTheReaderLooksFor pins the contract between
// the two halves: the writer picks names and the reader derives them
// again from the manager job's -Dag argument, with no channel between
// them but this rule.
func TestInstrumentNamesAreWhatTheReaderLooksFor(t *testing.T) {
	_, instr := Instrument(bareDag, "fanout.dag", nil)
	if instr.DotFile != DotFileName("fanout.dag") {
		t.Errorf("Instrument wrote %q but a reader would look for %q",
			instr.DotFile, DotFileName("fanout.dag"))
	}
	if instr.StatusFile != StatusFileName("fanout.dag") {
		t.Errorf("Instrument wrote %q but a reader would look for %q",
			instr.StatusFile, StatusFileName("fanout.dag"))
	}
}

func names(d *DAG) string {
	var out []string
	for _, n := range d.Nodes {
		out = append(out, n.Name)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func edges(d *DAG) string {
	var out []string
	for _, e := range d.Edges {
		out = append(out, e.Parent+"->"+e.Child)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// scripts renders every PRE/POST/HOLD script's whole command line, which
// is where a swallowed continuation shows up: the node set and the edge
// set are both untouched when a SCRIPT line absorbs what was appended
// after it.
func scripts(d *DAG) string {
	var out []string
	for _, s := range d.Scripts {
		out = append(out, string(s.When)+" "+s.Node+" "+s.Executable+" "+strings.Join(s.Args, " "))
	}
	sort.Strings(out)
	return strings.Join(out, ";")
}

// TestInstrumentRefusesADanglingContinuation is finding 1 stated
// directly: the text comes back byte for byte and nothing claims to have
// been added.
//
// The backslash is NOT stripped on the way past. DAGMan discards such a
// trailing partial line at EOF, so removing the backslash would make it
// start parsing a line the workflow currently ignores -- a behaviour
// change nobody asked a monitoring feature to make.
func TestInstrumentRefusesADanglingContinuation(t *testing.T) {
	for _, tc := range []struct{ name, dag string }{
		{"PARENT", bareDag + "PARENT setup CHILD gather \\\n"},
		{"SCRIPT", "JOB a a.sub\nSCRIPT POST a c.sh --keep \\\n"},
		{"blank line after it", "JOB a a.sub\nSCRIPT POST a c.sh --keep \\\n\n\n"},
		{"comment after it", "JOB a a.sub\nSCRIPT POST a c.sh --keep \\\n# done\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, instr := Instrument(tc.dag, "workflow.dag", nil)
			if got != tc.dag {
				t.Errorf("the DAG was rewritten after a dangling continuation:\n%s", got)
			}
			if instr.Added() {
				t.Errorf("Instrument reported adding %+v to a DAG it did not touch", instr)
			}
			if instr.DotFile != "" || instr.StatusFile != "" {
				t.Errorf("a file was reported that nothing will write: %+v", instr)
			}
			if instr.Skipped == "" {
				t.Error("nothing was instrumented and nothing said why")
			}
		})
	}

	// A continuation that IS continued is fine, and so is a backslash in
	// the middle of a line.
	for _, dag := range []string{
		bareDag + "PARENT setup CHILD \\\n  gather\n",
		"JOB a a.sub\nVARS a path=\"c:\\\\tmp\" other=\"x\"\n",
	} {
		if _, instr := Instrument(dag, "workflow.dag", nil); !instr.Added() {
			t.Errorf("a well-formed DAG was refused instrumentation (%s):\n%s", instr.Skipped, dag)
		}
	}
}

// TestInstrumentSkipsAnIncompleteDag is finding 3. Parse sees only the
// text it is given, so a DOT or NODE_STATUS_FILE inside an INCLUDE or
// SPLICE is invisible -- and the two halves then fail in opposite
// directions. DAGMan folds an INCLUDE'd DOT into the parent scope and
// Dag::SetDotFileName is last-one-wins with no guard (dag.cpp:2309), so
// ours silently replaces the author's; SetNodeStatusFileName keeps the
// FIRST and warns (dag.cpp:2388), and DAGMAN_USE_STRICT=3 makes that
// warning fatal.
func TestInstrumentSkipsAnIncompleteDag(t *testing.T) {
	for _, dag := range []string{
		"INCLUDE common.dag\n" + bareDag,
		bareDag + "SPLICE sub sub.dag\n",
	} {
		got, instr := Instrument(dag, "workflow.dag", nil)
		if got != dag {
			t.Errorf("a DAG with an unresolved inclusion was instrumented anyway:\n%s", got)
		}
		if instr.Added() || instr.Skipped == "" {
			t.Errorf("instr = %+v, want nothing added and a reason", instr)
		}
	}
}

// TestInstrumentBaseKeepsOnlyWhatDagmanLexesBack is finding 2. dag_name
// is caller-controlled and reaches DAGMan's lexer
// (src/condor_utils/dag_parser.cpp:30-77), which splits on whitespace and
// treats " and ' as quotes. An unbalanced quote is a fatal "Invalid
// quoting: no ending quote found"; a BALANCED pair is worse, because it
// parses and is then stripped, so DAGMan writes a different file than the
// one the caller was told to look for.
func TestInstrumentBaseKeepsOnlyWhatDagmanLexesBack(t *testing.T) {
	cases := map[string]string{
		"bob's_flow.dag":  "bob_s_flow",
		`"quoted".dag`:    "_quoted_",
		"a\nb.dag":        "a_b",
		"tab\there.dag":   "tab_here",
		"ok.name-1+2.dag": "ok.name-1+2",
		"caf\u00e9.dag":   "caf_",
	}
	for in, want := range cases {
		if got := InstrumentBase(in); got != want {
			t.Errorf("InstrumentBase(%q) = %q, want %q", in, got, want)
		}
	}

	// And end to end: whatever the name, the emitted commands carry no
	// character DAGMan's lexer would act on.
	for name := range cases {
		got, instr := Instrument(bareDag, name, nil)
		for _, line := range append(dagCommands(got, "DOT"), dagCommands(got, "NODE_STATUS_FILE")...) {
			if strings.ContainsAny(line, "\"'") {
				t.Errorf("dag_name %q produced %q, which DAGMan lexes as quoted", name, line)
			}
		}
		if strings.ContainsAny(instr.DotFile+instr.StatusFile, "\"' \t\n") {
			t.Errorf("dag_name %q produced file names DAGMan cannot round-trip: %+v", name, instr)
		}
	}
}

// TestInstrumentReParsesWhatItProduced is finding 4: the structural
// safety net. Everything upstream analyses the caller's text; the
// instrumented text is what DAGMan reads, and nothing else ever looks at
// it. Re-reading it turns any future mistake here from "the workflow
// dies" into "no graph this time".
func TestInstrumentReParsesWhatItProduced(t *testing.T) {
	same := Parse(bareDag)
	if why, changed := instrumentChangedTheWorkflow(same, Parse(bareDag)); changed {
		t.Errorf("an identical parse was reported as changed: %s", why)
	}
	for _, tc := range []struct{ name, dag string }{
		{"a node gained an argument", bareDag + "JOB extra extra.sub\n"},
		{"an edge appeared", bareDag + "PARENT gather CHILD setup\n"},
		{"a node's descriptor changed", strings.Replace(bareDag, "setup.sub", "other.sub", 1)},
		{"DAGMan would reject a line", bareDag + "JOB setup setup.sub\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, changed := instrumentChangedTheWorkflow(same, Parse(tc.dag)); !changed {
				t.Error("a differing workflow was reported as unchanged, so the safety net would " +
					"stage a DAG that parses to something else")
			}
		})
	}
}
