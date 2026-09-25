package dagman

import (
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
func TestInstrumentUsesOnlyPortableSyntax(t *testing.T) {
	got, _ := Instrument(bareDag, "workflow.dag", nil)
	for _, added := range append(dagCommands(got, "NODE_STATUS_FILE"), dagCommands(got, "DOT")...) {
		for _, tooNew := range []string{"JSON", "CLASSAD", "COMPACT"} {
			if strings.Contains(strings.ToUpper(added), tooNew) {
				t.Errorf("%q uses %s, which an access point older than 2026-09-11 answers with "+
					"a parse error that kills the whole workflow", added, tooNew)
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
