package dagman

import (
	"strings"
	"testing"
)

func TestParseCollectsGraphAndFileReferences(t *testing.T) {
	d := Parse(`
# a comment
JOB A a.sub
JOB B b.sub DIR work NOOP
SUBDAG EXTERNAL S stage2.dag
SPLICE SP pieces.dag
SCRIPT PRE A pre.sh --flag
SCRIPT DEFER 3 60 POST B post.sh
PARENT A B CHILD S
RETRY A 3 UNLESS-EXIT 42
VARS A name="alpha"
INCLUDE common.inc
CONFIG dagman.config
NODE_STATUS_FILE status.txt
`)

	if len(d.Errors) > 0 {
		t.Fatalf("unexpected parse errors: %v", d.Errors)
	}
	if got := len(d.Nodes); got != 4 {
		t.Fatalf("nodes = %d, want 4: %+v", got, d.Nodes)
	}

	b, ok := d.NodeByName("B")
	if !ok {
		t.Fatal("node B not found")
	}
	if b.Dir != "work" || !b.NOOP {
		t.Errorf("B options not parsed: Dir=%q NOOP=%v", b.Dir, b.NOOP)
	}

	s, _ := d.NodeByName("S")
	if s.Type != NodeSubdag || s.Descriptor != "stage2.dag" {
		t.Errorf("SUBDAG parsed as %+v", s)
	}
	sp, _ := d.NodeByName("SP")
	if sp.Type != NodeSplice || sp.Descriptor != "pieces.dag" {
		t.Errorf("SPLICE parsed as %+v", sp)
	}

	// PARENT A B CHILD S is a cross product: two edges, not one.
	if len(d.Edges) != 2 {
		t.Errorf("edges = %+v, want 2 (A->S and B->S)", d.Edges)
	}

	if len(d.Scripts) != 2 {
		t.Fatalf("scripts = %+v, want 2", d.Scripts)
	}
	// The DEFER modifier has to be skipped, or the script's type, node and
	// executable all shift by three and the analysis demands a file called
	// "3".
	var post *Script
	for i := range d.Scripts {
		if d.Scripts[i].When == ScriptPost {
			post = &d.Scripts[i]
		}
	}
	if post == nil {
		t.Fatal("no POST script parsed")
	}
	if post.Node != "B" || post.Executable != "post.sh" {
		t.Errorf("DEFER was not skipped: node=%q exe=%q", post.Node, post.Executable)
	}

	if len(d.Includes) != 1 || d.Includes[0].Path != "common.inc" {
		t.Errorf("includes = %+v", d.Includes)
	}
	if len(d.Configs) != 1 || d.Configs[0].Path != "dagman.config" {
		t.Errorf("configs = %+v", d.Configs)
	}
	// NODE_STATUS_FILE is written, not read; it must not end up anywhere
	// that makes the caller try to supply it.
	if len(d.Outputs) != 1 || d.Outputs[0].Path != "status.txt" {
		t.Errorf("outputs = %+v", d.Outputs)
	}
}

func TestParseInlineSubmitDescriptions(t *testing.T) {
	d := Parse(`
SUBMIT-DESCRIPTION shared {
    executable = /bin/echo
    transfer_executable = false
}
JOB A shared
JOB B {
    executable = /bin/date
    transfer_executable = false
}
JOB C @=end
    executable = /bin/true
@end
PARENT A CHILD B C
`)
	if len(d.Errors) > 0 {
		t.Fatalf("unexpected parse errors: %v", d.Errors)
	}
	if len(d.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3", len(d.Nodes))
	}
	desc, ok := d.Descriptions["shared"]
	if !ok {
		t.Fatal("SUBMIT-DESCRIPTION shared was not captured")
	}
	if !strings.Contains(desc.Body, "/bin/echo") {
		t.Errorf("description body = %q", desc.Body)
	}

	b, _ := d.NodeByName("B")
	if !b.Inline || !strings.Contains(b.InlineBody, "/bin/date") {
		t.Errorf("brace-inline node not captured: %+v", b)
	}
	// The @=tag form closes with @tag, not }; getting this wrong swallows
	// the rest of the file into one node's description.
	c, _ := d.NodeByName("C")
	if !c.Inline || !strings.Contains(c.InlineBody, "/bin/true") {
		t.Errorf("@=tag inline node not captured: %+v", c)
	}
	if strings.Contains(c.InlineBody, "PARENT") {
		t.Errorf("@=tag block did not stop at its delimiter: %q", c.InlineBody)
	}
}

func TestParseUnknownCommandIsNotAnError(t *testing.T) {
	// DAGMan gains syntax every release. A command this package has not
	// been taught must pass through, not fail the workflow -- otherwise
	// upgrading HTCondor breaks the tool.
	d := Parse("JOB A a.sub\nSOME-FUTURE-COMMAND A whatever\nANOTHER_NEW_THING B\n")
	if len(d.Errors) != 0 {
		t.Errorf("unknown commands were treated as errors: %v", d.Errors)
	}
	if len(d.Unrecognized) != 2 {
		t.Errorf("unrecognized = %+v, want 2", d.Unrecognized)
	}
}

func TestParseReportsMalformedKnownCommands(t *testing.T) {
	// A keyword we DO know, with arguments that make no sense, is worth
	// reporting: it is much more likely a mistake than a new feature.
	d := Parse("JOB\nPARENT A B\nSPLICE only-a-name\n")
	if len(d.Errors) != 3 {
		t.Errorf("errors = %+v, want 3", d.Errors)
	}
}

func TestParseUnclosedInlineDescription(t *testing.T) {
	d := Parse("JOB A {\n    executable = /bin/true\n")
	if len(d.Errors) == 0 {
		t.Fatal("an unterminated inline description should be reported")
	}
	if !strings.Contains(d.Errors[0].Why, "never closed") {
		t.Errorf("error does not say what is wrong: %q", d.Errors[0].Why)
	}
}

func TestParseIsCaseInsensitive(t *testing.T) {
	// DAGMan folds its keywords; a DAG written in lower case is valid and
	// common.
	d := Parse("job A a.sub\njob B b.sub\nparent A child B\n")
	if len(d.Nodes) != 2 || len(d.Edges) != 1 {
		t.Fatalf("lower-case DAG did not parse: nodes=%d edges=%d errors=%v",
			len(d.Nodes), len(d.Edges), d.Errors)
	}
}

func TestParseBackslashLineContinuation(t *testing.T) {
	// dag_parser.cpp:231-235: a line ending in a backslash joins the next
	// one. Without this the first half is a PARENT with no CHILD and the
	// second half is an unrecognized command, so a valid DAG looks broken.
	d := Parse("JOB A a.sub\nJOB B b.sub\nPARENT A \\\n  CHILD B\n")
	if len(d.Errors) != 0 || len(d.Unrecognized) != 0 {
		t.Fatalf("a continued line did not parse: errors=%v unrecognized=%v", d.Errors, d.Unrecognized)
	}
	if len(d.Edges) != 1 || d.Edges[0].Parent != "A" || d.Edges[0].Child != "B" {
		t.Fatalf("edges = %+v, want one A->B", d.Edges)
	}
	// The logical line belongs to where the author started it, not where
	// it happened to end.
	if d.Edges[0].Line != 3 {
		t.Errorf("edge line = %d, want 3 (the first physical line)", d.Edges[0].Line)
	}
}

func TestParseKeywordDashesFoldToUnderscores(t *testing.T) {
	// dag_parser.cpp:965 replaces '-' with '_' before the keyword lookup,
	// which is what makes SUBMIT-DESCRIPTION and SUBMIT_DESCRIPTION the
	// same command. Both spellings are in the wild.
	for _, kw := range []string{"SUBMIT-DESCRIPTION", "SUBMIT_DESCRIPTION"} {
		d := Parse(kw + " shared {\n    executable = /bin/echo\n}\nJOB A shared\n")
		if len(d.Errors) != 0 || len(d.Unrecognized) != 0 {
			t.Fatalf("%s did not parse: errors=%v unrecognized=%v", kw, d.Errors, d.Unrecognized)
		}
		if _, ok := d.Descriptions["shared"]; !ok {
			t.Errorf("%s did not register a description: %+v", kw, d.Descriptions)
		}
	}
	// The same fold applies to the other hyphenated spellings.
	d := Parse("JOB A a.sub\nABORT-DAG-ON A 1\nPRE-SKIP A 2\n")
	if len(d.Unrecognized) != 0 {
		t.Errorf("hyphenated keywords were not folded: %+v", d.Unrecognized)
	}
}

func TestParseTokensAfterInlineDescriptionEnd(t *testing.T) {
	// parse.cpp:158 accepts the closing token followed by a space, and
	// dag_parser.cpp:268 re-lexes what follows. Dropping the remainder
	// swallowed the next command, or lost a DIR.
	d := Parse("JOB A {\n    executable = /bin/true\n} DIR sub\nJOB B b.sub\n")
	if len(d.Errors) != 0 {
		t.Fatalf("unexpected parse errors: %v", d.Errors)
	}
	if len(d.Nodes) != 2 {
		t.Fatalf("nodes = %+v, want 2", d.Nodes)
	}
	a, _ := d.NodeByName("A")
	if !a.Inline || a.Dir != "sub" {
		t.Errorf("options after the closing brace were dropped: %+v", a)
	}
	if !strings.Contains(a.InlineBody, "/bin/true") {
		t.Errorf("inline body = %q", a.InlineBody)
	}

	// And the same for the @=tag form.
	tagged := Parse("JOB A @=end\n    executable = /bin/true\n@end NOOP\nJOB B b.sub\n")
	if len(tagged.Nodes) != 2 {
		t.Fatalf("nodes = %+v, want 2", tagged.Nodes)
	}
	ta, _ := tagged.NodeByName("A")
	if !ta.NOOP {
		t.Errorf("options after @end were dropped: %+v", ta)
	}
}

func TestAnalyzeInlineDirIsStillRefused(t *testing.T) {
	// Now that a DIR after the closing brace is parsed, it must be caught
	// by the same flat-spool rule as any other DIR.
	r := Analyze(Input{DagName: "wf.dag", Dag: "JOB A {\n    executable = /bin/true\n    transfer_executable = false\n} DIR sub\n"})
	if !r.Fatal() {
		t.Fatalf("a DIR on an inline node should be refused: %+v", r.Findings)
	}
}

func TestParseWeakParentChild(t *testing.T) {
	d := Parse("JOB A a.sub\nJOB B b.sub\nWEAK PARENT A CHILD B\n")
	if len(d.Errors) != 0 || len(d.Unrecognized) != 0 {
		t.Fatalf("WEAK PARENT did not parse: errors=%v unrecognized=%v", d.Errors, d.Unrecognized)
	}
	if len(d.Edges) != 1 || d.Edges[0].Parent != "A" || d.Edges[0].Child != "B" {
		t.Errorf("edges = %+v, want one A->B", d.Edges)
	}
}

func TestParseToleranceIsKnown(t *testing.T) {
	d := Parse("JOB A a.sub\nTOLERANCE A 0.5\n")
	if len(d.Unrecognized) != 0 {
		t.Errorf("TOLERANCE is a real DAG command: %+v", d.Unrecognized)
	}
}

func TestParseQuotingFollowsTheLexer(t *testing.T) {
	// dag_parser.cpp:35-77: either quote character groups a token, and a
	// backslash inside quotes escapes the next character.
	d := Parse("JOB A 'my file.sub'\n")
	if len(d.Nodes) != 1 {
		t.Fatalf("nodes = %+v, want 1", d.Nodes)
	}
	if d.Nodes[0].Descriptor != "my file.sub" {
		t.Errorf("descriptor = %q, want %q", d.Nodes[0].Descriptor, "my file.sub")
	}

	q := Parse(`JOB B "double quoted.sub"`)
	if len(q.Nodes) != 1 || q.Nodes[0].Descriptor != "double quoted.sub" {
		t.Errorf("double-quoted descriptor = %+v", q.Nodes)
	}

	esc := Parse(`JOB C "it\'s here.sub"`)
	if len(esc.Nodes) != 1 || esc.Nodes[0].Descriptor != "it's here.sub" {
		t.Errorf("escaped descriptor = %+v", esc.Nodes)
	}
}

func TestParseDotIncludeHeaderIsCollected(t *testing.T) {
	d := Parse("DOT wf.dot DONT-UPDATE OVERWRITE INCLUDE header.dot\n")
	if len(d.DotIncludes) != 1 || d.DotIncludes[0].Path != "header.dot" {
		t.Fatalf("DotIncludes = %+v, want header.dot", d.DotIncludes)
	}
	if len(d.Outputs) != 1 || d.Outputs[0].Path != "wf.dot" {
		t.Errorf("outputs = %+v, want the dot file itself", d.Outputs)
	}
}

// TestParseSetJobAttr: the value is whatever follows the first '=',
// verbatim. DAGMan keeps the whole line and condor_submit_dag writes
// `My.<line>` into the manager's submit file, so a parser that stripped
// quotes or normalized the expression would change what the attribute
// means -- "17" is a string and 17 is a number.
func TestParseSetJobAttr(t *testing.T) {
	d := Parse(`
SET_JOB_ATTR TestNumber = 17
SET_JOB_ATTR Label = "a phrase with spaces"
SET_JOB_ATTR Derived = (TestNumber + 1) * 2
SET-JOB-ATTR Dashed = True
`)
	if len(d.Errors) != 0 {
		t.Fatalf("unexpected parse errors: %+v", d.Errors)
	}
	want := []JobAttr{
		{Name: "TestNumber", Value: "17", Line: 2},
		{Name: "Label", Value: `"a phrase with spaces"`, Line: 3},
		{Name: "Derived", Value: "(TestNumber + 1) * 2", Line: 4},
		{Name: "Dashed", Value: "True", Line: 5},
	}
	if len(d.JobAttrs) != len(want) {
		t.Fatalf("JobAttrs = %+v, want %d", d.JobAttrs, len(want))
	}
	for i, w := range want {
		if d.JobAttrs[i] != w {
			t.Errorf("JobAttrs[%d] = %+v, want %+v", i, d.JobAttrs[i], w)
		}
	}
}

// TestParseSetJobAttrMalformed: a SET_JOB_ATTR that is not an assignment
// is reported rather than silently producing a submit-file line that
// makes the whole manager job unparseable.
func TestParseSetJobAttrMalformed(t *testing.T) {
	for _, line := range []string{
		"SET_JOB_ATTR",
		"SET_JOB_ATTR JustAName",
		"SET_JOB_ATTR = 17",
		"SET_JOB_ATTR Empty =",
	} {
		d := Parse(line + "\n")
		if len(d.JobAttrs) != 0 {
			t.Errorf("%q produced %+v, want nothing", line, d.JobAttrs)
		}
		if len(d.Errors) == 0 {
			t.Errorf("%q was accepted without complaint", line)
		}
	}
}

// TestParseEnvSetAndGet exercises the delimiters, which DIFFER between
// the two sub-commands: GET takes whitespace-separated names and SET
// takes a semicolon-delimited environment string (env.cpp's
// env_delimiter), or the whole thing double-quoted and space-separated.
// Reading SET as whitespace-separated turns `A=one two;B=3` into three
// variables, two of them nonsense.
func TestParseEnvSetAndGet(t *testing.T) {
	d := Parse(`
ENV GET PATH HOME TZ
ENV SET FOO=bar;BAZ=a value;
ENV SET "ONE=1 TWO=2"
`)
	if len(d.Errors) != 0 {
		t.Fatalf("unexpected parse errors: %+v", d.Errors)
	}
	if len(d.EnvGet) != 1 {
		t.Fatalf("EnvGet = %+v, want one command", d.EnvGet)
	}
	if got := strings.Join(d.EnvGet[0].Names, ","); got != "PATH,HOME,TZ" {
		t.Errorf("ENV GET names = %q, want PATH,HOME,TZ", got)
	}
	want := []EnvVar{
		{Name: "FOO", Value: "bar", Line: 3},
		{Name: "BAZ", Value: "a value", Line: 3},
		{Name: "ONE", Value: "1", Line: 4},
		{Name: "TWO", Value: "2", Line: 4},
	}
	if len(d.EnvSet) != len(want) {
		t.Fatalf("EnvSet = %+v, want %d pairs", d.EnvSet, len(want))
	}
	for i, w := range want {
		if d.EnvSet[i] != w {
			t.Errorf("EnvSet[%d] = %+v, want %+v", i, d.EnvSet[i], w)
		}
	}
}

// TestParseEnvMalformed: ENV without SET or GET, and a SET whose
// argument is not a pair, are the two shapes DagParser::ParseEnv
// refuses.
func TestParseEnvMalformed(t *testing.T) {
	for _, line := range []string{
		"ENV",
		"ENV PATH",
		"ENV SET",
		"ENV SET notapair",
		"ENV GET",
	} {
		d := Parse(line + "\n")
		if len(d.EnvSet) != 0 || len(d.EnvGet) != 0 {
			t.Errorf("%q produced EnvSet=%+v EnvGet=%+v, want nothing", line, d.EnvSet, d.EnvGet)
		}
		if len(d.Errors) == 0 {
			t.Errorf("%q was accepted without complaint", line)
		}
	}
}

// TestParseEnvAndSetJobAttrAreNotUnrecognized guards the move out of the
// "known, referencing no file" list: an unrecognized command is passed
// through to DAGMan untouched, which is exactly what must NOT happen to
// these two -- their whole effect is on the manager job's submit file,
// which DAGMan never sees.
func TestParseEnvAndSetJobAttrAreNotUnrecognized(t *testing.T) {
	d := Parse("SET_JOB_ATTR X = 1\nENV SET A=b\nENV GET PATH\n")
	if len(d.Unrecognized) != 0 {
		t.Errorf("Unrecognized = %+v, want none", d.Unrecognized)
	}
}

// TestParseVarsIntoPerNodeAssignments: the raw line was all this package
// kept, and a raw line cannot be substituted into a file name -- which is
// how a fan-out workflow's `result_$(sample).txt` went unmatched against
// the literal names the gather node reads.
func TestParseVarsIntoPerNodeAssignments(t *testing.T) {
	d := Parse(`
JOB A a.sub
JOB B b.sub
VARS A sample="1" label = "first run"
VARS A APPEND greeting="say \"hi\""
VARS A +Project="Chem" My.Group="grp"
VARS B PREPEND sample="2"
VARS ALL_NODES stage="prod"
VARS a sample="1b"
`)
	if len(d.Errors) > 0 {
		t.Fatalf("unexpected parse errors: %v", d.Errors)
	}
	for _, tc := range []struct{ node, name, want string }{
		// The last assignment of a name wins, and the node name is folded
		// exactly as DAGMan matches it.
		{"a", "sample", "1b"},
		// `name = value` with spaces around the '=' is one pair, and the
		// quoted value keeps its space.
		{"a", "label", "first run"},
		// A \" inside a quoted value is one literal quote.
		{"a", "greeting", `say "hi"`},
		// APPEND/PREPEND change where DAGMan writes the assignment, not
		// what it says.
		{"b", "sample", "2"},
		{"all_nodes", "stage", "prod"},
	} {
		if got := d.NodeVars[tc.node][tc.name]; got != tc.want {
			t.Errorf("NodeVars[%q][%q] = %q, want %q (all: %+v)", tc.node, tc.name, got, tc.want, d.NodeVars)
		}
	}
	// A +attr is a job-ad attribute, not a macro: expanding $(Project)
	// from one would invent a macro DAGMan never defines.
	if _, ok := d.NodeVars["a"]["project"]; ok {
		t.Errorf("a +attr entry became a submit macro: %+v", d.NodeVars["a"])
	}
	for name, want := range map[string]string{"My.Project": "Chem", "My.Group": "grp"} {
		if got := d.NodeAttrVars["a"][name]; got != want {
			t.Errorf("NodeAttrVars[a][%q] = %q, want %q (all: %+v)", name, got, want, d.NodeAttrVars["a"])
		}
	}
	// The raw text is still there for the messages that quote the author.
	if len(d.Vars["a"]) != 4 || d.VarNames["b"] != "B" {
		t.Errorf("the raw VARS material was lost: %v / %v", d.Vars, d.VarNames)
	}
}

func TestExpandNodeMacros(t *testing.T) {
	d := Parse(`
JOB Analyze a.sub
VARS Analyze sample="7" nested="run_$(sample)" self="$(self)"
VARS Analyze loopa="$(loopb)" loopb="$(loopa)"
VARS ALL_NODES stage="prod"
`)
	n, ok := d.NodeByName("Analyze")
	if !ok {
		t.Fatal("node Analyze not found")
	}
	for _, tc := range []struct {
		value, want string
		resolved    bool
	}{
		{"result_$(sample).txt", "result_7.txt", true},
		// Macro names are case-insensitive, as submit's are.
		{"$(SAMPLE)", "7", true},
		// $(JOB) is the node name, which DAGMan supplies to every node.
		{"$(JOB).out", "Analyze.out", true},
		{"$(stage)/$(sample)", "prod/7", true},
		// A VARS value that references another is expanded too.
		{"$(nested).log", "run_7.log", true},
		// DAGMan's own run-time macros are knowable only while the DAG
		// runs, so they stay put and the value counts as unresolved.
		{"input.$(RETRY)", "input.$(RETRY)", false},
		{"$(DAGManJobId)", "$(DAGManJobId)", false},
		// Neither a cycle nor a self-reference may loop.
		{"$(self)", "$(self)", false},
		{"$(loopa)", "$(loopa)", false},
		// A form this reader does not model is left alone rather than
		// half-substituted.
		{"$(sample:2)", "$(sample:2)", false},
		{"plain.txt", "plain.txt", true},
	} {
		got, resolved := expandNodeMacros(tc.value, n, d)
		if got != tc.want || resolved != tc.resolved {
			t.Errorf("expandNodeMacros(%q) = %q,%v; want %q,%v", tc.value, got, resolved, tc.want, tc.resolved)
		}
	}
}
