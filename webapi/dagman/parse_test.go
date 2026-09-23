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
