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
	d := Parse("JOB A a.sub\nTOLERANCE A 0.5\nSOME-FUTURE-COMMAND A whatever\n")
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
