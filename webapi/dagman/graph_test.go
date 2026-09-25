package dagman

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// groupByLabel indexes a grouping by label, which is how every test here
// names the shape it expects.
func groupByLabel(t *testing.T, g *Grouping) map[string]Group {
	t.Helper()
	out := map[string]Group{}
	for _, grp := range g.Groups {
		if _, dup := out[grp.Label]; dup {
			t.Fatalf("two groups share the label %q: %+v", grp.Label, g.Groups)
		}
		out[grp.Label] = grp
	}
	return out
}

func TestCollapseFanOutGather(t *testing.T) {
	d := Parse(`
JOB setup setup.sub
JOB work_0 work.sub
JOB work_1 work.sub
JOB work_2 work.sub
JOB gather gather.sub
PARENT setup CHILD work_0 work_1 work_2
PARENT work_0 work_1 work_2 CHILD gather
`)
	g := Collapse(d)
	if g.Approximate {
		t.Fatalf("an acyclic DAG must not report approximate layering")
	}
	if g.NodeCount != 5 || g.EdgeCount != 6 {
		t.Fatalf("NodeCount/EdgeCount = %d/%d, want 5/6", g.NodeCount, g.EdgeCount)
	}
	if len(g.Groups) != 3 {
		t.Fatalf("got %d groups, want 3: %+v", len(g.Groups), g.Groups)
	}
	// Topological emission: the group a node depends on comes first.
	if g.Groups[0].Label != "setup" || g.Groups[1].Label != "work" || g.Groups[2].Label != "gather" {
		t.Fatalf("groups are not in topological order: %v %v %v",
			g.Groups[0].Label, g.Groups[1].Label, g.Groups[2].Label)
	}
	by := groupByLabel(t, g)
	if by["work"].Count != 3 {
		t.Errorf("the fan-out collapsed to Count %d, want 3", by["work"].Count)
	}
	if got := strings.Join(by["work"].Members, ","); got != "work_0,work_1,work_2" {
		t.Errorf("members = %q", got)
	}
	if by["work"].Description != "work.sub" {
		t.Errorf("Description = %q, want work.sub", by["work"].Description)
	}
	if len(by["setup"].ParentIDs) != 0 {
		t.Errorf("the root group has parents: %v", by["setup"].ParentIDs)
	}
	if got := by["work"].ParentIDs; len(got) != 1 || got[0] != by["setup"].ID {
		t.Errorf("work parents = %v, want [%s]", got, by["setup"].ID)
	}
	if got := by["gather"].ParentIDs; len(got) != 1 || got[0] != by["work"].ID {
		t.Errorf("gather parents = %v, want [%s]", got, by["work"].ID)
	}
}

// TestCollapseDiamondMergesEquivalentArms: B and C sit in the same place
// -- same parent, same child -- so a drawing shows one shape holding two
// nodes. They run different submit descriptions, and under the old
// description-based key they were two groups; a DOT file carries no
// descriptions, so position is all there is, and "two of these ran side
// by side" is the honest picture.
func TestCollapseDiamondMergesEquivalentArms(t *testing.T) {
	d := Parse(`
JOB A a.sub
JOB B b.sub
JOB C c.sub
JOB D d.sub
PARENT A CHILD B C
PARENT B C CHILD D
`)
	g := Collapse(d)
	if len(g.Groups) != 3 {
		t.Fatalf("got %d groups, want 3 (A, the B/C pair, D): %+v", len(g.Groups), g.Groups)
	}
	mid := g.Groups[1]
	if mid.Count != 2 || strings.Join(mid.Members, ",") != "B,C" {
		t.Fatalf("the middle group is %+v, want B and C together", mid)
	}
	if mid.Description != "" {
		t.Errorf("Description = %q; members running different descriptions must not claim one",
			mid.Description)
	}
	if got := g.Groups[2].ParentIDs; len(got) != 1 || got[0] != mid.ID {
		t.Errorf("D parents = %v, want [%s]", got, mid.ID)
	}
}

// TestCollapseSeparatesFanOutsThatFeedDifferentWork is the test the
// CHILD half of the structural key exists for.
//
// p1 and p2 are both roots and both fan out two ways, so the parent half
// alone puts all four workers in one group of four -- whose drawn edges
// would claim every worker descends from both roots. What tells them
// apart is downstream: the a's feed a gather node and the b's feed
// nothing. Refining by child group splits the workers, and that split
// propagates back and splits the roots on the same pass.
//
// Drop the child-set term and this test collapses to two groups.
func TestCollapseSeparatesFanOutsThatFeedDifferentWork(t *testing.T) {
	d := Parse(`
JOB p1 w.sub
JOB p2 w.sub
JOB a1 w.sub
JOB a2 w.sub
JOB b1 w.sub
JOB b2 w.sub
JOB gather w.sub
PARENT p1 CHILD a1 a2
PARENT p2 CHILD b1 b2
PARENT a1 a2 CHILD gather
`)
	g := Collapse(d)
	if len(g.Groups) != 5 {
		t.Fatalf("got %d groups, want 5 (p1, p2, the a's, the b's, gather): %+v",
			len(g.Groups), g.Groups)
	}
	by := groupByLabel(t, g)
	a, b := by["a"], by["b"]
	if a.Count != 2 || b.Count != 2 {
		t.Fatalf("the two fan-outs are %+v and %+v, want two nodes each", a, b)
	}
	if a.ID == b.ID {
		t.Fatalf("the two fan-outs collapsed into one group; the child set must keep them apart")
	}
	if len(a.ParentIDs) != 1 || len(b.ParentIDs) != 1 {
		t.Fatalf("each fan-out must have exactly one parent group: %v / %v", a.ParentIDs, b.ParentIDs)
	}
	if a.ParentIDs[0] == b.ParentIDs[0] {
		t.Errorf("both fan-outs claim the same parent group %s", a.ParentIDs[0])
	}
	if got := by["gather"].ParentIDs; len(got) != 1 || got[0] != a.ID {
		t.Errorf("gather parents = %v, want [%s]", got, a.ID)
	}
}

func TestCollapseNodeWithNoParents(t *testing.T) {
	d := Parse("JOB lonely lonely.sub\n")
	g := Collapse(d)
	if len(g.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(g.Groups))
	}
	grp := g.Groups[0]
	if grp.Count != 1 || grp.Label != "lonely" || len(grp.ParentIDs) != 0 {
		t.Errorf("unexpected group %+v", grp)
	}
	if g.EdgeCount != 0 {
		t.Errorf("EdgeCount = %d, want 0", g.EdgeCount)
	}
}

// TestCollapseIsolatedNodesAreOneGroup: three nodes with no edges at all
// occupy the same position -- no parents, no children -- so they are one
// group, whatever they run. The group refuses to name a description,
// because its members do not share one.
func TestCollapseIsolatedNodesAreOneGroup(t *testing.T) {
	d := Parse(`
JOB a {
	executable = /bin/echo
	queue
}
JOB b {
	executable = /bin/echo
	queue
}
JOB c c.sub
`)
	g := Collapse(d)
	if len(g.Groups) != 1 {
		t.Fatalf("got %d groups, want 1 (nothing distinguishes three isolated nodes): %+v",
			len(g.Groups), g.Groups)
	}
	if g.Groups[0].Count != 3 {
		t.Errorf("Count = %d, want 3", g.Groups[0].Count)
	}
	if g.Groups[0].Description != "" {
		t.Errorf("Description = %q, want empty: the members run different things",
			g.Groups[0].Description)
	}
}

// TestCollapseSharedDescriptionIsReported: when every member of a group
// DOES run the same description, the group says so. This is what a parsed
// .dag can add that a DOT file cannot.
func TestCollapseSharedDescriptionIsReported(t *testing.T) {
	d := Parse(`
JOB a {
	executable = /bin/echo
	queue
}
JOB b {
	executable = /bin/echo
	queue
}
`)
	g := Collapse(d)
	if len(g.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(g.Groups))
	}
	if g.Groups[0].Description != inlineMarker {
		t.Errorf("Description = %q, want the inline marker", g.Groups[0].Description)
	}
}

// TestCollapseCycleDoesNotHang is the safety net. Analyze refuses a cyclic
// DAG, so this should be unreachable in production -- but a hand-edited
// .dag can contain one and neither hanging nor panicking is an acceptable
// answer.
func TestCollapseCycleDoesNotHang(t *testing.T) {
	d := Parse(`
JOB a a.sub
JOB b b.sub
JOB c c.sub
PARENT a CHILD b
PARENT b CHILD c
PARENT c CHILD a
`)
	done := make(chan *Grouping, 1)
	go func() { done <- Collapse(d) }()
	select {
	case g := <-done:
		if !g.Approximate {
			t.Fatalf("a cyclic graph must report approximate layering")
		}
		if len(g.Groups) != 3 {
			t.Fatalf("got %d groups, want 3 (the fallback leaves every node on its own)", len(g.Groups))
		}
		if g.NodeCount != 3 || g.EdgeCount != 3 {
			t.Errorf("NodeCount/EdgeCount = %d/%d, want 3/3", g.NodeCount, g.EdgeCount)
		}
		for _, grp := range g.Groups {
			if len(grp.ParentIDs) != 1 {
				t.Errorf("group %s parents = %v, want one even in the fallback", grp.ID, grp.ParentIDs)
			}
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Collapse hung on a cyclic graph")
	}
}

// TestCollapseSelfEdgeIsNotACycle: a node that lists itself as its own
// parent is nonsense DAGMan rejects, but it must not make the whole
// layering approximate.
func TestCollapseSelfEdgeIsNotACycle(t *testing.T) {
	d := Parse("JOB a a.sub\nPARENT a CHILD a\n")
	g := Collapse(d)
	if g.Approximate {
		t.Errorf("a self-edge should be dropped, not treated as a cycle")
	}
	if g.EdgeCount != 0 {
		t.Errorf("EdgeCount = %d, want 0", g.EdgeCount)
	}
}

func TestParseWithFilesResolvesSpliceAndInclude(t *testing.T) {
	top := `
JOB pre pre.sub
INCLUDE extra.dag
SPLICE mid mid.dag
PARENT pre CHILD tail
`
	files := map[string]string{
		"extra.dag": "JOB tail tail.sub\n",
		"mid.dag":   "JOB x x.sub\nJOB y y.sub\nPARENT x CHILD y\n",
	}

	bare := Parse(top)
	if !bare.Incomplete {
		t.Fatalf("Parse without the files should leave the DAG Incomplete")
	}

	d := ParseWithFiles(top, files)
	if d.Incomplete {
		t.Fatalf("ParseWithFiles resolved nothing: %+v", d.Nodes)
	}
	names := map[string]bool{}
	for _, n := range d.Nodes {
		names[n.Name] = true
	}
	for _, want := range []string{"pre", "tail", "mid+x", "mid+y"} {
		if !names[want] {
			t.Errorf("node %q is missing; have %v", want, names)
		}
	}

	g := Collapse(d)
	// The SPLICE placeholder is not a node DAGMan runs, so it is not
	// drawn: pre, tail and the two spliced nodes are.
	if g.NodeCount != 4 {
		t.Errorf("NodeCount = %d, want 4 (the splice placeholder is not a node)", g.NodeCount)
	}
	if g.EdgeCount != 2 {
		t.Errorf("EdgeCount = %d, want 2 (pre->tail and the spliced x->y)", g.EdgeCount)
	}
	// Two isolated two-node chains are structurally the same chain, so
	// the roots collapse together and so do the leaves. The member lists
	// are what says which nodes those were.
	if len(g.Groups) != 2 {
		t.Fatalf("got %d groups, want 2: %+v", len(g.Groups), g.Groups)
	}
	roots, leaves := g.Groups[0], g.Groups[1]
	if strings.Join(roots.Members, ",") != "pre,mid+x" {
		t.Errorf("root group members = %v", roots.Members)
	}
	if strings.Join(leaves.Members, ",") != "tail,mid+y" {
		t.Errorf("leaf group members = %v", leaves.Members)
	}
	if got := leaves.ParentIDs; len(got) != 1 || got[0] != roots.ID {
		t.Errorf("the INCLUDE'd and spliced edges are missing: %v", got)
	}
}

// TestParseWithFilesSelfIncludeTerminates: a file that includes itself
// must be caught rather than recursed into forever.
func TestParseWithFilesSelfIncludeTerminates(t *testing.T) {
	done := make(chan *DAG, 1)
	go func() {
		done <- ParseWithFiles("JOB a a.sub\nINCLUDE loop.dag\n",
			map[string]string{"loop.dag": "JOB b b.sub\nINCLUDE loop.dag\n"})
	}()
	select {
	case d := <-done:
		if len(d.Nodes) != 2 {
			t.Errorf("got %d nodes, want 2", len(d.Nodes))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a self-including file recursed forever")
	}
}

// TestCollapseLargeFanOut is the reason this package collapses at all: a
// 50,000-node fan-out is a small workflow here, and a 100,000-node one is
// ordinary. It has to be three groups, and it has to be fast.
func TestCollapseLargeFanOut(t *testing.T) {
	const n = 50000
	var b strings.Builder
	b.WriteString("JOB setup setup.sub\nJOB gather gather.sub\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "JOB analyze_%d analyze.sub\n", i)
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "PARENT setup CHILD analyze_%d\nPARENT analyze_%d CHILD gather\n", i, i)
	}

	d := ParseWithFiles(b.String(), nil)
	if len(d.Nodes) != n+2 {
		t.Fatalf("parsed %d nodes, want %d", len(d.Nodes), n+2)
	}

	start := time.Now()
	g := Collapse(d)
	elapsed := time.Since(start)

	if len(g.Groups) != 3 {
		t.Fatalf("got %d groups, want 3: a 50,000-way fan-out is ONE group", len(g.Groups))
	}
	by := groupByLabel(t, g)
	if by["analyze"].Count != n {
		t.Errorf("the fan-out group holds %d nodes, want %d", by["analyze"].Count, n)
	}
	if g.EdgeCount != 2*n {
		t.Errorf("EdgeCount = %d, want %d", g.EdgeCount, 2*n)
	}
	if got := by["analyze"].ParentIDs; len(got) != 1 || got[0] != by["setup"].ID {
		t.Errorf("fan-out parents = %v", got)
	}
	if elapsed > time.Second {
		t.Errorf("Collapse took %v for %d nodes; it must be linear", elapsed, n+2)
	}
	t.Logf("collapsed %d nodes / %d edges in %v", g.NodeCount, g.EdgeCount, elapsed)
}

// --- the DOT file DAGMan writes ---------------------------------------

// sampleDot is byte for byte what Dag::DumpDotFile produces (dag.cpp
// ~2331): the header, a graph label, one line per node with the state in
// the label's parenthesised suffix, then one line per edge.
const sampleDot = `digraph DAG {
    label="DAGMan Job status at Mon Sep 22 10:11:12 2025";

    "setup" [shape=ellipse label="setup (Done)" style=bold];
    "work_0" [shape=ellipse label="work_0 (R)" peripheries=2];
    "work_1" [shape=ellipse label="work_1 (I)"];
    "work_2" [shape=ellipse label="work_2 (Pre)" style=dotted];
    "work_3" [shape=ellipse label="work_3 (Post)" style=dotted];
    "gather" [shape=box label="gather (E)"];

    "setup" -> "work_0";
    "setup" -> "work_1";
    "setup" -> "work_2";
    "setup" -> "work_3";
    "work_0" -> "gather";
    "work_1" -> "gather";
    "work_2" -> "gather";
    "work_3" -> "gather";
}
`

func TestParseDot(t *testing.T) {
	g, err := ParseDot(strings.NewReader(sampleDot))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	if len(g.Nodes) != 6 {
		t.Fatalf("got %d nodes, want 6: %+v", len(g.Nodes), g.Nodes)
	}
	if len(g.Edges) != 8 {
		t.Fatalf("got %d edges, want 8: %+v", len(g.Edges), g.Edges)
	}
	want := map[string]string{
		"setup": DotStateDone, "work_0": DotStateRunning, "work_1": DotStateIdle,
		"work_2": DotStatePre, "work_3": DotStatePost, "gather": DotStateError,
	}
	for _, n := range g.Nodes {
		if want[n.Name] != n.State {
			t.Errorf("node %s state = %q, want %q", n.Name, n.State, want[n.Name])
		}
		if n.Description != "" {
			t.Errorf("node %s claims a description %q; a DOT file carries none", n.Name, n.Description)
		}
	}
	if g.Edges[0].Parent != "setup" || g.Edges[0].Child != "work_0" {
		t.Errorf("first edge = %+v", g.Edges[0])
	}
}

// TestParseDotCollapses is the whole point of reading the file: the
// structure it carries collapses to the drawing.
func TestParseDotCollapses(t *testing.T) {
	g, err := ParseDot(strings.NewReader(sampleDot))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	c := CollapseGraph(g)
	if c.NodeCount != 6 || c.EdgeCount != 8 {
		t.Fatalf("NodeCount/EdgeCount = %d/%d, want 6/8", c.NodeCount, c.EdgeCount)
	}
	if len(c.Groups) != 3 {
		t.Fatalf("got %d groups, want 3 (setup, the four workers, gather): %+v", len(c.Groups), c.Groups)
	}
	if c.Groups[1].Count != 4 || c.Groups[1].Label != "work" {
		t.Errorf("the fan-out group is %+v", c.Groups[1])
	}
	if c.Groups[1].Description != "" {
		t.Errorf("a DOT-derived group claims a description: %q", c.Groups[1].Description)
	}
}

// TestParseDotTolerance: quoting, attribute order, an INCLUDE header's
// verbatim graphviz, comments and a truncated tail all have to be
// survivable. DAGMan rewrites this file in place when the DAG says
// UPDATE, so a half-written one is a thing we will read.
func TestParseDotTolerance(t *testing.T) {
	g, err := ParseDot(strings.NewReader(`digraph DAG {
    label="DAGMan Job status at Mon Sep 22 10:11:12 2025";

// Beginning of commands included from header.dot.
node [shape=box];
edge [color=blue];
rankdir=LR;
// End of commands included from header.dot.

    "a" [label="a (Done)" shape=ellipse style=bold];
    "b-with-dashes" [shape=ellipse label="b-with-dashes (I)"];
    "c" [shape=ellipse];
    "a" -> "b-with-dashes";
    "b-with-dashes" -> "c"
    "c" [shape=ellipse label="c (Don`))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	names := map[string]string{}
	for _, n := range g.Nodes {
		names[n.Name] = n.State
	}
	if len(names) != 3 {
		t.Fatalf("got %d nodes, want 3 (a, b-with-dashes, c): %v", len(names), names)
	}
	if names["a"] != DotStateDone {
		t.Errorf("a state = %q; the label came before the shape", names["a"])
	}
	if state, ok := names["c"]; !ok || state != "" {
		t.Errorf("c = %q, %v; a node with no readable state must still be a node", state, ok)
	}
	if len(g.Edges) != 2 {
		t.Errorf("got %d edges, want 2 (a missing semicolon is still an edge): %+v", len(g.Edges), g.Edges)
	}
}

func TestParseDotEmpty(t *testing.T) {
	g, err := ParseDot(strings.NewReader("digraph DAG {\n}\n"))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	if len(g.Nodes) != 0 || len(g.Edges) != 0 {
		t.Errorf("an empty graph gave %+v", g)
	}
	if c := CollapseGraph(g); len(c.Groups) != 0 || c.NodeCount != 0 {
		t.Errorf("collapsing an empty graph gave %+v", c)
	}
}
