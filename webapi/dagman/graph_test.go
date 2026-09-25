package dagman

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// groupsByLabel indexes a grouping by label, which is how most tests here
// name the shape they expect.
//
// Labels are NOT unique in general: a group whose members share no useful
// prefix falls back to the description they run, and two such groups can
// carry the same one. So this collects every group under its label, and a
// test that means "the one group called X" says so with oneGroup.
func groupsByLabel(g *Grouping) map[string][]Group {
	out := map[string][]Group{}
	for _, grp := range g.Groups {
		out[grp.Label] = append(out[grp.Label], grp)
	}
	return out
}

// oneGroup is the single group with this label, and a failure when there
// is not exactly one.
func oneGroup(t *testing.T, by map[string][]Group, label string) Group {
	t.Helper()
	got := by[label]
	if len(got) != 1 {
		t.Fatalf("want exactly one group labelled %q, got %d: %+v", label, len(got), got)
	}
	return got[0]
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
	by := groupsByLabel(g)
	setup, work, gather := oneGroup(t, by, "setup"), oneGroup(t, by, "work"), oneGroup(t, by, "gather")
	if work.Count != 3 {
		t.Errorf("the fan-out collapsed to Count %d, want 3", work.Count)
	}
	if got := strings.Join(work.Members, ","); got != "work_0,work_1,work_2" {
		t.Errorf("members = %q", got)
	}
	if work.Description != "work.sub" {
		t.Errorf("Description = %q, want work.sub", work.Description)
	}
	if len(setup.ParentIDs) != 0 {
		t.Errorf("the root group has parents: %v", setup.ParentIDs)
	}
	if got := work.ParentIDs; len(got) != 1 || got[0] != setup.ID {
		t.Errorf("work parents = %v, want [%s]", got, setup.ID)
	}
	if got := gather.ParentIDs; len(got) != 1 || got[0] != work.ID {
		t.Errorf("gather parents = %v, want [%s]", got, work.ID)
	}
	if g.LinkCount != 2 {
		t.Errorf("LinkCount = %d, want 2 group links for 6 edges", g.LinkCount)
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
	by := groupsByLabel(g)
	a, b := oneGroup(t, by, "a"), oneGroup(t, by, "b")
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
	if got := oneGroup(t, by, "gather").ParentIDs; len(got) != 1 || got[0] != a.ID {
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
	if grp.Count != 1 || grp.Label != "lonely" {
		t.Errorf("unexpected group %+v", grp)
	}
	if got := strings.Join(grp.Members, ","); got != "lonely" {
		t.Errorf("members = %q, want the node itself", got)
	}
	if grp.ParentIDs != nil {
		t.Errorf("ParentIDs = %v, want none at all", grp.ParentIDs)
	}
	if g.NodeCount != 1 || g.EdgeCount != 0 || g.LinkCount != 0 {
		t.Errorf("NodeCount/EdgeCount/LinkCount = %d/%d/%d, want 1/0/0",
			g.NodeCount, g.EdgeCount, g.LinkCount)
	}
	if g.Approximate || g.ApproximateReason != "" || g.Truncated || g.Incomplete || g.DanglingEdges != 0 {
		t.Errorf("a one-node DAG raised a flag: %+v", g)
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
	d := Parse("JOB a a.sub\nJOB b b.sub\nPARENT a CHILD a b\n")
	g := Collapse(d)
	if g.Approximate {
		t.Errorf("a self-edge should be dropped, not treated as a cycle: %+v", g)
	}
	if g.EdgeCount != 1 || g.DanglingEdges != 0 {
		t.Errorf("EdgeCount/DanglingEdges = %d/%d, want 1/0: a->a is dropped, a->b is not",
			g.EdgeCount, g.DanglingEdges)
	}
	if len(g.Groups) != 2 {
		t.Fatalf("got %d groups, want 2 (a then b): %+v", len(g.Groups), g.Groups)
	}
	if g.Groups[0].Members[0] != "a" || g.Groups[1].Members[0] != "b" {
		t.Errorf("groups are %+v, want a then b", g.Groups)
	}
	if got := g.Groups[1].ParentIDs; len(got) != 1 || got[0] != g.Groups[0].ID {
		t.Errorf("b parents = %v, want [%s]", got, g.Groups[0].ID)
	}
	if got := g.Groups[0].ParentIDs; len(got) != 0 {
		t.Errorf("a parents = %v; the self-edge must not become a group self-link", got)
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

	g := Collapse(d)

	if len(g.Groups) != 3 {
		t.Fatalf("got %d groups, want 3: a 50,000-way fan-out is ONE group", len(g.Groups))
	}
	by := groupsByLabel(g)
	setup, analyze, gather := oneGroup(t, by, "setup"), oneGroup(t, by, "analyze"), oneGroup(t, by, "gather")
	if analyze.Count != n || len(analyze.Members) != n {
		t.Errorf("the fan-out group holds %d nodes (%d members), want %d",
			analyze.Count, len(analyze.Members), n)
	}
	// Every worker, not just the count: a grouping that put two of them
	// somewhere else would still have the right number of groups.
	seen := make(map[string]bool, n)
	for _, m := range analyze.Members {
		seen[m] = true
	}
	for i := 0; i < n; i++ {
		if !seen[fmt.Sprintf("analyze_%d", i)] {
			t.Fatalf("analyze_%d is not in the fan-out group", i)
		}
	}
	if setup.Count != 1 || gather.Count != 1 {
		t.Errorf("setup/gather hold %d/%d nodes, want one each", setup.Count, gather.Count)
	}
	if g.NodeCount != n+2 || g.EdgeCount != 2*n {
		t.Errorf("NodeCount/EdgeCount = %d/%d, want %d/%d", g.NodeCount, g.EdgeCount, n+2, 2*n)
	}
	if g.LinkCount != 2 {
		t.Errorf("LinkCount = %d, want 2: %d edges are TWO lines in a drawing", g.LinkCount, 2*n)
	}
	if got := analyze.ParentIDs; len(got) != 1 || got[0] != setup.ID {
		t.Errorf("fan-out parents = %v", got)
	}
	if got := gather.ParentIDs; len(got) != 1 || got[0] != analyze.ID {
		t.Errorf("gather parents = %v", got)
	}
	if g.Approximate {
		t.Errorf("a fan-out must not be approximate: %q", g.ApproximateReason)
	}
}

// BenchmarkCollapseLargeFanOut is where the speed of that belongs. A
// wall-clock assertion in the test above was a CI flake waiting to
// happen; a benchmark says the same thing and says it in numbers.
func BenchmarkCollapseLargeFanOut(b *testing.B) {
	const n = 50000
	var s strings.Builder
	s.WriteString("JOB setup setup.sub\nJOB gather gather.sub\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&s, "JOB analyze_%d analyze.sub\n", i)
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&s, "PARENT setup CHILD analyze_%d\nPARENT analyze_%d CHILD gather\n", i, i)
	}
	d := ParseWithFiles(s.String(), nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if g := Collapse(d); len(g.Groups) != 3 {
			b.Fatalf("got %d groups", len(g.Groups))
		}
	}
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

// TestParseDotEmpty: a DAG with no nodes at all. The assertion that
// matters is not the empty node list -- a parser that dropped everything
// would pass that -- but that the file was seen WHOLE, which is what
// distinguishes "this workflow has no nodes" from "we read nothing".
func TestParseDotEmpty(t *testing.T) {
	g, err := ParseDot(strings.NewReader("digraph DAG {\n    label=\"DAGMan Job status\";\n}\n"))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	if len(g.Nodes) != 0 || len(g.Edges) != 0 {
		t.Errorf("an empty graph gave %+v", g)
	}
	if !g.SawHeader || !g.SawFooter || g.Truncated {
		t.Errorf("a complete empty file reads as truncated: %+v", g)
	}
	c := CollapseGraph(g)
	if len(c.Groups) != 0 || c.NodeCount != 0 {
		t.Errorf("collapsing an empty graph gave %+v", c)
	}
	if c.Truncated {
		t.Errorf("Grouping.Truncated set for a whole file")
	}
	// The same parser on the same file, one node added, must find it --
	// otherwise the assertions above are vacuous.
	full, err := ParseDot(strings.NewReader("digraph DAG {\n    \"a\" [shape=ellipse label=\"a (I)\"];\n}\n"))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	if len(full.Nodes) != 1 || full.Nodes[0].Name != "a" || full.Nodes[0].State != DotStateIdle {
		t.Fatalf("the one-node control file parsed as %+v", full.Nodes)
	}
}

// --- depth: the refinement has to carry a split the whole way ---------

// chainDAG is n nodes in a line: step_0 -> step_1 -> ... -> step_n-1.
func chainDAG(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "JOB step_%d step.sub\n", i)
	}
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, "PARENT step_%d CHILD step_%d\n", i-1, i)
	}
	return b.String()
}

// TestCollapseDeepChainIsOnePerStep is the regression test for a
// refinement that propagated one edge per pass.
//
// Every node of a chain is in a different position, so a chain of 100 is
// 100 groups and nothing about it is approximate. Reading the PRE-pass
// numbering for the neighbours instead of the one the pass is producing
// moves a distinction exactly one edge per pass, needs depth/2 rounds,
// and hits the round bound at about 65 nodes: a 1000-node chain then
// collapses to 66 groups, one of them holding 935 nodes from all over the
// workflow, and the dependencies inside that group are not drawn at all.
func TestCollapseDeepChainIsOnePerStep(t *testing.T) {
	for _, n := range []int{10, 100, 1000} {
		g := Collapse(Parse(chainDAG(n)))
		if g.Approximate {
			t.Fatalf("chain of %d: Approximate (%s); a chain settles in one round",
				n, g.ApproximateReason)
		}
		if len(g.Groups) != n {
			t.Fatalf("chain of %d collapsed to %d groups, want one per step", n, len(g.Groups))
		}
		if g.NodeCount != n || g.EdgeCount != n-1 || g.LinkCount != n-1 {
			t.Fatalf("chain of %d: NodeCount/EdgeCount/LinkCount = %d/%d/%d",
				n, g.NodeCount, g.EdgeCount, g.LinkCount)
		}
		for i, grp := range g.Groups {
			want := fmt.Sprintf("step_%d", i)
			if grp.Count != 1 || grp.Members[0] != want {
				t.Fatalf("chain of %d: group %d is %+v, want just %s", n, i, grp, want)
			}
		}
	}
}

// TestCollapsePipelineKeepsStagesApart: 40 stages of one gate and three
// workers. Every stage is a different position in the workflow, so the
// answer is 80 groups -- a gate and a worker group per stage -- and NOT
// the 66 a bounded-out refinement produces, which mixes gates and workers
// from unrelated stages into one shape.
func TestCollapsePipelineKeepsStagesApart(t *testing.T) {
	const stages, width = 40, 3
	var b strings.Builder
	for s := 0; s < stages; s++ {
		fmt.Fprintf(&b, "JOB gate_%02d gate.sub\n", s)
		for w := 0; w < width; w++ {
			fmt.Fprintf(&b, "JOB work_%02d_%d work.sub\n", s, w)
		}
	}
	for s := 0; s < stages; s++ {
		for w := 0; w < width; w++ {
			fmt.Fprintf(&b, "PARENT gate_%02d CHILD work_%02d_%d\n", s, s, w)
			if s+1 < stages {
				fmt.Fprintf(&b, "PARENT work_%02d_%d CHILD gate_%02d\n", s, w, s+1)
			}
		}
	}
	g := Collapse(Parse(b.String()))
	if g.Approximate {
		t.Fatalf("a 160-node pipeline came out approximate (%s)", g.ApproximateReason)
	}
	if g.NodeCount != stages*(width+1) {
		t.Fatalf("NodeCount = %d, want %d", g.NodeCount, stages*(width+1))
	}
	if len(g.Groups) != 2*stages {
		t.Fatalf("got %d groups, want %d (one gate and one worker group per stage)",
			len(g.Groups), 2*stages)
	}
	for s := 0; s < stages; s++ {
		gate, work := g.Groups[2*s], g.Groups[2*s+1]
		if gate.Count != 1 || gate.Members[0] != fmt.Sprintf("gate_%02d", s) {
			t.Fatalf("group %d is %+v, want gate_%02d alone", 2*s, gate, s)
		}
		if work.Count != width {
			t.Fatalf("stage %d workers collapsed to %+v, want %d nodes", s, work, width)
		}
		for _, m := range work.Members {
			if !strings.HasPrefix(m, fmt.Sprintf("work_%02d_", s)) {
				t.Fatalf("stage %d worker group holds %q, from another stage", s, m)
			}
		}
	}
}

// combDAG is a spine of k nodes with one leaf hanging off each. It is the
// shape that needs a second round to settle (the first round splits the
// spine, the second propagates that back into the leaves), so it is what
// a lowered round bound can be tested against.
func combDAG(k int) string {
	var b strings.Builder
	for i := 0; i < k; i++ {
		fmt.Fprintf(&b, "JOB s_%03d s.sub\nJOB l_%03d l.sub\n", i, i)
	}
	for i := 0; i < k; i++ {
		fmt.Fprintf(&b, "PARENT s_%03d CHILD l_%03d\n", i, i)
		if i+1 < k {
			fmt.Fprintf(&b, "PARENT s_%03d CHILD s_%03d\n", i, i+1)
		}
	}
	return b.String()
}

// TestCollapseBoundedRefinementIsStillACoarsening: when the refinement
// runs out of rounds, the result must be a COARSENING of the true answer
// -- groups that are too big -- and never a drawing with dependencies
// missing. Every member's parent has to be represented by a group link,
// including a link from a group to itself, and the caller has to be told
// which of the two approximations it got.
func TestCollapseBoundedRefinementIsStillACoarsening(t *testing.T) {
	saved := collapseMaxRounds
	collapseMaxRounds = 1 // a comb needs two
	t.Cleanup(func() { collapseMaxRounds = saved })

	d := Parse(combDAG(32))
	g := Collapse(d)
	if !g.Approximate || g.ApproximateReason != ApproximateUnsettled {
		t.Fatalf("Approximate/%q = %v/%q, want true/%q",
			"reason", g.Approximate, g.ApproximateReason, ApproximateUnsettled)
	}
	if g.ApproximateReason == ApproximateCycle {
		t.Fatalf("a bounded refinement must not be reported as a cycle")
	}
	// Index every node to its group, then check every dependency.
	groupOf := map[string]string{}
	for _, grp := range g.Groups {
		for _, m := range grp.Members {
			groupOf[m] = grp.ID
		}
	}
	links := map[[2]string]bool{}
	for _, grp := range g.Groups {
		for _, p := range grp.ParentIDs {
			links[[2]string{p, grp.ID}] = true
		}
	}
	graph := GraphFromDAG(d)
	if len(graph.Edges) == 0 {
		t.Fatal("the fixture has no edges")
	}
	for _, e := range graph.Edges {
		pg, cg := groupOf[e.Parent], groupOf[e.Child]
		if pg == "" || cg == "" {
			t.Fatalf("edge %+v names a node in no group", e)
		}
		if !links[[2]string{pg, cg}] {
			t.Fatalf("edge %s -> %s (%s -> %s) is not drawn: the capped grouping lost a dependency",
				e.Parent, e.Child, pg, cg)
		}
	}
	// And the bound really was what stopped it: with the real bound the
	// same DAG settles.
	collapseMaxRounds = saved
	if full := Collapse(d); full.Approximate {
		t.Fatalf("a comb is not pathological; it settled only under the lowered bound")
	}
}

// TestCollapseIsDeterministic: the same DAG must produce byte-identical
// output every time, or a UI that diffs two fetches shows churn that is
// not there.
func TestCollapseIsDeterministic(t *testing.T) {
	d := ParseWithFiles(`
JOB prep prep.sub
JOB a_0 w.sub
JOB a_1 w.sub
JOB b_0 w.sub
SPLICE mid mid.dag
JOB gather g.sub
PARENT prep CHILD a_0 a_1 b_0
PARENT a_0 a_1 CHILD gather
PARENT b_0 CHILD mid
PARENT mid CHILD gather
`, map[string]string{"mid.dag": "JOB x x.sub\nJOB y y.sub\nPARENT x CHILD y\n"})

	first, err := json.Marshal(Collapse(d))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		got, err := json.Marshal(Collapse(d))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Equal(first, got) {
			t.Fatalf("collapse %d differs:\n%s\n%s", i, first, got)
		}
	}
}

// --- node identity ----------------------------------------------------

// TestCollapseNodeNamesAreCaseSensitive: DAGMan's node name table is a
// std::map<std::string,...> with a plain strcmp (dag.cpp:1229-1241), so
// `Work` and `work` are two nodes. Folding them here deleted one of them
// AND its dependencies.
func TestCollapseNodeNamesAreCaseSensitive(t *testing.T) {
	d := Parse(`
JOB setup setup.sub
JOB Work Work.sub
JOB work work.sub
PARENT setup CHILD Work
PARENT Work CHILD work
`)
	g := Collapse(d)
	if g.NodeCount != 3 {
		t.Fatalf("NodeCount = %d, want 3: Work and work are different nodes", g.NodeCount)
	}
	if g.EdgeCount != 2 || g.DanglingEdges != 0 {
		t.Fatalf("EdgeCount/DanglingEdges = %d/%d, want 2/0", g.EdgeCount, g.DanglingEdges)
	}
	if len(g.Groups) != 3 {
		t.Fatalf("got %d groups, want 3 (a chain): %+v", len(g.Groups), g.Groups)
	}
	want := []string{"setup", "Work", "work"}
	for i, grp := range g.Groups {
		if grp.Count != 1 || grp.Members[0] != want[i] {
			t.Fatalf("group %d is %+v, want %s alone", i, grp, want[i])
		}
	}

	// The same through the DOT reader, which is the path a running
	// workflow takes.
	dot, err := ParseDot(strings.NewReader(`digraph DAG {
    "Work" [shape=ellipse label="Work (R)"];
    "work" [shape=ellipse label="work (I)"];
    "Work" -> "work";
}
`))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	c := CollapseGraph(dot)
	if c.NodeCount != 2 || c.EdgeCount != 1 {
		t.Fatalf("DOT path: NodeCount/EdgeCount = %d/%d, want 2/1", c.NodeCount, c.EdgeCount)
	}
	states := map[string]string{}
	for _, n := range dot.Nodes {
		states[n.Name] = n.State
	}
	if states["Work"] != DotStateRunning || states["work"] != DotStateIdle {
		t.Errorf("states = %v; the two nodes' states were merged", states)
	}
}

// --- the names DAGMan actually allows ---------------------------------

// TestParseDotExoticNodeNames: DAGMan forbids exactly ONE character in a
// node name -- '+', which it reserves for splice scopes
// (condor_dagman/parse.cpp ILLEGAL_CHARS) -- and writes the name into the
// DOT file with no escaping at all. Spaces, brackets, parentheses, the
// graphviz keywords and even "->" are legal names, and a parser that
// looks for "->" or "[" before reading the quoted token deletes the node
// AND every edge that touches it.
func TestParseDotExoticNodeNames(t *testing.T) {
	g, err := ParseDot(strings.NewReader(`digraph DAG {
    label="DAGMan Job status at Mon Sep 22 10:11:12 2025";

    "a->b" [shape=ellipse label="a->b (I)"];
    "a[0]" [shape=ellipse label="a[0] (R)"];
    "my node" [shape=ellipse label="my node (Done)"];
    "foo (R)" [shape=ellipse label="foo (R) (I)"];
    "node" [shape=ellipse label="node (I)"];
    "graph" [shape=ellipse label="graph (Done)"];
    "c" [shape=ellipse label="c (I)"];

    "a->b" -> "c";
    "a[0]" -> "c";
    "my node" -> "c";
    "foo (R)" -> "c";
    "node" -> "graph";
}
`))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	want := map[string]string{
		"a->b": DotStateIdle, "a[0]": DotStateRunning, "my node": DotStateDone,
		"foo (R)": DotStateIdle, "node": DotStateIdle, "graph": DotStateDone,
		"c": DotStateIdle,
	}
	got := map[string]string{}
	for _, n := range g.Nodes {
		got[n.Name] = n.State
	}
	for name, state := range want {
		s, ok := got[name]
		if !ok {
			t.Errorf("node %q was deleted; have %v", name, got)
			continue
		}
		if s != state {
			t.Errorf("node %q state = %q, want %q", name, s, state)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d nodes, want %d: %v", len(got), len(want), got)
	}
	if len(g.Edges) != 5 {
		t.Fatalf("got %d edges, want 5: %+v", len(g.Edges), g.Edges)
	}
	if g.Edges[0].Parent != "a->b" || g.Edges[0].Child != "c" {
		t.Errorf("first edge = %+v, want a->b -> c", g.Edges[0])
	}
	// And they all resolve: nothing was dropped as dangling.
	c := CollapseGraph(g)
	if c.NodeCount != 7 || c.EdgeCount != 5 || c.DanglingEdges != 0 {
		t.Errorf("NodeCount/EdgeCount/DanglingEdges = %d/%d/%d, want 7/5/0",
			c.NodeCount, c.EdgeCount, c.DanglingEdges)
	}
}

// TestParseDotNameWithQuoteIsTruncated documents the one name that cannot
// survive the round trip: DAGMan does not escape a double quote, so
// `a"b` is written as `"a"b"` and there is no way to read it back. The
// node is kept under the truncated name -- losing the node would take its
// children's parent with it -- and its state is lost.
func TestParseDotNameWithQuoteIsTruncated(t *testing.T) {
	g, err := ParseDot(strings.NewReader(`digraph DAG {
    "a"b" [shape=ellipse label="a"b" (I)"];
    "c" [shape=ellipse label="c (I)"];
    "a"b" -> "c";
}
`))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	if len(g.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2: %+v", len(g.Nodes), g.Nodes)
	}
	if g.Nodes[0].Name != "a" || g.Nodes[0].State != "" {
		t.Errorf("node = %+v, want the truncated name %q with no state", g.Nodes[0], "a")
	}
	if len(g.Edges) != 1 || g.Edges[0].Parent != "a" || g.Edges[0].Child != "c" {
		t.Errorf("edges = %+v, want the same truncation on both ends", g.Edges)
	}
}

// --- a file read while DAGMan is rewriting it -------------------------

// TestParseDotTornReadIsFlagged: DAGMan unlinks and renames when it
// rewrites the DOT file (repeatedly, when the DAG says UPDATE), so
// reading a zero-length or half-written one is a real window. The
// generator writes ALL node lines and then ALL arc lines, so the usual
// torn read is a graph with its DEPENDENCIES missing -- which renders,
// confidently, as a workflow where nothing depends on anything. The
// signal is what this asserts; the node count on its own cannot tell a
// torn file from a small workflow.
func TestParseDotTornReadIsFlagged(t *testing.T) {
	cases := []struct {
		name           string
		text           string
		header, footer bool
		nodes, edges   int
	}{
		{"zero length", "", false, false, 0, 0},
		{"header only", "digraph DAG {\n", true, false, 0, 0},
		{"nodes but no arcs yet", `digraph DAG {
    "a" [shape=ellipse label="a (I)"];
    "b" [shape=ellipse label="b (I)"];
`, true, false, 2, 0},
		{"whole file", `digraph DAG {
    "a" [shape=ellipse label="a (I)"];
    "b" [shape=ellipse label="b (I)"];
    "a" -> "b";
}
`, true, true, 2, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := ParseDot(strings.NewReader(tc.text))
			if err != nil {
				t.Fatalf("ParseDot: %v", err)
			}
			if g.SawHeader != tc.header || g.SawFooter != tc.footer {
				t.Errorf("SawHeader/SawFooter = %v/%v, want %v/%v",
					g.SawHeader, g.SawFooter, tc.header, tc.footer)
			}
			wantTruncated := !tc.header || !tc.footer
			if g.Truncated != wantTruncated {
				t.Errorf("Truncated = %v, want %v", g.Truncated, wantTruncated)
			}
			if len(g.Nodes) != tc.nodes || len(g.Edges) != tc.edges {
				t.Errorf("got %d nodes / %d edges, want %d/%d",
					len(g.Nodes), len(g.Edges), tc.nodes, tc.edges)
			}
			if c := CollapseGraph(g); c.Truncated != wantTruncated {
				t.Errorf("Grouping.Truncated = %v, want %v", c.Truncated, wantTruncated)
			}
		})
	}
}

// TestCollapseCountsDanglingEdges: an arc naming a node that has no node
// line is dropped -- it cannot be drawn -- but dropping it SILENTLY is
// how a torn read, or a `DOT ... INCLUDE` header whose text parsed as an
// arc, turns into a confident wrong picture.
func TestCollapseCountsDanglingEdges(t *testing.T) {
	g, err := ParseDot(strings.NewReader(`digraph DAG {
    "a" [shape=ellipse label="a (I)"];
    "b" [shape=ellipse label="b (I)"];
    "a" -> "b";
    "a" -> "ghost";
    "ghost" -> "b";
}
`))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}
	if len(g.Edges) != 3 {
		t.Fatalf("got %d edges, want 3 before resolving: %+v", len(g.Edges), g.Edges)
	}
	c := CollapseGraph(g)
	if c.EdgeCount != 1 {
		t.Errorf("EdgeCount = %d, want 1", c.EdgeCount)
	}
	if c.DanglingEdges != 2 {
		t.Errorf("DanglingEdges = %d, want 2: the drop has to be reported", c.DanglingEdges)
	}
}

// TestParseDotOverLongLineSkipsOnlyThatLine: one corrupt or enormous line
// must cost that line and nothing else. bufio.Scanner's 1 MiB cap used to
// abort the whole parse with ErrTooLong, which is the opposite of the
// stated policy and threw away every other node in the file.
func TestParseDotOverLongLineSkipsOnlyThatLine(t *testing.T) {
	var b strings.Builder
	b.WriteString("digraph DAG {\n")
	b.WriteString("    \"a\" [shape=ellipse label=\"a (I)\"];\n")
	b.WriteString("    \"" + strings.Repeat("x", dotMaxLineBytes+1024) + "\" [shape=ellipse label=\"long (I)\"];\n")
	b.WriteString("    \"b\" [shape=ellipse label=\"b (Done)\"];\n")
	b.WriteString("    \"a\" -> \"b\";\n")
	b.WriteString("}\n")

	g, err := ParseDot(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("ParseDot refused the whole file over one line: %v", err)
	}
	if g.SkippedLines != 1 {
		t.Errorf("SkippedLines = %d, want 1", g.SkippedLines)
	}
	if len(g.Nodes) != 2 || g.Nodes[0].Name != "a" || g.Nodes[1].Name != "b" {
		t.Fatalf("nodes = %+v, want a and b", g.Nodes)
	}
	if len(g.Edges) != 1 {
		t.Errorf("edges = %+v, want the one after the long line", g.Edges)
	}
	if !g.SawHeader || !g.SawFooter {
		t.Errorf("the framing was lost with the long line: %+v", g)
	}
}

// --- the DAG-derived path and the DOT-derived one, on one workflow ----

// TestDAGAndDotAgree is the equivalence harness: the same workflow, once
// as a .dag this package parses and once as the DOT file DAGMan would
// emit for it, has to collapse to the same drawing. Everything that
// differs between the two paths -- splice placeholders that are not
// nodes, sub-DAGs, a FINAL node -- is in it on purpose.
//
// The one thing that cannot match is Description: a DOT file carries
// none. That is compared separately.
func TestDAGAndDotAgree(t *testing.T) {
	dag := `
JOB prep prep.sub
JOB work_0 work.sub
JOB work_1 work.sub
SPLICE mid mid.dag
SUBDAG EXTERNAL sub sub.dag
FINAL cleanup cleanup.sub
PARENT prep CHILD work_0 work_1
PARENT work_0 work_1 CHILD mid
PARENT mid CHILD sub
`
	d := ParseWithFiles(dag, map[string]string{
		"mid.dag": "JOB x x.sub\nJOB y y.sub\nPARENT x CHILD y\n",
	})
	if d.Incomplete {
		t.Fatalf("the splice did not resolve: %+v", d.Fatals)
	}

	// What Dag::DumpDotFile writes for exactly that workflow: the splice
	// placeholder is not a node (its nodes are, under the "mid+" scope),
	// the SUBDAG and FINAL nodes are, and the splice-boundary
	// dependencies are written against the splice's real nodes.
	dot := `digraph DAG {
    label="DAGMan Job status at Mon Sep 22 10:11:12 2025";

    "prep" [shape=ellipse label="prep (I)"];
    "work_0" [shape=ellipse label="work_0 (I)"];
    "work_1" [shape=ellipse label="work_1 (I)"];
    "mid+x" [shape=ellipse label="mid+x (I)"];
    "mid+y" [shape=ellipse label="mid+y (I)"];
    "sub" [shape=ellipse label="sub (I)"];
    "cleanup" [shape=ellipse label="cleanup (I)"];

    "prep" -> "work_0";
    "prep" -> "work_1";
    "work_0" -> "mid+x";
    "work_1" -> "mid+x";
    "mid+x" -> "mid+y";
    "mid+y" -> "sub";
}
`
	parsed, err := ParseDot(strings.NewReader(dot))
	if err != nil {
		t.Fatalf("ParseDot: %v", err)
	}

	fromDAG, fromDot := Collapse(d), CollapseGraph(parsed)
	if fromDAG.NodeCount != fromDot.NodeCount || fromDAG.EdgeCount != fromDot.EdgeCount {
		t.Fatalf("counts differ: dag %d/%d, dot %d/%d",
			fromDAG.NodeCount, fromDAG.EdgeCount, fromDot.NodeCount, fromDot.EdgeCount)
	}
	if fromDAG.DanglingEdges != 0 || fromDot.DanglingEdges != 0 {
		t.Fatalf("dangling edges: dag %d, dot %d", fromDAG.DanglingEdges, fromDot.DanglingEdges)
	}
	if len(fromDAG.Groups) != len(fromDot.Groups) {
		t.Fatalf("group counts differ: dag %d, dot %d\ndag: %+v\ndot: %+v",
			len(fromDAG.Groups), len(fromDot.Groups), fromDAG.Groups, fromDot.Groups)
	}
	for i := range fromDAG.Groups {
		a, b := fromDAG.Groups[i], fromDot.Groups[i]
		a.Description, b.Description = "", ""
		if !reflect.DeepEqual(a, b) {
			t.Errorf("group %d differs:\n dag: %+v\n dot: %+v", i, a, b)
		}
	}
	// The one honest difference.
	byLabel := groupsByLabel(fromDAG)
	if got := oneGroup(t, byLabel, "prep").Description; got != "prep.sub" {
		t.Errorf("the .dag path lost its description: %q", got)
	}
	if got := oneGroup(t, groupsByLabel(fromDot), "prep").Description; got != "" {
		t.Errorf("the DOT path invented a description: %q", got)
	}
	// And the splice boundary really is what joined the two halves.
	work := oneGroup(t, byLabel, "work")
	x := oneGroup(t, byLabel, "mid+x")
	if got := x.ParentIDs; len(got) != 1 || got[0] != work.ID {
		t.Fatalf("mid+x parents = %v, want the workers [%s]: the splice-boundary edge was lost",
			got, work.ID)
	}
}

// TestCollapseSpliceBoundaryEdges is the smallest form of the same bug: a
// four-node chain through a splice. DAGMan attaches `PARENT pre CHILD
// mid` to the splice's INITIAL nodes and `PARENT mid CHILD post` to its
// TERMINAL ones; keeping the edge on the placeholder instead drew two
// unrelated roots that then merged into one group.
func TestCollapseSpliceBoundaryEdges(t *testing.T) {
	d := ParseWithFiles(`
JOB pre pre.sub
SPLICE mid mid.dag
JOB post post.sub
PARENT pre CHILD mid
PARENT mid CHILD post
`, map[string]string{"mid.dag": "JOB x x.sub\nJOB y y.sub\nPARENT x CHILD y\n"})
	if d.Incomplete {
		t.Fatalf("the splice did not resolve")
	}
	g := Collapse(d)
	if g.NodeCount != 4 {
		t.Fatalf("NodeCount = %d, want 4 (the placeholder is not a node)", g.NodeCount)
	}
	if g.EdgeCount != 3 || g.DanglingEdges != 0 {
		t.Fatalf("EdgeCount/DanglingEdges = %d/%d, want 3/0: pre->x, x->y, y->post",
			g.EdgeCount, g.DanglingEdges)
	}
	if len(g.Groups) != 4 {
		t.Fatalf("got %d groups, want 4 (one chain): %+v", len(g.Groups), g.Groups)
	}
	want := []string{"pre", "mid+x", "mid+y", "post"}
	for i, grp := range g.Groups {
		if grp.Count != 1 || grp.Members[0] != want[i] {
			t.Fatalf("group %d is %+v, want %s", i, grp, want[i])
		}
		if i > 0 {
			if got := grp.ParentIDs; len(got) != 1 || got[0] != g.Groups[i-1].ID {
				t.Fatalf("%s parents = %v, want [%s]", want[i], got, g.Groups[i-1].ID)
			}
		}
	}
}

// TestCollapseNestedSpliceBoundary: a splice inside a splice. The outer
// splice's boundary has to be its REAL nodes, not the inner placeholder.
func TestCollapseNestedSpliceBoundary(t *testing.T) {
	d := ParseWithFiles(`
JOB pre pre.sub
SPLICE outer outer.dag
JOB post post.sub
PARENT pre CHILD outer
PARENT outer CHILD post
`, map[string]string{
		"outer.dag": "SPLICE inner inner.dag\n",
		"inner.dag": "JOB x x.sub\nJOB y y.sub\nPARENT x CHILD y\n",
	})
	if d.Incomplete {
		t.Fatalf("the splices did not resolve")
	}
	g := Collapse(d)
	if g.NodeCount != 4 || g.EdgeCount != 3 || g.DanglingEdges != 0 {
		t.Fatalf("NodeCount/EdgeCount/DanglingEdges = %d/%d/%d, want 4/3/0",
			g.NodeCount, g.EdgeCount, g.DanglingEdges)
	}
	want := []string{"pre", "outer+inner+x", "outer+inner+y", "post"}
	if len(g.Groups) != 4 {
		t.Fatalf("got %d groups, want 4: %+v", len(g.Groups), g.Groups)
	}
	for i, grp := range g.Groups {
		if grp.Members[0] != want[i] {
			t.Fatalf("group %d is %+v, want %s", i, grp, want[i])
		}
	}
}

// TestCollapseUnreadableSpliceIsIncomplete: a splice whose file is not in
// hand contributes no nodes and no boundary, so the dependency on it is
// dropped. The caller has to be able to tell that from a workflow that
// really is one node -- which is what Incomplete is for.
func TestCollapseUnreadableSpliceIsIncomplete(t *testing.T) {
	d := ParseWithFiles("JOB pre pre.sub\nSPLICE mid mid.dag\nPARENT pre CHILD mid\n", nil)
	if !d.Incomplete {
		t.Fatalf("an unreadable splice must leave the DAG Incomplete")
	}
	g := Collapse(d)
	if !g.Incomplete {
		t.Errorf("Grouping.Incomplete = false; a one-node drawing is indistinguishable from a real one")
	}
	if g.NodeCount != 1 {
		t.Errorf("NodeCount = %d, want 1", g.NodeCount)
	}
	if g.DanglingEdges != 1 {
		t.Errorf("DanglingEdges = %d, want 1 (the edge into the missing splice)", g.DanglingEdges)
	}
}

// TestCollapseAllNodesEdge: `PARENT ALL_NODES CHILD last` means every
// other node, and expanding it is the honest handling. Deleting the edge
// -- which is what happened -- drew the workflow as a fan of roots with
// the gather node hanging off nothing.
func TestCollapseAllNodesEdge(t *testing.T) {
	d := Parse(`
JOB a a.sub
JOB b b.sub
JOB c c.sub
JOB last last.sub
PARENT ALL_NODES CHILD last
`)
	g := Collapse(d)
	if g.NodeCount != 4 {
		t.Fatalf("NodeCount = %d, want 4", g.NodeCount)
	}
	if g.EdgeCount != 3 || g.DanglingEdges != 0 {
		t.Fatalf("EdgeCount/DanglingEdges = %d/%d, want 3/0: last depends on the other three",
			g.EdgeCount, g.DanglingEdges)
	}
	if len(g.Groups) != 2 {
		t.Fatalf("got %d groups, want 2 (the three roots, then last): %+v", len(g.Groups), g.Groups)
	}
	roots, last := g.Groups[0], g.Groups[1]
	if roots.Count != 3 || last.Count != 1 || last.Members[0] != "last" {
		t.Fatalf("groups are %+v / %+v", roots, last)
	}
	if got := last.ParentIDs; len(got) != 1 || got[0] != roots.ID {
		t.Errorf("last parents = %v, want [%s]", got, roots.ID)
	}
}

// TestCollapseSpecialNodeTypesDoNotMerge: a FINAL node has no
// dependencies, and neither does an isolated JOB, so position alone puts
// them in one group -- where the group takes one of their labels and the
// FINAL node reads as a peer of an ordinary root. The node type is part
// of the key so that cannot happen on the .dag path. (A DOT file carries
// no types, so it cannot make this distinction; that divergence is
// documented on GraphFromDAG.)
func TestCollapseSpecialNodeTypesDoNotMerge(t *testing.T) {
	d := Parse(`
JOB lonely lonely.sub
FINAL cleanup cleanup.sub
PROVISIONER prov prov.sub
`)
	g := Collapse(d)
	if len(g.Groups) != 3 {
		t.Fatalf("got %d groups, want 3 (JOB, FINAL and PROVISIONER are not peers): %+v",
			len(g.Groups), g.Groups)
	}
	for _, grp := range g.Groups {
		if grp.Count != 1 {
			t.Errorf("group %+v merged nodes of different types", grp)
		}
	}
	// Two isolated nodes of the SAME type still merge: the type term
	// must not defeat collapsing.
	same := Collapse(Parse("JOB a a.sub\nJOB b b.sub\n"))
	if len(same.Groups) != 1 {
		t.Errorf("two isolated JOBs gave %d groups, want 1", len(same.Groups))
	}
}

// --- ParseWithFiles and the flat spool --------------------------------

// TestParseWithFilesSubdirectorySplicePath: the DAG text names
// `sub/mid.dag`, the spooled sandbox has `mid.dag` -- the schedd
// flattens it. Keying the lookup on the literal path left the graph
// Incomplete and the splice's whole subgraph missing, with nothing but a
// one-node drawing to show for it.
func TestParseWithFilesSubdirectorySplicePath(t *testing.T) {
	d := ParseWithFiles(`
JOB pre pre.sub
SPLICE mid sub/mid.dag
PARENT pre CHILD mid
`, map[string]string{"mid.dag": "JOB x x.sub\nJOB y y.sub\nPARENT x CHILD y\n"})
	if d.Incomplete {
		t.Fatalf("the basename fallback did not fire: %+v", d.Nodes)
	}
	g := Collapse(d)
	if g.Incomplete {
		t.Errorf("Grouping.Incomplete set for a DAG that resolved")
	}
	if g.NodeCount != 3 || g.EdgeCount != 2 {
		t.Fatalf("NodeCount/EdgeCount = %d/%d, want 3/2", g.NodeCount, g.EdgeCount)
	}
	if len(g.Groups) != 3 {
		t.Fatalf("got %d groups, want 3: %+v", len(g.Groups), g.Groups)
	}
	// An exact-path key still wins, so a caller that has full paths is
	// not broken by the fallback.
	exact := ParseWithFiles("SPLICE mid sub/mid.dag\n",
		map[string]string{"sub/mid.dag": "JOB x x.sub\n", "mid.dag": "JOB wrong wrong.sub\n"})
	if _, ok := exact.NodeByName("mid+x"); !ok {
		t.Errorf("the literal path lost to its basename: %+v", exact.Nodes)
	}
}

// --- labels -----------------------------------------------------------

func TestGroupLabel(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		desc  string
		want  string
	}{
		{"fan-out prefix", []string{"analyze_0", "analyze_1"}, "analyze.sub", "analyze"},
		{"single node keeps its name", []string{"lonely"}, "lonely.sub", "lonely"},
		{"one shared letter is still a name", []string{"pre", "post"}, "x.sub", "p"},
		{"no shared prefix falls back to the description",
			[]string{"alpha", "beta"}, "shared.sub", "shared.sub"},
		{"no prefix and no description falls back to a member",
			[]string{"alpha", "beta"}, "", "alpha"},
		{"separators alone are not a name", []string{"_a", "_b"}, "w.sub", "w.sub"},
		// A byte-wise common prefix of these two is "job" plus the first
		// byte of a three-byte rune, which is not valid UTF-8 and which
		// JSON renders as "job?".
		{"multi-byte names cut on a rune boundary",
			[]string{"job解析", "job諸元"}, "w.sub", "job"},
		{"identical multi-byte names survive whole",
			[]string{"解析_0", "解析_1"}, "w.sub", "解析"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := groupLabel(tc.names, tc.desc)
			if got != tc.want {
				t.Errorf("groupLabel(%q, %q) = %q, want %q", tc.names, tc.desc, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("label %q is not valid UTF-8", got)
			}
		})
	}
}
