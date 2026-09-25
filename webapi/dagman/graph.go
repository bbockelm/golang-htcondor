package dagman

import (
	"bufio"
	"errors"
	"io"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ParseWithFiles parses a DAG the way Parse does, but with the workflow's
// other files in hand, so INCLUDE and SPLICE are resolved instead of
// leaving the graph Incomplete.
//
// This is what makes a multi-file DAG's graph complete. Parse sees one
// file and has to admit it cannot see the rest; Analyze resolves them but
// answers a different question (what is missing from the spool). A caller
// that wants the graph itself -- every node, including the ones a splice
// contributed -- wants this.
//
// files is keyed by the bare name a spooled sandbox has: the schedd
// flattens the sandbox to basenames in one directory. The DAG text,
// however, may name the same file with a path (`SPLICE mid sub/mid.dag`),
// so the lookup tries the literal name first and then its basename. A
// caller that keyed the map by full path gets the literal hit; a caller
// that modelled the flat spool gets the basename one.
//
// Note that this is NOT how a RUNNING workflow is read: a spooled .dag
// never comes back from TRANSFER_DATA (see instrument.go), so the graph
// of a workflow in flight comes from ParseDot instead. This remains the
// way to read a DAG whose text is already in hand.
func ParseWithFiles(text string, files map[string]string) *DAG {
	return parseText(text, &resolver{
		lookup: func(name string) (string, bool) {
			if s, ok := files[name]; ok {
				return s, true
			}
			// The flat spool: `sub/mid.dag` was staged as `mid.dag`.
			// checkCollisions models the same rewrite, so looking the
			// basename up here keeps the graph and the analysis agreed
			// on which files the sandbox actually supplies.
			if b := path.Base(name); b != name {
				if s, ok := files[b]; ok {
					return s, true
				}
			}
			return "", false
		},
	})
}

// Graph is the collapsible shape of a workflow: named nodes and the
// dependencies between them, with whatever each source happens to know
// about a node besides its name.
//
// It exists because the two sources say very different things. A parsed
// .dag knows each node's submit description and type and nothing about
// its state; DAGMan's generated DOT file knows a one-letter state and
// nothing about descriptions or types. Collapse needs neither -- it works
// on shape alone -- so both reduce to this.
type Graph struct {
	Nodes []GraphNode
	Edges []Edge
	// SawHeader and SawFooter record whether ParseDot saw the file's
	// `digraph ... {` line and its closing `}`. They are the only
	// evidence that a DOT file was read whole: DAGMan writes the file by
	// unlinking and renaming (repeatedly, when the DAG says UPDATE), so
	// reading a zero-length or half-written one is a real window.
	//
	// Only ParseDot sets them. A Graph built from a parsed .dag leaves
	// them false and leaves Truncated false with them, because there is
	// no file framing to have missed.
	SawHeader bool
	SawFooter bool
	// Truncated is ParseDot's verdict: the file was missing its header or
	// its footer, so what is here is part of a file, not a whole
	// workflow. It matters more than it sounds. The generator writes ALL
	// node lines and then ALL arc lines, so the usual torn read loses
	// EDGES, and a graph with its edges missing does not render as
	// "partial" -- it renders, confidently, as a fan of unrelated nodes
	// that depend on nothing.
	Truncated bool
	// SkippedLines counts lines ParseDot could not read because they were
	// longer than dotMaxLineBytes. Such a line is skipped, not fatal.
	SkippedLines int
	// Incomplete is carried from a parsed DAG whose INCLUDE or SPLICE
	// could not be read: nodes are missing and nothing may conclude from
	// their absence. Always false for a Graph from ParseDot.
	Incomplete bool
}

// GraphNode is one node of a Graph.
type GraphNode struct {
	Name string
	// Type is the keyword that introduced the node (JOB, FINAL,
	// PROVISIONER, SUBDAG...), when the source knows. Empty from a DOT
	// file, which does not say. It is part of the grouping key, so a
	// FINAL node cannot collapse into a group of ordinary jobs.
	Type NodeType
	// Description is what the node runs, when the source knows: a
	// SUBMIT-DESCRIPTION name, a submit file, a sub-DAG, or the inline
	// marker. Empty from a DOT file, which carries no descriptions.
	Description string
	// State is the letter DAGMan wrote in the node's DOT label: "I",
	// "Pre", "R", "Post", "Done" or "E". Empty from a parsed .dag, which
	// describes a workflow rather than a run.
	State string
}

// The states a DOT label can carry, as DumpDotFileNodes writes them
// (dag.cpp ~2985): I is ready or not-yet-ready, Pre and Post are the
// scripts, R is submitted, Done is done, E is error.
const (
	DotStateIdle    = "I"
	DotStatePre     = "Pre"
	DotStateRunning = "R"
	DotStatePost    = "Post"
	DotStateDone    = "Done"
	DotStateError   = "E"
)

// dotStates maps a label suffix, folded, to its canonical spelling.
var dotStates = map[string]string{
	"i": DotStateIdle, "pre": DotStatePre, "r": DotStateRunning,
	"post": DotStatePost, "done": DotStateDone, "e": DotStateError,
}

// dotMaxLineBytes bounds one line of a DOT file. Every line DAGMan writes
// is one node or one edge, so this is generous by a wide margin; it is
// here so a corrupt or hostile file cannot be read into memory unbounded.
// A line over the bound is skipped and counted in Graph.SkippedLines --
// refusing the whole file over one bad line would throw away every other
// node in it.
const dotMaxLineBytes = 1 << 20

// ParseDot reads the DOT file DAGMan writes for a DAG that declares
// `DOT <file>`.
//
// It is a parser for THIS generator, not for the DOT language. DAGMan
// writes one node per line as
//
//	"name" [shape=ellipse label="name (I)"];
//
// and one edge per line as
//
//	"parent" -> "child";
//
// with a `digraph DAG {` header, a graph-level label, and possibly
// verbatim text from a `DOT ... INCLUDE` header file. That is regular
// enough to read line by line, and reading it that way keeps a graphviz
// dependency -- and a general grammar's failure modes -- out of a path
// that only ever sees machine-generated input. Anything it does not
// recognise is skipped rather than refused: a file DAGMan is rewriting
// under us, or an author's INCLUDE header full of graphviz styling,
// should cost the unreadable lines and nothing more.
//
// Node names are read as written. DAGMan forbids exactly one character in
// a node name -- '+', which it reserves for splice scopes
// (condor_dagman/parse.cpp ILLEGAL_CHARS) -- so spaces, brackets, "->"
// and even quotes are legal names, and every one of them appears here
// inside the quotes the generator always writes. The leading quoted token
// is therefore read FIRST and the rest of the line is interpreted only
// after it, which is what keeps a node named `a->b` from being read as an
// edge. The one name that cannot survive is one containing a double
// quote: DAGMan does not escape it, so `"a"b"` is unreadable as written
// and the name is truncated at the quote.
//
// Names may also carry a `<dagnum>.` prefix that the .dag text does not
// have: munge_node_name (dag.cpp) prepends the DAG number for a multi-DAG
// submission, so `condor_submit_dag a.dag b.dag` writes `0.foo` and
// `1.foo` for nodes both files call `foo`.
func ParseDot(r io.Reader) (*Graph, error) {
	g := &Graph{}
	seen := map[string]bool{}
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		raw, tooLong, err := readDotLine(br)
		if tooLong {
			g.SkippedLines++
		} else {
			parseDotLine(g, seen, strings.TrimSpace(raw))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
	}
	g.Truncated = !g.SawHeader || !g.SawFooter
	return g, nil
}

// parseDotLine reads one line into the graph, or ignores it.
func parseDotLine(g *Graph, seen map[string]bool, line string) {
	if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "/*") {
		return
	}
	if strings.HasPrefix(line, "}") {
		g.SawFooter = true
		return
	}
	if strings.HasPrefix(line, "digraph") {
		g.SawHeader = true
		return
	}
	name, quoted, rest := dotToken(line)
	if name == "" {
		return
	}
	// A graphviz keyword is only a keyword UNQUOTED. `node [shape=box];`
	// in an INCLUDE header is a statement, but "node" in quotes is a
	// node DAGMan wrote, and deleting it takes its children's parent
	// away with it.
	if !quoted && dotKeyword(name) {
		return
	}
	arrow := strings.Index(rest, "->")
	open := strings.IndexByte(rest, '[')
	switch {
	case arrow >= 0 && (open < 0 || arrow < open):
		child, _, _ := dotToken(rest[arrow+len("->"):])
		if child != "" {
			g.Edges = append(g.Edges, Edge{Parent: name, Child: child})
		}
	case open >= 0:
		// Node names are always quoted by the generator, so requiring
		// the quotes costs nothing and keeps an INCLUDE header's
		// default attributes (`node [...]`) from becoming a node.
		if !quoted || seen[name] {
			return
		}
		seen[name] = true
		g.Nodes = append(g.Nodes, GraphNode{Name: name, State: dotLabelState(dotAttrs(rest[open:]))})
	}
}

// readDotLine reads one line, without loading an arbitrarily long one
// into memory: a line over dotMaxLineBytes is discarded to the next
// newline and reported as tooLong. The returned error is io.EOF on the
// last line, which may still hold text.
func readDotLine(br *bufio.Reader) (line string, tooLong bool, err error) {
	var b []byte
	for {
		chunk, rerr := br.ReadSlice('\n')
		if !tooLong {
			if len(b)+len(chunk) > dotMaxLineBytes {
				tooLong, b = true, nil
			} else {
				b = append(b, chunk...)
			}
		}
		// ErrBufferFull is "no newline in the buffer yet", not a
		// failure: keep reading, discarding if the line is already
		// over the bound.
		if errors.Is(rerr, bufio.ErrBufferFull) {
			continue
		}
		return string(b), tooLong, rerr
	}
}

// dotToken reads the first token of s -- a quoted string, or a bare word
// up to the first space or punctuation -- and returns what follows it.
// quoted says which it was.
//
// A quoted token ends at the next quote, because DAGMan writes node names
// verbatim with no escaping at all. That is also why rest is the text
// after that quote rather than after the token: a name containing a quote
// leaves junk behind, and the caller still finds the attribute list in
// it, which is the difference between losing the node's state and losing
// the node.
func dotToken(s string) (tok string, quoted bool, rest string) {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return "", false, ""
	}
	if s[0] == '"' {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			return s[1 : 1+end], true, s[end+2:]
		}
		return "", false, ""
	}
	end := strings.IndexAny(s, " \t;[]\"=")
	if end < 0 {
		end = len(s)
	}
	return s[:end], false, s[end:]
}

// dotAttrs returns the attribute list starting at s[0] == '[', scanned to
// its matching ']' rather than to the first one, so a node named `a[0]`
// -- whose name appears again inside the label -- does not cut it short.
// An unterminated list (a torn read) is returned whole.
func dotAttrs(s string) string {
	inQuote := false
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case ']':
			if !inQuote {
				return s[:i+1]
			}
		}
	}
	return s
}

// dotKeyword is a graphviz word that is never a node name here. It is
// applied to UNQUOTED tokens only: DAGMan quotes every node name, and a
// DAG may perfectly well contain `JOB node node.sub`.
func dotKeyword(tok string) bool {
	switch strings.ToLower(tok) {
	case "digraph", "graph", "subgraph", "node", "edge", "label", "rankdir":
		return true
	}
	return false
}

// dotLabelState pulls the state out of a node's attribute list.
//
// The attributes are unordered and unseparated (`[shape=ellipse
// label="x (R)" peripheries=2]`), so the label is found by name and the
// state is the parenthesised suffix of its value. A label that does not
// end in a known suffix yields "", which reads as "this file does not say"
// rather than as a state.
func dotLabelState(attrs string) string {
	i := strings.Index(strings.ToLower(attrs), "label=")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(attrs[i+len("label="):])
	if rest == "" || rest[0] != '"' {
		return ""
	}
	end := strings.IndexByte(rest[1:], '"')
	if end < 0 {
		return ""
	}
	label := strings.TrimSpace(rest[1 : 1+end])
	if !strings.HasSuffix(label, ")") {
		return ""
	}
	open := strings.LastIndexByte(label, '(')
	if open < 0 {
		return ""
	}
	return dotStates[strings.ToLower(label[open+1:len(label)-1])]
}

// GraphFromDAG reduces a parsed DAG to the shape Collapse works on.
//
// SPLICE nodes are left out: a splice is not a node DAGMan runs, it is a
// sub-graph inlined at parse time, and ParseWithFiles has already added
// its real nodes under the "scope+name" spelling. Drawing the placeholder
// too would double-count the splice. A dependency that NAMES the splice
// is not dropped with it -- DAGMan attaches such a dependency to the
// splice's own initial and terminal nodes, and so does this (see
// DAG.resolveEdgeEnd).
//
// ALL_NODES is expanded the same way, to every other node, because that
// is what DAGMan does with it.
//
// One divergence from the DOT-derived graph is worth knowing about:
// SERVICE nodes are here and are NOT in a DOT file. Dag::Add pushes a
// service node onto _service_nodes and returns before _nodes.push_back,
// so DumpDotFileNodes never sees one. FINAL and PROVISIONER nodes do
// appear in both.
func GraphFromDAG(d *DAG) *Graph {
	if d == nil {
		return &Graph{}
	}
	g := &Graph{Nodes: make([]GraphNode, 0, len(d.Nodes)), Incomplete: d.Incomplete}
	all := make([]string, 0, len(d.Nodes))
	for i := range d.Nodes {
		n := &d.Nodes[i]
		if n.Type == NodeSplice {
			continue
		}
		g.Nodes = append(g.Nodes, GraphNode{Name: n.Name, Type: n.Type, Description: nodeDescription(n)})
		all = append(all, n.Name)
	}
	g.Edges = d.expandEdges(d.Edges, all)
	return g
}

// expandEdges rewrites every dependency into one between nodes that
// actually exist: a splice placeholder becomes the splice's boundary
// nodes, ALL_NODES becomes every other node, and anything else is itself.
func (d *DAG) expandEdges(edges []Edge, all []string) []Edge {
	out := make([]Edge, 0, len(edges))
	for _, e := range edges {
		// ALL_NODES on both sides would be every node depending on every
		// other, which is not a drawing and is not what anyone wrote.
		if isAllNodes(e.Parent) && isAllNodes(e.Child) {
			continue
		}
		ps := d.resolveEdgeEnd(e.Parent, true, all)
		cs := d.resolveEdgeEnd(e.Child, false, all)
		for _, p := range ps {
			for _, c := range cs {
				if p == c {
					continue
				}
				out = append(out, Edge{Parent: p, Child: c, Line: e.Line, Source: e.Source})
			}
		}
	}
	return out
}

// Group is a set of nodes a drawing may show as one shape.
//
// Two nodes are in the same group when they occupy the same POSITION in
// the workflow: same node type, same set of parent groups, same set of
// child groups. That is the whole point: a fan-out of 10,000 `analyze_N`
// nodes between one prepare and one combine is ONE group, and a
// 100,000-node DAG -- an ordinary size here -- can be drawn at all.
// Drawing it node by node is not slow, it is impossible.
//
// WHAT A GROUP LINK MEANS. A group in ParentIDs means "SOME member of
// that group is the parent of SOME member of this one". It does NOT mean
// every member of one parents every member of the other, and a renderer
// that draws it as complete bipartite is drawing edges that do not exist.
// The clearest case: N independent two-node chains (a_i -> b_i) collapse
// to two groups joined by one group link, because every a_i occupies the
// same position and so does every b_i -- but the dependencies are a
// perfect matching, not N*N edges. Draw a group link as ONE line between
// two shapes; if the exact pairing matters, expand the group and use
// Members.
type Group struct {
	ID string `json:"id"`
	// Label is a readable name: the common prefix of the member node
	// names when they share one ("analyze_" for analyze_0..analyze_9999),
	// otherwise the description the nodes run, otherwise the first
	// member's name.
	Label string `json:"label"`
	// Description is what the nodes were pointed at -- a
	// SUBMIT-DESCRIPTION name, a submit file name, a sub-DAG's .dag file,
	// or the marker for an inline submit description -- when every member
	// ran the same one AND the source knew it. Empty otherwise, including
	// for every group read from a DOT file, which carries no descriptions.
	Description string `json:"description"`
	Count       int    `json:"count"`
	// Members are the node names, always filled in. A caller that must
	// not send 100,000 names decides that for itself; throwing them away
	// here would mean a second parse to get them back.
	Members []string `json:"members"`
	// ParentIDs are the groups this one depends on -- "some member of
	// that group parents some member of this group", see the type
	// comment. A group may name ITSELF here, which says that members
	// depend on other members; that cannot happen in an exact grouping
	// and is a symptom of Grouping.Approximate.
	ParentIDs []string `json:"parent_ids"`
}

// Grouping is the collapsed graph.
//
// Collapse returns a struct rather than a bare []Group because how much
// the drawing can be trusted has to be reported with it: a caller that
// draws layers from ParentIDs must be able to say the layering is
// approximate, or that the source was a half-written file, rather than
// show a wrong picture confidently.
//
// Read Group's comment before drawing the links. A link between two
// groups is an existence claim about their members, not a claim about
// every pair of them.
type Grouping struct {
	Groups []Group `json:"groups"`
	// NodeCount and EdgeCount describe the graph the groups came from:
	// the nodes that can actually run, and the dependencies between them.
	// EdgeCount counts NODE dependencies, which is not what a drawing
	// shows -- LinkCount is the number of group links -- and the two
	// differ by orders of magnitude on exactly the workflows this exists
	// for (a 50,000-way fan-out is 100,000 edges and 2 links).
	NodeCount int `json:"node_count"`
	EdgeCount int `json:"edge_count"`
	// LinkCount is the number of group-to-group links, i.e. the edges a
	// renderer actually draws.
	LinkCount int `json:"link_count"`
	// DanglingEdges counts dependencies dropped because one end named a
	// node the graph does not have. On a DOT file that is either a torn
	// read or text from a `DOT ... INCLUDE` header that parsed as an arc;
	// on a parsed .dag it is a splice whose file could not be read. It is
	// never normal, and a drawing missing this many dependencies should
	// say so.
	DanglingEdges int `json:"dangling_edges,omitempty"`
	// Truncated is carried from a DOT file that was missing its header or
	// footer: a partial file is NOT a partial workflow, and since the
	// generator writes all nodes before all arcs, the usual way to read
	// one is with its dependencies missing.
	Truncated bool `json:"truncated,omitempty"`
	// Incomplete is carried from a parsed DAG whose INCLUDE or SPLICE
	// could not be read: nodes are missing. It is what tells a one-node
	// workflow apart from a workflow whose other file was unreadable.
	Incomplete bool `json:"incomplete,omitempty"`
	// Approximate is set when the grouping is not the exact structural
	// one. ApproximateReason says which of the two ways it happened,
	// because a caller cannot tell them apart otherwise and they are not
	// equally bad.
	Approximate bool `json:"approximate,omitempty"`
	// ApproximateReason is ApproximateCycle or ApproximateUnsettled, and
	// empty when Approximate is false.
	ApproximateReason string `json:"approximate_reason,omitempty"`
}

// The reasons a Grouping can be approximate.
const (
	// ApproximateCycle: the graph has a cycle, so it has no topological
	// order and every node is left in its own group. DAGMan refuses a
	// cyclic DAG, so this means the .dag was hand-edited or half-written.
	ApproximateCycle = "cycle"
	// ApproximateUnsettled: the refinement did not reach its fixpoint
	// within collapseMaxRounds. The groups are a COARSENING of the exact
	// answer -- every dependency is still represented by a group link,
	// including a link from a group to itself -- but two nodes that a
	// drawing should separate may share a shape.
	ApproximateUnsettled = "refinement-bound"
)

// inlineMarker is the Description of a group whose nodes carry an inline
// submit description, which has no name to show.
const inlineMarker = "(inline submit description)"

// collapseMaxRounds bounds the refinement. Each round that changes
// anything splits at least one group, so the fixpoint is reached in at
// most one round per group; because each pass reads the numbering the
// SAME pass is producing for the neighbours it has already visited, one
// pass propagates a split the whole length of the graph, and chains of
// 10,000 nodes, combs and ladders settle in one or two rounds. The bound
// is here only so a pathological graph cannot turn a page load into an
// O(V^2) walk. Hitting it sets Approximate with ApproximateUnsettled.
//
// It is a var only so the test that has to reach the bound can lower it;
// nothing outside the package can.
var collapseMaxRounds = 32

// Collapse folds a parsed DAG into the groups a drawing can show.
func Collapse(d *DAG) *Grouping { return CollapseGraph(GraphFromDAG(d)) }

// CollapseGraph folds a graph into groups by STRUCTURAL EQUIVALENCE: two
// nodes are in one group when they have the same type, the same set of
// parent groups and the same set of child groups.
//
// Both adjacency halves are needed, and the child half is the one that is
// easy to leave out. Without it, two fan-outs that happen to hang off
// structurally identical parents merge into a single group whose drawn
// edges claim every node descends from both parents. With it, the fan-out
// that feeds a gather node is told apart from the one that feeds nothing,
// and that difference propagates back to their parents on the same pass.
//
// The rule is structure (plus node type) only. It cannot be "same submit
// description plus same parents", because the source for a RUNNING
// workflow is DAGMan's DOT file and a DOT file carries no submit
// descriptions at all (see instrument.go for why that is the source). The
// cost is that two isomorphic but unrelated subgraphs collapse together
// -- an honest drawing of "two of these ran side by side", not a wrong
// one, and the member list says exactly which nodes those were. The type
// term is free in the same sense: a DOT file carries no types either, so
// it only ever separates nodes on the .dag-derived path, where a FINAL
// node merging into a group of ordinary roots would read as a peer of
// them.
//
// It is linear in nodes plus edges per pass, apart from sorting each
// node's adjacent group set, and it never recurses -- a 50,000-node
// fan-out is a few milliseconds and no stack at all.
func CollapseGraph(in *Graph) *Grouping {
	g := &Grouping{Groups: []Group{}}
	if in == nil {
		return g
	}
	nodes, index := collapsibleNodes(in)
	parents, children, edgeCount, dangling := buildAdjacency(nodes, index, in.Edges)
	g.NodeCount = len(nodes)
	g.EdgeCount = edgeCount
	g.DanglingEdges = dangling
	g.Truncated = in.Truncated
	g.Incomplete = in.Incomplete

	order, acyclic := topoOrder(nodes, parents, children)

	var ids []int
	if acyclic {
		var settled bool
		ids, settled = structuralGroups(order, parents, children, nodeClasses(nodes))
		if !settled {
			g.Approximate, g.ApproximateReason = true, ApproximateUnsettled
		}
	} else {
		g.Approximate, g.ApproximateReason = true, ApproximateCycle
		// Fall back to one group per node. The structural key cannot be
		// computed without a topological order, and guessing one would
		// produce a layering that looks authoritative and is not; leaving
		// every node on its own is the only answer that invents nothing.
		ids = make([]int, len(nodes))
		for i := range ids {
			ids[i] = i
		}
	}

	// Walk in topological order so group g1 is a root and a group's
	// parents always come before it, which is what lets a caller draw
	// layers straight down the list. A cyclic graph has no such order, so
	// it falls back to declaration order.
	walk := order
	if !acyclic {
		walk = make([]int, len(nodes))
		for i := range walk {
			walk[i] = i
		}
	}
	members := make([][]int, 0, len(nodes))
	byID := map[int]int{}
	for _, n := range walk {
		slot, ok := byID[ids[n]]
		if !ok {
			slot = len(members)
			byID[ids[n]] = slot
			members = append(members, nil)
		}
		members[slot] = append(members[slot], n)
	}

	compact := make([]int, len(nodes))
	for n := range nodes {
		compact[n] = byID[ids[n]]
	}
	g.Groups = buildGroups(nodes, compact, members, parents)
	for _, grp := range g.Groups {
		g.LinkCount += len(grp.ParentIDs)
	}
	return g
}

// nodeClasses is the partition every node starts in: its type. A DOT
// file gives every node the same (empty) type, so this is one class and
// the refinement starts where it always did.
func nodeClasses(nodes []GraphNode) []int {
	classes := make([]int, len(nodes))
	byType := map[NodeType]int{}
	for i, n := range nodes {
		c, ok := byType[n.Type]
		if !ok {
			c = len(byType)
			byType[n.Type] = c
		}
		classes[i] = c
	}
	return classes
}

// structuralGroups assigns every node a group id by structural
// equivalence, and reports whether the refinement settled within its
// bound.
//
// Every pass REFINES -- the key always includes the node's current group,
// so a pass can split a group but never merge two -- which is what makes
// the loop terminate: group count is non-decreasing, bounded by the node
// count, and a pass that changes nothing ends it. seed is the partition
// to start from, which is the node types.
//
// The passes alternate direction, and each walks in an order where the
// neighbours it reads are already reassigned (parents first in
// topological order, children first in reverse) AND reads that new
// assignment, so one pass propagates a split the whole length of the
// graph instead of one edge per round.
func structuralGroups(order []int, parents, children [][]int, seed []int) (ids []int, settled bool) {
	ids = make([]int, len(parents))
	copy(ids, seed)
	count := assignBySet(order, ids, parents)
	for round := 0; round < collapseMaxRounds; round++ {
		assignBySet(reversed(order), ids, children)
		// Only the last pass's count is compared: a pass never merges, so
		// if the round ends with the group count it started with, neither
		// pass split anything and the partition is the fixpoint.
		n := assignBySet(order, ids, parents)
		if n == count {
			return ids, true
		}
		count = n
	}
	return ids, false
}

// assignBySet renumbers every node by (its current group, the set of
// groups of its adjacent nodes), walking in the given order. It returns
// the number of groups.
//
// The set is read IN-PASS: a neighbour this pass has already visited
// contributes its NEW number, and one it has not contributes its old one.
// That is the whole reason a pass propagates information further than one
// edge -- reading the pre-pass numbering for every neighbour, which is
// what a plain "renumber everything then swap" does, moves a distinction
// exactly one edge per pass and needs a round per two levels of depth.
// The two numberings are written distinguishably ("3" vs "n3") so a node
// cannot be told to match a neighbour it does not match; the key still
// contains the node's own current group, so the pass is still a strict
// refinement and termination is unchanged.
func assignBySet(order []int, ids []int, adj [][]int) int {
	keys := make(map[string]int, len(ids))
	next := make([]int, len(ids))
	done := make([]bool, len(ids))
	var b strings.Builder
	set := make([]int64, 0, 16)
	for _, n := range order {
		b.Reset()
		b.WriteString(strconv.Itoa(ids[n]))
		b.WriteByte('|')
		set = writeGroupSet(&b, ids, next, done, adj[n], set[:0])
		key := b.String()
		id, ok := keys[key]
		if !ok {
			id = len(keys)
			keys[key] = id
		}
		next[n] = id
		done[n] = true
	}
	copy(ids, next)
	return len(keys)
}

// writeGroupSet writes the sorted, de-duplicated set of group ids of the
// given nodes, taking each neighbour's in-pass number when it has one.
// Each id is encoded with a low bit saying which numbering it came from,
// so the two can never be confused and the order is still total.
func writeGroupSet(b *strings.Builder, ids, next []int, done []bool, adj []int, set []int64) []int64 {
	if len(adj) == 0 {
		return set
	}
	for _, a := range adj {
		if done[a] {
			set = append(set, int64(next[a])<<1|1)
		} else {
			set = append(set, int64(ids[a])<<1)
		}
	}
	slices.Sort(set)
	set = slices.Compact(set)
	for i, v := range set {
		if i > 0 {
			b.WriteByte(',')
		}
		if v&1 == 1 {
			b.WriteByte('n')
		}
		b.WriteString(strconv.FormatInt(v>>1, 10))
	}
	return set
}

func reversed(order []int) []int {
	out := make([]int, len(order))
	for i, n := range order {
		out[len(order)-1-i] = n
	}
	return out
}

// collapsibleNodes is the node set a drawing shows, with a name index for
// resolving edges.
//
// Names are compared byte for byte, because DAGMan's node names are
// case-SENSITIVE: _nodeNameHash is a std::map<std::string, ...> with a
// plain strcmp (dag.cpp:1229-1241), so `JOB Work` and `JOB work` are two
// different nodes and folding them here would delete one of them and its
// dependencies. (SUBMIT-DESCRIPTION names and VARS keys ARE folded, and
// are folded elsewhere; node names are not.)
func collapsibleNodes(g *Graph) ([]GraphNode, map[string]int) {
	nodes := make([]GraphNode, 0, len(g.Nodes))
	index := make(map[string]int, len(g.Nodes))
	for _, n := range g.Nodes {
		if _, dup := index[n.Name]; dup {
			// DAGMan rejects a duplicate node name outright; keeping
			// the first is enough to stay self-consistent here.
			continue
		}
		index[n.Name] = len(nodes)
		nodes = append(nodes, n)
	}
	return nodes, index
}

// buildAdjacency turns the PARENT/CHILD list into parent and child
// adjacency, dropping what cannot be drawn: a self-edge, a repeat of an
// edge already seen, and an edge naming a node this graph does not have.
//
// That last one is COUNTED and returned, because it is never routine. A
// splice placeholder and ALL_NODES are expanded before they get here (see
// GraphFromDAG), so an unknown endpoint now means a splice whose file
// could not be read, a torn DOT file, or header text that parsed as an
// arc -- all of which are worth telling the caller about rather than
// quietly drawing a workflow with dependencies missing.
func buildAdjacency(nodes []GraphNode, index map[string]int, edges []Edge) (parents, children [][]int, count, dangling int) {
	parents = make([][]int, len(nodes))
	children = make([][]int, len(nodes))
	seen := make(map[[2]int]bool, len(edges))
	for _, e := range edges {
		p, okP := index[e.Parent]
		c, okC := index[e.Child]
		if !okP || !okC {
			dangling++
			continue
		}
		if p == c || seen[[2]int{p, c}] {
			continue
		}
		seen[[2]int{p, c}] = true
		parents[c] = append(parents[c], p)
		children[p] = append(children[p], c)
		count++
	}
	return parents, children, count, dangling
}

// topoOrder is Kahn's algorithm, in node declaration order so the same
// DAG always produces the same group IDs. acyclic is false when some
// node never reached indegree zero, which is the cycle.
func topoOrder(nodes []GraphNode, parents, children [][]int) (order []int, acyclic bool) {
	indeg := make([]int, len(nodes))
	queue := make([]int, 0, len(nodes))
	for n := range nodes {
		indeg[n] = len(parents[n])
		if indeg[n] == 0 {
			queue = append(queue, n)
		}
	}
	order = make([]int, 0, len(nodes))
	for head := 0; head < len(queue); head++ {
		n := queue[head]
		order = append(order, n)
		for _, c := range children[n] {
			indeg[c]--
			if indeg[c] == 0 {
				queue = append(queue, c)
			}
		}
	}
	return order, len(order) == len(nodes)
}

// buildGroups turns the per-node assignment into the exported groups.
//
// ParentIDs is derived from the edges rather than from the group key, so
// the cycle fallback -- which has no key parent set -- still gets usable
// links. In the exact case the two are the same set by construction.
//
// A group that is its own parent is kept rather than dropped. In an exact
// grouping it cannot arise (a parent and child in one group would need an
// infinite ancestor chain), so it only appears when the refinement was
// cut off by its bound -- and there, dropping it would silently delete
// every dependency inside the oversized group, which is precisely the
// "nothing depends on anything" drawing this is trying not to produce.
func buildGroups(nodes []GraphNode, ids []int, members [][]int, parents [][]int) []Group {
	out := make([]Group, len(members))
	for id, ms := range members {
		names := make([]string, len(ms))
		for i, n := range ms {
			names[i] = nodes[n].Name
		}
		desc := sharedDescription(nodes, ms)
		out[id] = Group{
			ID:          "g" + strconv.Itoa(id+1),
			Label:       groupLabel(names, desc),
			Description: desc,
			Count:       len(ms),
			Members:     names,
			ParentIDs:   nil,
		}
	}
	for id, ms := range members {
		seen := make(map[int]bool)
		var pids []int
		for _, n := range ms {
			for _, p := range parents[n] {
				pid := ids[p]
				if !seen[pid] {
					seen[pid] = true
					pids = append(pids, pid)
				}
			}
		}
		sort.Ints(pids)
		for _, pid := range pids {
			out[id].ParentIDs = append(out[id].ParentIDs, "g"+strconv.Itoa(pid+1))
		}
	}
	return out
}

// nodeDescription is what one node was pointed at, for display.
func nodeDescription(n *Node) string {
	if n.Inline {
		return inlineMarker
	}
	if n.Descriptor == "" {
		return n.Name
	}
	return n.Descriptor
}

// sharedDescription is the description a whole group ran, or "" when its
// members ran different ones. Since grouping is structural, a group CAN
// hold nodes that run different work; claiming one member's description
// for all of them would be a made-up fact, and an empty string is the
// honest answer.
func sharedDescription(nodes []GraphNode, members []int) string {
	desc := nodes[members[0]].Description
	for _, n := range members[1:] {
		if nodes[n].Description != desc {
			return ""
		}
	}
	return desc
}

// groupLabel names a group the way its author would. The common prefix of
// the member names is what a fan-out is actually called -- "analyze_" for
// analyze_0..analyze_9999 -- and when the names share nothing useful the
// description, then the first member's name, is the only honest name
// left.
func groupLabel(names []string, desc string) string {
	prefix := names[0]
	for _, n := range names[1:] {
		prefix = commonPrefix(prefix, n)
		if prefix == "" {
			break
		}
	}
	if len(names) > 1 {
		prefix = strings.TrimRight(prefix, "_-. ")
	}
	if usefulPrefix(prefix) {
		return prefix
	}
	if desc != "" {
		return desc
	}
	return names[0]
}

// usefulPrefix rejects a prefix that names nothing: empty, or nothing but
// punctuation and separators. A prefix that is a single letter or digit
// IS useful -- `a1`/`a2` are "the a's" -- so the bar is deliberately low.
func usefulPrefix(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// commonPrefix is the shared leading text of a and b, cut on a RUNE
// boundary: the names are UTF-8 and cutting mid-rune produces a label
// that is not valid UTF-8 at all, which JSON encodes as U+FFFD and a
// reader sees as `job?`. `job解析` and `job諸元` share "job", not "job"
// plus the first byte of a kanji.
func commonPrefix(a, b string) string {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	for i > 0 && i < len(a) && !utf8.RuneStart(a[i]) {
		i--
	}
	return a[:i]
}
