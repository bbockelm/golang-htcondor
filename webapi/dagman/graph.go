package dagman

import (
	"bufio"
	"io"
	"sort"
	"strconv"
	"strings"
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
// files is keyed by the bare name the DAG uses, which is what a spooled
// sandbox has: the schedd flattens it to basenames in one directory.
//
// Note that this is NOT how a RUNNING workflow is read: a spooled .dag
// never comes back from TRANSFER_DATA (see instrument.go), so the graph
// of a workflow in flight comes from ParseDot instead. This remains the
// way to read a DAG whose text is already in hand.
func ParseWithFiles(text string, files map[string]string) *DAG {
	return parseText(text, &resolver{
		lookup: func(name string) (string, bool) {
			s, ok := files[name]
			return s, ok
		},
	})
}

// Graph is the collapsible shape of a workflow: named nodes and the
// dependencies between them, with whatever each source happens to know
// about a node besides its name.
//
// It exists because the two sources say very different things. A parsed
// .dag knows each node's submit description and nothing about its state;
// DAGMan's generated DOT file knows a one-letter state and nothing about
// descriptions. Collapse needs neither -- it works on shape alone -- so
// both reduce to this.
type Graph struct {
	Nodes []GraphNode
	Edges []Edge
}

// GraphNode is one node of a Graph.
type GraphNode struct {
	Name string
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
func ParseDot(r io.Reader) (*Graph, error) {
	g := &Graph{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), dotMaxLineBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "}") {
			continue
		}
		if i := strings.Index(line, "->"); i >= 0 {
			parent, _ := dotToken(line[:i])
			child, _ := dotToken(line[i+len("->"):])
			if parent != "" && child != "" && !dotKeyword(parent) {
				g.Edges = append(g.Edges, Edge{Parent: parent, Child: child})
			}
			continue
		}
		open := strings.Index(line, "[")
		if open < 0 {
			continue
		}
		name, quoted := dotToken(line[:open])
		// An unquoted leading word is a graphviz statement -- `node
		// [shape=box];`, `graph [...]` -- not a node DAGMan wrote. Node
		// names are always quoted by the generator, so requiring the
		// quotes costs nothing and keeps an INCLUDE header's default
		// attributes from becoming phantom nodes.
		if name == "" || !quoted || dotKeyword(name) {
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		g.Nodes = append(g.Nodes, GraphNode{Name: name, State: dotLabelState(line[open:])})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return g, nil
}

// dotToken reads the first token of s: a quoted string, or a bare word up
// to the first space or punctuation. quoted says which it was.
func dotToken(s string) (tok string, quoted bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if s[0] == '"' {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			return s[1 : 1+end], true
		}
		return "", false
	}
	end := strings.IndexAny(s, " \t;[]\"=")
	if end < 0 {
		end = len(s)
	}
	return s[:end], false
}

// dotKeyword is a graphviz word that is never a node name here.
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
// too would double-count the splice.
func GraphFromDAG(d *DAG) *Graph {
	if d == nil {
		return &Graph{}
	}
	g := &Graph{Nodes: make([]GraphNode, 0, len(d.Nodes)), Edges: d.Edges}
	for i := range d.Nodes {
		n := &d.Nodes[i]
		if n.Type == NodeSplice {
			continue
		}
		g.Nodes = append(g.Nodes, GraphNode{Name: n.Name, Description: nodeDescription(n)})
	}
	return g
}

// Group is a set of nodes a drawing may show as one shape.
//
// Two nodes are in the same group when they occupy the same POSITION in
// the workflow: same set of parent groups, same set of child groups. That
// is the whole point: a fan-out of 10,000 `analyze_N` nodes between one
// prepare and one combine is ONE group, and a 100,000-node DAG -- an
// ordinary size here -- can be drawn at all. Drawing it node by node is
// not slow, it is impossible.
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
	Members   []string `json:"members"`
	ParentIDs []string `json:"parent_ids"`
}

// Grouping is the collapsed graph.
//
// Collapse returns a struct rather than a bare []Group because the cycle
// fallback has to be reported: a caller that draws layers from ParentIDs
// must be able to say the layering is approximate rather than show a
// wrong picture confidently.
type Grouping struct {
	Groups []Group `json:"groups"`
	// NodeCount and EdgeCount describe the graph the groups came from:
	// the nodes that can actually run, and the dependencies between them.
	NodeCount int `json:"node_count"`
	EdgeCount int `json:"edge_count"`
	// Approximate is set when the grouping is not the exact structural
	// one: a cycle (DAGMan refuses a cyclic DAG, so this should not happen
	// on a workflow that ran -- but a half-written or hand-edited .dag can
	// contain one, and hanging or panicking on it would be far worse than
	// saying so), or a refinement that did not settle within its bound.
	Approximate bool `json:"approximate,omitempty"`
}

// inlineMarker is the Description of a group whose nodes carry an inline
// submit description, which has no name to show.
const inlineMarker = "(inline submit description)"

// collapseMaxRounds bounds the refinement. Each round that changes
// anything splits at least one group, so the fixpoint is reached in at
// most one round per group; in practice two or three rounds settle a real
// workflow, and the bound is here only so a pathological graph cannot
// turn a page load into an O(V^2) walk. Hitting it sets Approximate.
const collapseMaxRounds = 32

// Collapse folds a parsed DAG into the groups a drawing can show.
func Collapse(d *DAG) *Grouping { return CollapseGraph(GraphFromDAG(d)) }

// CollapseGraph folds a graph into groups by STRUCTURAL EQUIVALENCE: two
// nodes are in one group when they have the same set of parent groups and
// the same set of child groups.
//
// Both halves are needed, and the child half is the one that is easy to
// leave out. Without it, two fan-outs that happen to hang off
// structurally identical parents merge into a single group whose drawn
// edges claim every node descends from both parents. With it, the fan-out
// that feeds a gather node is told apart from the one that feeds nothing,
// and that difference propagates back to their parents on the same pass.
//
// The rule is structure only. It cannot be "same submit description plus
// same parents", because the source for a RUNNING workflow is DAGMan's
// DOT file and a DOT file carries no submit descriptions at all (see
// instrument.go for why that is the source). The cost is that two
// isomorphic but unrelated subgraphs collapse together -- an honest
// drawing of "two of these ran side by side", not a wrong one, and the
// member list says exactly which nodes those were.
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
	parents, children, edgeCount := buildAdjacency(nodes, index, in.Edges)
	g.NodeCount = len(nodes)
	g.EdgeCount = edgeCount

	order, acyclic := topoOrder(nodes, parents, children)
	g.Approximate = !acyclic

	var ids []int
	if acyclic {
		var settled bool
		ids, settled = structuralGroups(order, parents, children)
		if !settled {
			g.Approximate = true
		}
	} else {
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
	return g
}

// structuralGroups assigns every node a group id by structural
// equivalence, and reports whether the refinement settled within its
// bound.
//
// The first pass assigns by parent-group set in topological order, which
// is exact for a graph whose nodes differ only upstream. Every pass after
// it REFINES -- the key always includes the node's current group, so a
// pass can split a group but never merge two -- which is what makes the
// loop terminate: group count is non-decreasing, bounded by the node
// count, and a pass that changes nothing ends it.
//
// The passes alternate direction and each walks in an order where the
// neighbours it reads have already been reassigned (parents first in
// topological order, children first in reverse), so one pass propagates a
// split the whole length of the graph instead of one edge per round.
func structuralGroups(order []int, parents, children [][]int) (ids []int, settled bool) {
	ids = make([]int, len(parents))
	count := assignBySet(order, ids, parents, false)
	for round := 0; round < collapseMaxRounds; round++ {
		assignBySet(reversed(order), ids, children, true)
		// Only the last pass's count is compared: a pass never merges, so
		// if the round ends with the group count it started with, neither
		// pass split anything and the partition is the fixpoint.
		n := assignBySet(order, ids, parents, true)
		if n == count {
			return ids, true
		}
		count = n
	}
	return ids, false
}

// assignBySet renumbers every node by (its current group, the set of
// groups of its adjacent nodes), walking in the given order so those
// neighbours are already renumbered. refine false drops the current-group
// term, which is how the first pass starts from nothing. It returns the
// number of groups.
func assignBySet(order []int, ids []int, adj [][]int, refine bool) int {
	keys := map[string]int{}
	next := make([]int, len(ids))
	var b strings.Builder
	for _, n := range order {
		b.Reset()
		if refine {
			b.WriteString(strconv.Itoa(ids[n]))
			b.WriteByte('|')
		}
		writeGroupSet(&b, ids, adj[n])
		key := b.String()
		id, ok := keys[key]
		if !ok {
			id = len(keys)
			keys[key] = id
		}
		next[n] = id
	}
	copy(ids, next)
	return len(keys)
}

// writeGroupSet writes the sorted, de-duplicated set of group ids of the
// given nodes.
func writeGroupSet(b *strings.Builder, ids []int, adj []int) {
	if len(adj) == 0 {
		return
	}
	set := make([]int, 0, len(adj))
	seen := make(map[int]bool, len(adj))
	for _, a := range adj {
		if id := ids[a]; !seen[id] {
			seen[id] = true
			set = append(set, id)
		}
	}
	sort.Ints(set)
	for i, id := range set {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(id))
	}
}

func reversed(order []int) []int {
	out := make([]int, len(order))
	for i, n := range order {
		out[len(order)-1-i] = n
	}
	return out
}

// collapsibleNodes is the node set a drawing shows, with a lower-cased
// name index for resolving edges the way DAGMan does.
func collapsibleNodes(g *Graph) ([]GraphNode, map[string]int) {
	nodes := make([]GraphNode, 0, len(g.Nodes))
	index := make(map[string]int, len(g.Nodes))
	for _, n := range g.Nodes {
		key := strings.ToLower(n.Name)
		if _, dup := index[key]; dup {
			// DAGMan rejects a duplicate node name outright; keeping
			// the first is enough to stay self-consistent here.
			continue
		}
		index[key] = len(nodes)
		nodes = append(nodes, n)
	}
	return nodes, index
}

// buildAdjacency turns the PARENT/CHILD list into parent and child
// adjacency, dropping what cannot be drawn: an edge naming a node this
// graph does not have (a splice placeholder, or ALL_NODES, which stands
// for every node rather than one), a self-edge, and a repeat of an edge
// already seen.
func buildAdjacency(nodes []GraphNode, index map[string]int, edges []Edge) (parents, children [][]int, count int) {
	parents = make([][]int, len(nodes))
	children = make([][]int, len(nodes))
	seen := make(map[[2]int]bool, len(edges))
	for _, e := range edges {
		p, okP := index[strings.ToLower(e.Parent)]
		c, okC := index[strings.ToLower(e.Child)]
		if !okP || !okC || p == c || seen[[2]int{p, c}] {
			continue
		}
		seen[[2]int{p, c}] = true
		parents[c] = append(parents[c], p)
		children[p] = append(children[p], c)
		count++
	}
	return parents, children, count
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
// links. In the acyclic case the two are the same set by construction.
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
				if pid >= 0 && pid != id && !seen[pid] {
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
// analyze_0..analyze_9999 -- and when the names share nothing the
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
	if prefix != "" {
		return prefix
	}
	if desc != "" {
		return desc
	}
	return names[0]
}

func commonPrefix(a, b string) string {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return a[:i]
}
