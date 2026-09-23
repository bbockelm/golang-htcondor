// Package dagman reads DAGMan workflow descriptions well enough to tell
// an agent what it still has to supply, and builds the scheduler-universe
// submit file that runs one.
//
// It is deliberately NOT a reimplementation of DAGMan's parser. The
// authority on what a .dag file means is condor_dagman itself; this
// package recognizes the commands that reference a file or shape the
// graph, and passes everything else through untouched. A command it does
// not know is not an error -- DAGMan gains syntax every release, and a
// parser that rejects what it has not been taught would make this tool
// useless for exactly the workflows worth running.
//
// The distinction that matters most here is WHEN a referenced file has to
// exist:
//
//   - SPLICE and INCLUDE are resolved at parse time. DAGMan reads the
//     file and inlines it into the parent graph before anything runs, so
//     a missing one means the DAG cannot start at all.
//   - SUBDAG EXTERNAL is resolved when the node becomes ready. The DAG
//     description "only needs to exist just before node submission time"
//     (docs/automated-workflows/dagman-using-other-dags.rst), which is
//     the whole point of the idiom: an earlier node generates it. A
//     SUBDAG file that is absent at submit time is the NORMAL case, not a
//     mistake.
//   - A node's submit file, when it is a file on disk rather than an
//     inline description, is read when that node is submitted. Writing or
//     rewriting a submit file from an earlier node's output is a standard
//     DAGMan trick, so an absent submit file is deferred exactly like a
//     sub-DAG description, not reported as a missing input.
//
// Conflating those is the easiest way to make this package reject good
// workflows, so they are separate paths all the way through.
package dagman

import (
	"bufio"
	"fmt"
	"strings"
)

// NodeType is the keyword that introduced a node.
type NodeType string

// The node types. SUBDAG and SPLICE are nodes too, but they reference a
// DAG description rather than a submit description, and at different
// times -- see the package comment.
const (
	NodeJob         NodeType = "JOB"
	NodeFinal       NodeType = "FINAL"
	NodeProvisioner NodeType = "PROVISIONER"
	NodeService     NodeType = "SERVICE"
	NodeSubdag      NodeType = "SUBDAG"
	NodeSplice      NodeType = "SPLICE"
)

// nodeKeywords mirrors NODE_KEYWORDS in condor_dagman/parse.cpp: the
// keywords that introduce a node and may carry an inline submit
// description.
var nodeKeywords = map[string]NodeType{
	"JOB":         NodeJob,
	"FINAL":       NodeFinal,
	"PROVISIONER": NodeProvisioner,
	"SERVICE":     NodeService,
}

// allNodes is DAG::ALL_NODES: a stand-in that resolves to every node, so
// it is never an undeclared node name.
const allNodes = "ALL_NODES"

// reservedNames is DAG::RESERVED (dag_commands.cpp): words a node may not
// be named, because the parser cannot tell them from syntax.
var reservedNames = map[string]bool{"PARENT": true, "CHILD": true, allNodes: true}

func isAllNodes(name string) bool { return strings.EqualFold(name, allNodes) }

// Node is one node of the graph.
type Node struct {
	Name string
	Type NodeType
	// Descriptor is what the node was pointed at: a submit file name, a
	// SUBMIT-DESCRIPTION name, or (for SUBDAG/SPLICE) a .dag file. Empty
	// when the node carried an inline description.
	Descriptor string
	// Inline is true when the submit description was written in the DAG
	// itself, with `{ ... }` or `@=tag ... @tag`. Such a node needs no
	// separate file staged, which is why it is the shape worth steering
	// an agent toward.
	Inline bool
	// InlineBody is the description text, for inline nodes.
	InlineBody string
	// Dir is the node's DIR argument, if any. It names a subdirectory,
	// which does not survive the flat basename rewrite the schedd applies
	// to a spooled sandbox -- see Analyze.
	Dir  string
	NOOP bool
	Done bool
	Line int
	// Source is the file this came from, when it was not the top-level
	// DAG: an INCLUDE'd or SPLICE'd file. Line numbers are relative to it.
	Source string
}

// ScriptWhen is which script slot a SCRIPT command filled.
type ScriptWhen string

// The script slots a SCRIPT command can fill.
const (
	ScriptPre  ScriptWhen = "PRE"
	ScriptPost ScriptWhen = "POST"
	ScriptHold ScriptWhen = "HOLD"
)

// Script is a PRE/POST/HOLD script. Scripts run on the access point, in
// the DAG's working directory, so their executables must be staged with
// the workflow.
type Script struct {
	Node       string
	When       ScriptWhen
	Executable string
	Args       []string
	Line       int
	Source     string
}

// Edge is one PARENT/CHILD dependency.
type Edge struct {
	Parent string
	Child  string
	Line   int
	Source string
}

// FileRef is a file named by a command, with the line that named it.
type FileRef struct {
	Path    string
	Command string
	Line    int
	Source  string
}

// JobAttr is one SET_JOB_ATTR command: an attribute set on the DAGMan
// MANAGER job's ClassAd, not on the node jobs
// (docs/automated-workflows/dagman-advance-functionality.rst).
//
// Value is the text after the first "=", verbatim and unquoted-nothing:
// it is a ClassAd expression, and the quotes around a string literal are
// part of it. condor_submit_dag keeps the whole line and writes
// `My.<line>` into the manager's submit file (dagman_utils.cpp), so
// anything that reinterpreted the value would change what the attribute
// means.
type JobAttr struct {
	Name   string
	Value  string
	Line   int
	Source string
}

// EnvVar is one ENV SET pair: a variable put into the DAGMan manager
// job's environment, and through it into every PRE/POST script and node
// submission DAGMan performs.
type EnvVar struct {
	Name   string
	Value  string
	Line   int
	Source string
}

// EnvGet is one ENV GET command: the variable names it asks to be copied
// from the environment of the process that SUBMITS the DAG. That process
// is condor_submit_dag for a local submission and this server for a
// remote one, which is why Analyze reports it rather than honouring it.
type EnvGet struct {
	Names  []string
	Line   int
	Source string
}

// Description is a named SUBMIT-DESCRIPTION block.
type Description struct {
	Name   string
	Body   string
	Line   int
	Source string
}

// ParseError is a line this package could not make sense of. It is
// advisory: DAGMan is the authority, and an unparsed line may well be
// valid syntax this package has not been taught.
type ParseError struct {
	Line   int
	Text   string
	Why    string
	Source string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("line %d: %s: %q", e.Line, e.Why, e.Text)
}

// DAG is a parsed workflow description.
type DAG struct {
	Nodes []Node
	// Descriptions are SUBMIT-DESCRIPTION blocks, keyed by name folded to
	// lower case: DAGMan matches description names case-insensitively.
	Descriptions map[string]Description
	Scripts      []Script
	Edges        []Edge
	// Includes and Configs are read by DAGMan at PARSE time. A missing
	// one is fatal before any node runs.
	Includes []FileRef
	Configs  []FileRef
	// DotIncludes are DOT ... INCLUDE header files. Unlike the other DOT
	// arguments they are read, not written.
	DotIncludes []FileRef
	// Outputs are files the DAG writes (NODE_STATUS_FILE, JOBSTATE_LOG,
	// SAVE_POINT_FILE, DOT). Tracked so nothing mistakes them for inputs
	// that must be staged.
	Outputs []FileRef
	// JobAttrs are SET_JOB_ATTR commands, in the order they were written.
	// Later ones win, as they do in condor_submit_dag: it appends every
	// line to the submit file and submit takes the last assignment.
	JobAttrs []JobAttr
	// EnvSet and EnvGet are the two halves of the ENV command. EnvSet
	// pairs are put into the manager job's environment; EnvGet names are
	// only reported, because the environment they name is not ours.
	EnvSet []EnvVar
	EnvGet []EnvGet
	// Vars are VARS assignments per node, lower-cased node name to the
	// raw remainder of the line. Kept for reporting, not expanded.
	Vars map[string][]string
	// VarNames maps the lower-cased key of Vars back to the spelling the
	// DAG used, so a message about it quotes the author's own text.
	VarNames map[string]string
	// Unrecognized are lines whose leading keyword this package does not
	// know. They are passed through to DAGMan untouched.
	Unrecognized []ParseError
	// Errors are lines whose keyword IS known but whose arguments did not
	// parse.
	Errors []ParseError
	// Fatals are lines DAGMan itself rejects: a duplicate or reserved
	// node name, for instance. Unlike Errors these are not "this package
	// did not understand it", they are "DAGMan will refuse this".
	Fatals []ParseError
	// Incomplete is set when a parse-time inclusion (INCLUDE or SPLICE)
	// could not be read, so the node set in hand is admittedly partial.
	// Nothing may conclude "that node is not declared" from it.
	Incomplete bool
}

// NodeByName finds a node, case-insensitively, as DAGMan does.
func (d *DAG) NodeByName(name string) (*Node, bool) {
	want := strings.ToLower(name)
	for i := range d.Nodes {
		if strings.ToLower(d.Nodes[i].Name) == want {
			return &d.Nodes[i], true
		}
	}
	return nil, false
}

// resolver supplies the text of a file named by INCLUDE or SPLICE, which
// DAGMan reads at parse time. Analyze passes one built from the files the
// caller supplied; the bare Parse entry point has none, and then a
// parse-time inclusion simply leaves the DAG Incomplete.
type resolver struct {
	lookup func(name string) (string, bool)
	// stack is the chain of files currently being parsed, so a file that
	// includes itself is caught rather than recursed into forever.
	stack []string
}

func (rs *resolver) has(name string) bool {
	if rs == nil || rs.lookup == nil {
		return false
	}
	_, ok := rs.lookup(name)
	return ok
}

func (rs *resolver) cycle(name string) bool {
	for _, s := range rs.stack {
		if s == name {
			return true
		}
	}
	return false
}

func (rs *resolver) child(name string) *resolver {
	next := make([]string, 0, len(rs.stack)+1)
	next = append(next, rs.stack...)
	next = append(next, name)
	return &resolver{lookup: rs.lookup, stack: next}
}

// Parse reads a DAG description.
//
// It never returns an error for unrecognized input: everything it could
// not interpret lands in DAG.Unrecognized, DAG.Errors or DAG.Fatals, and
// the caller decides what that is worth.
//
// Parse sees only the text it is given, so an INCLUDE or SPLICE leaves
// the result Incomplete. Analyze parses those recursively, because it is
// the one that knows which files the caller supplied.
func Parse(text string) *DAG {
	return parseText(text, nil)
}

func newDAG() *DAG {
	return &DAG{
		Descriptions: map[string]Description{},
		Vars:         map[string][]string{},
		VarNames:     map[string]string{},
	}
}

func parseText(text string, rs *resolver) *DAG {
	d := newDAG()
	lr := newLineReader(text)

	for {
		line, lineNo, ok := lr.next()
		if !ok {
			break
		}
		fields := splitFields(line)
		if len(fields) == 0 {
			continue
		}
		// dag_parser.cpp:965 folds '-' to '_' before looking the command
		// up, which is what makes PRE-SKIP and PRE_SKIP the same command.
		keyword := strings.ToUpper(strings.ReplaceAll(fields[0], "-", "_"))

		if nt, ok := nodeKeywords[keyword]; ok {
			d.parseNode(nt, fields, lineNo, lr)
			continue
		}

		switch keyword {
		case "SUBDAG":
			d.parseSubdag(fields, lineNo)
		case "SPLICE":
			d.parseSplice(fields, lineNo, rs)
		case "SUBMIT_DESCRIPTION":
			d.parseDescription(fields, lineNo, lr)
		case "SCRIPT":
			d.parseScript(fields, lineNo)
		case "PARENT":
			d.parseParent(fields, lineNo)
		case "WEAK":
			// WEAK PARENT ... CHILD ... is a PARENT/CHILD edge with a
			// weaker ordering guarantee; the graph is the same shape.
			if len(fields) >= 2 && strings.EqualFold(fields[1], "PARENT") {
				d.parseParent(fields[1:], lineNo)
			} else {
				d.errf(lineNo, line, "expected WEAK PARENT p1 [p2 ...] CHILD c1 [c2 ...]")
			}
		case "VARS":
			if len(fields) >= 2 {
				n := strings.ToLower(fields[1])
				d.Vars[n] = append(d.Vars[n], strings.Join(fields[2:], " "))
				if _, ok := d.VarNames[n]; !ok {
					d.VarNames[n] = fields[1]
				}
			} else {
				d.errf(lineNo, line, "VARS needs a node name")
			}
		case "INCLUDE", "CONFIG", "DOT", "NODE_STATUS_FILE", "JOBSTATE_LOG", "SAVE_POINT_FILE":
			d.parseFileCommand(keyword, fields, lineNo, line, rs)
		case "SET_JOB_ATTR":
			d.parseSetJobAttr(fields, lineNo, line)
		case "ENV":
			d.parseEnv(fields, lineNo, line)
		case "RETRY", "ABORT_DAG_ON", "PRIORITY", "CATEGORY", "MAXJOBS",
			"PRE_SKIP", "DONE", "REJECT",
			"CONNECT", "PIN_IN", "PIN_OUT", "TOLERANCE":
			// Known, and referencing no file. Nothing to collect.
		default:
			d.Unrecognized = append(d.Unrecognized, ParseError{
				Line: lineNo, Text: line, Why: "unrecognized command, passed through to DAGMan",
			})
		}
	}
	return d
}

// parseFileCommand handles the commands whose argument is a file name.
//
// They are grouped because the distinction that matters is not which
// keyword it is but WHEN the file is read: INCLUDE and CONFIG are read
// when DAGMan parses the DAG, so a missing one is fatal, while the
// others are written by the run and must never be asked of the caller.
func (d *DAG) parseFileCommand(keyword string, fields []string, lineNo int, line string, rs *resolver) {
	switch keyword {
	case "INCLUDE":
		if len(fields) >= 2 {
			p := unquote(fields[1])
			d.Includes = append(d.Includes, FileRef{Path: p, Command: keyword, Line: lineNo})
			d.include(p, lineNo, line, rs)
		} else {
			d.errf(lineNo, line, "INCLUDE needs a file name")
		}
	case "CONFIG":
		if len(fields) >= 2 {
			d.Configs = append(d.Configs, FileRef{Path: unquote(fields[1]), Command: keyword, Line: lineNo})
		} else {
			d.errf(lineNo, line, "CONFIG needs a file name")
		}
	case "DOT":
		// DOT <file> [UPDATE] [OVERWRITE] [INCLUDE <header>]. The dot
		// file is written; the INCLUDE header is read, so it has to be
		// staged like any other input.
		if len(fields) >= 2 {
			d.Outputs = append(d.Outputs, FileRef{Path: unquote(fields[1]), Command: keyword, Line: lineNo})
		}
		for i := 2; i+1 < len(fields); i++ {
			if strings.EqualFold(fields[i], "INCLUDE") {
				d.DotIncludes = append(d.DotIncludes, FileRef{
					Path: unquote(fields[i+1]), Command: "DOT INCLUDE", Line: lineNo})
				break
			}
		}
	case "NODE_STATUS_FILE", "JOBSTATE_LOG":
		// Outputs, not inputs. Recorded so the analyzer does not ask
		// the caller to stage a file the DAG is going to write.
		if len(fields) >= 2 {
			d.Outputs = append(d.Outputs, FileRef{Path: unquote(fields[1]), Command: keyword, Line: lineNo})
		}
	case "SAVE_POINT_FILE":
		// SAVE_POINT_FILE <node> [filename] -- the file is the
		// SECOND argument, and is optional.
		if len(fields) >= 3 {
			d.Outputs = append(d.Outputs, FileRef{Path: unquote(fields[2]), Command: keyword, Line: lineNo})
		}
	}
}

func (d *DAG) errf(line int, text, why string) {
	d.Errors = append(d.Errors, ParseError{Line: line, Text: text, Why: why})
}

func (d *DAG) fatalf(line int, text, why string) {
	d.Fatals = append(d.Fatals, ParseError{Line: line, Text: text, Why: why})
}

// addNode applies the two cheap rules DAGMan enforces on a node name
// (dag_parser.cpp:316-323, condor_dagman/parse.cpp:112-122): it may not be
// a reserved word, and it may not contain '+', which is the separator
// DAGMan itself uses to scope splice node names.
func (d *DAG) addNode(n Node, text string) {
	if reservedNames[strings.ToUpper(n.Name)] {
		d.fatalf(n.Line, text, fmt.Sprintf("node name %q is a reserved word", n.Name))
		return
	}
	if strings.Contains(n.Name, "+") {
		d.fatalf(n.Line, text, fmt.Sprintf("node name %q contains '+', which DAGMan reserves for splice scopes", n.Name))
		return
	}
	d.Nodes = append(d.Nodes, n)
}

// parseNode handles JOB / FINAL / PROVISIONER / SERVICE, including the
// inline submit description forms.
//
//	JOB NodeName SubmitDescription [DIR directory] [NOOP] [DONE]
//	JOB NodeName { ... } [DIR directory]
//	JOB NodeName @=tag ... @tag [DIR directory]
func (d *DAG) parseNode(nt NodeType, fields []string, line int, lr *lineReader) {
	text := strings.Join(fields, " ")
	if len(fields) < 3 {
		d.errf(line, text, string(nt)+" needs a name and a submit description")
		return
	}
	n := Node{Name: unquote(fields[1]), Type: nt, Line: line}

	if end, ok := inlineDescEnd(fields[2]); ok {
		body, rest, err := readInlineDesc(lr, end)
		if err != nil {
			d.errf(line, text, err.Error())
			return
		}
		n.Inline = true
		n.InlineBody = body
		// DAGMan re-lexes whatever followed the closing delimiter
		// (dag_parser.cpp:268), so `} DIR sub` is a node with a DIR.
		applyNodeOptions(&n, splitFields(rest))
	} else {
		n.Descriptor = unquote(fields[2])
		applyNodeOptions(&n, fields[3:])
	}
	d.addNode(n, text)
}

// parseSubdag handles `SUBDAG EXTERNAL Name DagFile [DIR d] [NOOP] [DONE]`.
func (d *DAG) parseSubdag(fields []string, line int) {
	text := strings.Join(fields, " ")
	// EXTERNAL is the only supported form, and is required.
	if len(fields) < 4 || !strings.EqualFold(fields[1], "EXTERNAL") {
		d.errf(line, text, "expected SUBDAG EXTERNAL <name> <dagfile>")
		return
	}
	n := Node{Name: unquote(fields[2]), Type: NodeSubdag, Descriptor: unquote(fields[3]), Line: line}
	applyNodeOptions(&n, fields[4:])
	d.addNode(n, text)
}

// parseSplice handles `SPLICE Name DagFile [DIR d]`.
//
// A splice is inlined at parse time, so when the file is in hand this
// reads it and merges its graph in, with every node name prefixed
// "Name+" -- the scope separator condor_dagman/parse.cpp uses
// (current_splice_scope). Without the file the graph is Incomplete.
func (d *DAG) parseSplice(fields []string, line int, rs *resolver) {
	text := strings.Join(fields, " ")
	if len(fields) < 3 {
		d.errf(line, text, "expected SPLICE <name> <dagfile>")
		return
	}
	n := Node{Name: unquote(fields[1]), Type: NodeSplice, Descriptor: unquote(fields[2]), Line: line}
	applyNodeOptions(&n, fields[3:])
	before := len(d.Nodes)
	d.addNode(n, text)
	if len(d.Nodes) == before {
		return // the name was refused; nothing to splice into
	}

	if !rs.has(n.Descriptor) {
		d.Incomplete = true
		return
	}
	if rs.cycle(n.Descriptor) {
		d.errf(line, text, "SPLICE "+n.Descriptor+" is already being parsed; a splice cannot contain itself")
		d.Incomplete = true
		return
	}
	body, _ := rs.lookup(n.Descriptor)
	sub := parseText(body, rs.child(n.Descriptor))
	d.merge(sub, n.Descriptor, n.Name+"+")
}

// include merges an INCLUDE'd file, which DAGMan reads at parse time as
// if its text had been written in place.
func (d *DAG) include(p string, line int, text string, rs *resolver) {
	if !rs.has(p) {
		// Still Fatal in the analysis -- but the node set in hand is now
		// admittedly partial, so nothing may call a node undeclared.
		d.Incomplete = true
		return
	}
	if rs.cycle(p) {
		d.errf(line, text, "INCLUDE "+p+" is already being parsed; a file cannot include itself")
		d.Incomplete = true
		return
	}
	body, _ := rs.lookup(p)
	sub := parseText(body, rs.child(p))
	d.merge(sub, p, "")
}

// merge folds a parsed INCLUDE or SPLICE into its parent. prefix is the
// splice scope ("" for an INCLUDE, which has no scope of its own), and
// source is the file the merged material came from, so a finding can say
// which file a line number belongs to.
func (d *DAG) merge(o *DAG, source, prefix string) {
	pfx := func(name string) string {
		if prefix == "" || isAllNodes(name) {
			return name
		}
		return prefix + name
	}
	src := func(s string) string {
		if s != "" {
			return s
		}
		return source
	}
	for _, n := range o.Nodes {
		n.Name = pfx(n.Name)
		n.Source = src(n.Source)
		d.Nodes = append(d.Nodes, n)
	}
	for _, e := range o.Edges {
		e.Parent, e.Child, e.Source = pfx(e.Parent), pfx(e.Child), src(e.Source)
		d.Edges = append(d.Edges, e)
	}
	for _, s := range o.Scripts {
		s.Node, s.Source = pfx(s.Node), src(s.Source)
		d.Scripts = append(d.Scripts, s)
	}
	for k, v := range o.Descriptions {
		if _, ok := d.Descriptions[k]; ok {
			continue
		}
		v.Source = src(v.Source)
		d.Descriptions[k] = v
	}
	for k, vals := range o.Vars {
		orig := o.VarNames[k]
		if orig == "" {
			orig = k
		}
		nk := strings.ToLower(pfx(k))
		d.Vars[nk] = append(d.Vars[nk], vals...)
		if _, ok := d.VarNames[nk]; !ok {
			d.VarNames[nk] = pfx(orig)
		}
	}
	for _, a := range o.JobAttrs {
		a.Source = src(a.Source)
		d.JobAttrs = append(d.JobAttrs, a)
	}
	for _, e := range o.EnvSet {
		e.Source = src(e.Source)
		d.EnvSet = append(d.EnvSet, e)
	}
	for _, e := range o.EnvGet {
		e.Source = src(e.Source)
		d.EnvGet = append(d.EnvGet, e)
	}
	refs := func(dst *[]FileRef, in []FileRef) {
		for _, f := range in {
			f.Source = src(f.Source)
			*dst = append(*dst, f)
		}
	}
	refs(&d.Includes, o.Includes)
	refs(&d.Configs, o.Configs)
	refs(&d.DotIncludes, o.DotIncludes)
	refs(&d.Outputs, o.Outputs)
	errs := func(dst *[]ParseError, in []ParseError) {
		for _, e := range in {
			e.Source = src(e.Source)
			*dst = append(*dst, e)
		}
	}
	errs(&d.Unrecognized, o.Unrecognized)
	errs(&d.Errors, o.Errors)
	errs(&d.Fatals, o.Fatals)
	if o.Incomplete {
		d.Incomplete = true
	}
}

func applyNodeOptions(n *Node, rest []string) {
	for i := 0; i < len(rest); i++ {
		switch strings.ToUpper(rest[i]) {
		case "DIR":
			if i+1 < len(rest) {
				n.Dir = unquote(rest[i+1])
				i++
			}
		case "NOOP":
			n.NOOP = true
		case "DONE":
			n.Done = true
		}
	}
}

// parseDescription handles `SUBMIT-DESCRIPTION Name { ... }`.
func (d *DAG) parseDescription(fields []string, line int, lr *lineReader) {
	text := strings.Join(fields, " ")
	if len(fields) < 3 {
		d.errf(line, text, "expected SUBMIT-DESCRIPTION <name> { ... }")
		return
	}
	end, ok := inlineDescEnd(fields[2])
	if !ok {
		d.errf(line, text, "SUBMIT-DESCRIPTION must open an inline block with { or @=tag")
		return
	}
	body, _, err := readInlineDesc(lr, end)
	if err != nil {
		d.errf(line, text, err.Error())
		return
	}
	name := unquote(fields[1])
	d.Descriptions[strings.ToLower(name)] = Description{Name: name, Body: body, Line: line}
}

// parseScript handles
// `SCRIPT [DEFER n s] [DEBUG file type] PRE|POST|HOLD node exe [args]`.
func (d *DAG) parseScript(fields []string, line int) {
	text := strings.Join(fields, " ")
	// DEFER and DEBUG are optional modifiers that sit between the SCRIPT
	// keyword and the script type, each taking two arguments.
	i := 1
	for i < len(fields) {
		kw := strings.ToUpper(fields[i])
		if kw != "DEFER" && kw != "DEBUG" {
			break
		}
		i += 3
	}
	if i+2 >= len(fields) {
		d.errf(line, text, "expected SCRIPT [DEFER n s] PRE|POST|HOLD <node> <executable>")
		return
	}
	var when ScriptWhen
	switch strings.ToUpper(fields[i]) {
	case "PRE":
		when = ScriptPre
	case "POST":
		when = ScriptPost
	case "HOLD":
		when = ScriptHold
	default:
		d.errf(line, text, "SCRIPT type must be PRE, POST or HOLD")
		return
	}
	d.Scripts = append(d.Scripts, Script{
		Node:       unquote(fields[i+1]),
		When:       when,
		Executable: unquote(fields[i+2]),
		Args:       fields[i+3:],
		Line:       line,
	})
}

// parseParent handles `PARENT p1 p2 ... CHILD c1 c2 ...`.
func (d *DAG) parseParent(fields []string, line int) {
	text := strings.Join(fields, " ")
	split := -1
	for i, f := range fields {
		if strings.EqualFold(f, "CHILD") {
			split = i
			break
		}
	}
	if split < 0 {
		d.errf(line, text, "PARENT list has no CHILD keyword")
		return
	}
	parents := fields[1:split]
	children := fields[split+1:]
	if len(parents) == 0 || len(children) == 0 {
		d.errf(line, text, "PARENT/CHILD needs at least one node on each side")
		return
	}
	for _, p := range parents {
		for _, c := range children {
			d.Edges = append(d.Edges, Edge{Parent: unquote(p), Child: unquote(c), Line: line})
		}
	}
}

// parseSetJobAttr handles `SET_JOB_ATTR <name> = <value>`.
//
// DAGMan's own parser (dag_parser.cpp, DAG::CMD::SET_JOB_ATTR) does not
// look at the line at all beyond checking it is non-empty: it keeps the
// remainder verbatim and condor_submit_dag writes `My.<remainder>` into
// the manager job's submit file. Splitting at the FIRST "=" is therefore
// only for reporting and for the reserved-name guard -- the value is
// reassembled unchanged, quotes included, because those quotes are what
// make it a string rather than a bare identifier.
func (d *DAG) parseSetJobAttr(fields []string, line int, text string) {
	rest := strings.TrimSpace(strings.Join(fields[1:], " "))
	if rest == "" {
		d.errf(line, text, "expected SET_JOB_ATTR <name> = <value>")
		return
	}
	i := strings.Index(rest, "=")
	if i < 0 {
		d.errf(line, text, "SET_JOB_ATTR needs an assignment: <name> = <value>")
		return
	}
	name := strings.TrimSpace(rest[:i])
	value := strings.TrimSpace(rest[i+1:])
	if name == "" {
		d.errf(line, text, "SET_JOB_ATTR has no attribute name before the '='")
		return
	}
	if value == "" {
		d.errf(line, text, "SET_JOB_ATTR "+name+" has no value after the '='")
		return
	}
	d.JobAttrs = append(d.JobAttrs, JobAttr{Name: name, Value: value, Line: line})
}

// parseEnv handles `ENV SET Key=Value;Key=Value; ...` and
// `ENV GET VAR-1 [VAR-2 ...]`, mirroring DagParser::ParseEnv.
//
// The two halves have DIFFERENT delimiters, which is the detail worth
// getting right: GET takes a whitespace-separated list of names, while
// SET takes the remainder of the line as an HTCondor environment string
// -- semicolon-delimited in V1 raw form, or the whole thing in double
// quotes and space-separated in V2 form, which is what
// Env::MergeFromV1RawOrV2Quoted accepts.
func (d *DAG) parseEnv(fields []string, line int, text string) {
	if len(fields) < 2 {
		d.errf(line, text, "expected ENV SET <pairs> or ENV GET <names>")
		return
	}
	switch strings.ToUpper(fields[1]) {
	case "GET":
		var names []string
		for _, f := range fields[2:] {
			if n := strings.TrimSpace(unquote(f)); n != "" {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			d.errf(line, text, "ENV GET needs at least one environment variable name")
			return
		}
		d.EnvGet = append(d.EnvGet, EnvGet{Names: names, Line: line})
	case "SET":
		rest := strings.TrimSpace(strings.Join(fields[2:], " "))
		if rest == "" {
			d.errf(line, text, "ENV SET needs at least one key=value pair")
			return
		}
		pairs, err := splitEnvPairs(rest)
		if err != nil {
			d.errf(line, text, err.Error())
			return
		}
		for _, p := range pairs {
			p.Line = line
			d.EnvSet = append(d.EnvSet, p)
		}
	default:
		d.errf(line, text, "ENV needs a sub-command, SET or GET, before the variables")
	}
}

// splitEnvPairs reads the argument of ENV SET.
//
// V2 quoted form ("A=1 B=2") is space-delimited; everything else is the
// V1 raw form, which on Unix is delimited with ';' (env.cpp's
// env_delimiter). Getting this backwards would turn `A=one two;B=3` into
// three variables, two of them nonsense.
func splitEnvPairs(rest string) ([]EnvVar, error) {
	var parts []string
	if len(rest) >= 2 && strings.HasPrefix(rest, `"`) && strings.HasSuffix(rest, `"`) {
		parts = strings.Fields(rest[1 : len(rest)-1])
	} else {
		parts = strings.Split(rest, ";")
	}
	var out []EnvVar
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			// A trailing ';' is how the documented example is written
			// (Key=Value;Key=Value; ...), so it is not an error.
			continue
		}
		i := strings.Index(p, "=")
		if i <= 0 {
			return nil, fmt.Errorf("ENV SET %q is not a key=value pair", p)
		}
		out = append(out, EnvVar{Name: strings.TrimSpace(p[:i]), Value: p[i+1:]})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ENV SET needs at least one key=value pair")
	}
	return out, nil
}

// inlineDescEnd mirrors get_inline_desc_end in condor_dagman/parse.cpp:
// `{` closes with `}`, and `@=tag` closes with `@tag`.
func inlineDescEnd(tok string) (string, bool) {
	switch {
	case tok == "":
		return "", false
	case strings.HasPrefix(tok, "{"):
		return "}", true
	case strings.HasPrefix(tok, "@="):
		return "@" + tok[2:], true
	}
	return "", false
}

// lineReader turns physical lines into the logical lines DAGMan parses.
//
// A line whose trimmed form ends in a backslash continues onto the next,
// joined with a single space (dag_parser.cpp:231-235). The logical line's
// number is that of its FIRST physical line, so a finding points at the
// command the author wrote rather than its last fragment.
type lineReader struct {
	sc     *bufio.Scanner
	lineNo int
}

func newLineReader(text string) *lineReader {
	sc := bufio.NewScanner(strings.NewReader(text))
	// DAG lines are short, but an inline submit description can make a
	// logical line long; raise the cap so a big one does not truncate
	// into a confusing parse error.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return &lineReader{sc: sc}
}

// raw returns the next physical line, verbatim.
func (lr *lineReader) raw() (string, int, bool) {
	if !lr.sc.Scan() {
		return "", 0, false
	}
	lr.lineNo++
	return lr.sc.Text(), lr.lineNo, true
}

// next returns the next logical line: comments and blanks skipped,
// continuations joined.
func (lr *lineReader) next() (string, int, bool) {
	var b strings.Builder
	first := 0
	started := false
	for {
		raw, n, ok := lr.raw()
		if !ok {
			if started {
				return b.String(), first, true
			}
			return "", 0, false
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !started {
			first, started = n, true
		} else {
			b.WriteString(" ")
		}
		if strings.HasSuffix(line, `\`) {
			b.WriteString(strings.TrimSuffix(line, `\`))
			continue
		}
		b.WriteString(line)
		return b.String(), first, true
	}
}

// readInlineDesc consumes lines up to the closing delimiter and returns
// the body plus whatever followed the delimiter on its own line, which
// DAGMan re-lexes as further node options.
func readInlineDesc(lr *lineReader, end string) (body, rest string, err error) {
	var b strings.Builder
	for {
		line, _, ok := lr.raw()
		if !ok {
			return "", "", fmt.Errorf("inline submit description is never closed (expected a line containing only %q)", end)
		}
		t := strings.TrimSpace(line)
		if t == end {
			return b.String(), "", nil
		}
		if strings.HasPrefix(t, end+" ") || strings.HasPrefix(t, end+"\t") {
			return b.String(), strings.TrimSpace(t[len(end):]), nil
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
}

// splitFields splits a line into tokens the way DagLexer does
// (dag_parser.cpp:35-77): whitespace separates, either quote character
// groups, and a backslash inside quotes escapes the next character. The
// quotes are kept on the token; unquote strips them.
func splitFields(line string) []string {
	var out []string
	var cur strings.Builder
	quote := rune(0)
	escaped := false
	started := false
	flush := func() {
		if started {
			out = append(out, cur.String())
			cur.Reset()
			started = false
		}
	}
	for _, r := range line {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case quote != 0:
			started = true
			switch r {
			case '\\':
				escaped = true
			case quote:
				cur.WriteRune(r)
				quote = 0
			default:
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			started = true
			cur.WriteRune(r)
		case r == ' ' || r == '\t' || r == '\r':
			flush()
		default:
			started = true
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`)) ||
			(strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`)) {
			return s[1 : len(s)-1]
		}
	}
	return s
}
