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
//   - SPLICE is resolved at parse time. DAGMan reads the splice file and
//     inlines its nodes into the parent graph before anything runs, so a
//     missing splice file means the DAG cannot start at all.
//   - SUBDAG EXTERNAL is resolved when the node becomes ready. The DAG
//     description "only needs to exist just before node submission time"
//     (docs/automated-workflows/dagman-using-other-dags.rst), which is
//     the whole point of the idiom: an earlier node generates it. A
//     SUBDAG file that is absent at submit time is the NORMAL case, not a
//     mistake.
//
// Conflating those two is the easiest way to make this package reject
// good workflows, so they are separate types all the way through.
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
}

// Edge is one PARENT/CHILD dependency.
type Edge struct {
	Parent string
	Child  string
	Line   int
}

// FileRef is a file named by a command, with the line that named it.
type FileRef struct {
	Path    string
	Command string
	Line    int
}

// Description is a named SUBMIT-DESCRIPTION block.
type Description struct {
	Name string
	Body string
	Line int
}

// ParseError is a line this package could not make sense of. It is
// advisory: DAGMan is the authority, and an unparsed line may well be
// valid syntax this package has not been taught.
type ParseError struct {
	Line int
	Text string
	Why  string
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
	// Outputs are files the DAG writes (NODE_STATUS_FILE, JOBSTATE_LOG,
	// SAVE_POINT_FILE, DOT). Tracked so nothing mistakes them for inputs
	// that must be staged.
	Outputs []FileRef
	// Vars are VARS assignments per node, lower-cased node name to the
	// raw remainder of the line. Kept for reporting, not expanded.
	Vars map[string][]string
	// Unrecognized are lines whose leading keyword this package does not
	// know. They are passed through to DAGMan untouched.
	Unrecognized []ParseError
	// Errors are lines whose keyword IS known but whose arguments did not
	// parse.
	Errors []ParseError
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

// Parse reads a DAG description.
//
// It never returns an error for unrecognized input: everything it could
// not interpret lands in DAG.Unrecognized or DAG.Errors, and the caller
// decides what that is worth. The only way to get nothing back is a read
// failure on the reader itself.
func Parse(text string) *DAG {
	d := &DAG{
		Descriptions: map[string]Description{},
		Vars:         map[string][]string{},
	}

	sc := bufio.NewScanner(strings.NewReader(text))
	// DAG lines are short, but an inline submit description can make a
	// logical line long; raise the cap so a big one does not truncate
	// into a confusing parse error.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := splitFields(line)
		if len(fields) == 0 {
			continue
		}
		keyword := strings.ToUpper(fields[0])

		if nt, ok := nodeKeywords[keyword]; ok {
			d.parseNode(nt, fields, lineNo, sc, &lineNo)
			continue
		}

		switch keyword {
		case "SUBDAG":
			d.parseSubdag(fields, lineNo)
		case "SPLICE":
			d.parseSplice(fields, lineNo)
		case "SUBMIT-DESCRIPTION":
			d.parseDescription(fields, lineNo, sc, &lineNo)
		case "SCRIPT":
			d.parseScript(fields, lineNo)
		case "PARENT":
			d.parseParent(fields, lineNo)
		case "VARS":
			if len(fields) >= 2 {
				n := strings.ToLower(fields[1])
				d.Vars[n] = append(d.Vars[n], strings.Join(fields[2:], " "))
			}
		case "INCLUDE":
			if len(fields) >= 2 {
				d.Includes = append(d.Includes, FileRef{Path: unquote(fields[1]), Command: keyword, Line: lineNo})
			} else {
				d.errf(lineNo, line, "INCLUDE needs a file name")
			}
		case "CONFIG":
			if len(fields) >= 2 {
				d.Configs = append(d.Configs, FileRef{Path: unquote(fields[1]), Command: keyword, Line: lineNo})
			} else {
				d.errf(lineNo, line, "CONFIG needs a file name")
			}
		case "NODE_STATUS_FILE", "JOBSTATE_LOG", "DOT":
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
		case "RETRY", "ABORT-DAG-ON", "PRIORITY", "CATEGORY", "MAXJOBS",
			"PRE_SKIP", "DONE", "REJECT", "SET_JOB_ATTR", "ENV",
			"CONNECT", "PIN_IN", "PIN_OUT":
			// Known, and referencing no file. Nothing to collect.
		default:
			d.Unrecognized = append(d.Unrecognized, ParseError{
				Line: lineNo, Text: line, Why: "unrecognized command, passed through to DAGMan",
			})
		}
	}
	return d
}

func (d *DAG) errf(line int, text, why string) {
	d.Errors = append(d.Errors, ParseError{Line: line, Text: text, Why: why})
}

// parseNode handles JOB / FINAL / PROVISIONER / SERVICE, including the
// inline submit description forms.
//
//	JOB NodeName SubmitDescription [DIR directory] [NOOP] [DONE]
//	JOB NodeName { ... }
//	JOB NodeName @=tag ... @tag
func (d *DAG) parseNode(nt NodeType, fields []string, line int, sc *bufio.Scanner, lineNo *int) {
	if len(fields) < 3 {
		d.errf(line, strings.Join(fields, " "), string(nt)+" needs a name and a submit description")
		return
	}
	n := Node{Name: fields[1], Type: nt, Line: line}

	if end, ok := inlineDescEnd(fields[2]); ok {
		body, err := readInlineDesc(sc, end, lineNo)
		if err != nil {
			d.errf(line, strings.Join(fields, " "), err.Error())
			return
		}
		n.Inline = true
		n.InlineBody = body
		// Options after the closing delimiter are not supported here; a
		// DIR on an inline node is vanishingly rare and guessing would be
		// worse than not claiming to know.
	} else {
		n.Descriptor = unquote(fields[2])
		applyNodeOptions(&n, fields[3:])
	}
	d.Nodes = append(d.Nodes, n)
}

// parseSubdag handles `SUBDAG EXTERNAL Name DagFile [DIR d] [NOOP] [DONE]`.
func (d *DAG) parseSubdag(fields []string, line int) {
	// EXTERNAL is the only supported form, and is required.
	if len(fields) < 4 || !strings.EqualFold(fields[1], "EXTERNAL") {
		d.errf(line, strings.Join(fields, " "), "expected SUBDAG EXTERNAL <name> <dagfile>")
		return
	}
	n := Node{Name: fields[2], Type: NodeSubdag, Descriptor: unquote(fields[3]), Line: line}
	applyNodeOptions(&n, fields[4:])
	d.Nodes = append(d.Nodes, n)
}

// parseSplice handles `SPLICE Name DagFile [DIR d]`.
func (d *DAG) parseSplice(fields []string, line int) {
	if len(fields) < 3 {
		d.errf(line, strings.Join(fields, " "), "expected SPLICE <name> <dagfile>")
		return
	}
	n := Node{Name: fields[1], Type: NodeSplice, Descriptor: unquote(fields[2]), Line: line}
	applyNodeOptions(&n, fields[3:])
	d.Nodes = append(d.Nodes, n)
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
func (d *DAG) parseDescription(fields []string, line int, sc *bufio.Scanner, lineNo *int) {
	if len(fields) < 3 {
		d.errf(line, strings.Join(fields, " "), "expected SUBMIT-DESCRIPTION <name> { ... }")
		return
	}
	end, ok := inlineDescEnd(fields[2])
	if !ok {
		d.errf(line, strings.Join(fields, " "), "SUBMIT-DESCRIPTION must open an inline block with { or @=tag")
		return
	}
	body, err := readInlineDesc(sc, end, lineNo)
	if err != nil {
		d.errf(line, strings.Join(fields, " "), err.Error())
		return
	}
	d.Descriptions[strings.ToLower(fields[1])] = Description{Name: fields[1], Body: body, Line: line}
}

// parseScript handles
// `SCRIPT [DEFER n s] [DEBUG file type] PRE|POST|HOLD node exe [args]`.
func (d *DAG) parseScript(fields []string, line int) {
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
		d.errf(line, strings.Join(fields, " "), "expected SCRIPT [DEFER n s] PRE|POST|HOLD <node> <executable>")
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
		d.errf(line, strings.Join(fields, " "), "SCRIPT type must be PRE, POST or HOLD")
		return
	}
	d.Scripts = append(d.Scripts, Script{
		Node:       fields[i+1],
		When:       when,
		Executable: unquote(fields[i+2]),
		Args:       fields[i+3:],
		Line:       line,
	})
}

// parseParent handles `PARENT p1 p2 ... CHILD c1 c2 ...`.
func (d *DAG) parseParent(fields []string, line int) {
	split := -1
	for i, f := range fields {
		if strings.EqualFold(f, "CHILD") {
			split = i
			break
		}
	}
	if split < 0 {
		d.errf(line, strings.Join(fields, " "), "PARENT list has no CHILD keyword")
		return
	}
	parents := fields[1:split]
	children := fields[split+1:]
	if len(parents) == 0 || len(children) == 0 {
		d.errf(line, strings.Join(fields, " "), "PARENT/CHILD needs at least one node on each side")
		return
	}
	for _, p := range parents {
		for _, c := range children {
			d.Edges = append(d.Edges, Edge{Parent: p, Child: c, Line: line})
		}
	}
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

// readInlineDesc consumes lines up to the closing delimiter and returns
// the body. lineNo is advanced so later errors still carry true line
// numbers.
func readInlineDesc(sc *bufio.Scanner, end string, lineNo *int) (string, error) {
	var b strings.Builder
	for sc.Scan() {
		*lineNo++
		line := sc.Text()
		if strings.TrimSpace(line) == end {
			return b.String(), nil
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return "", fmt.Errorf("inline submit description is never closed (expected a line containing only %q)", end)
}

// splitFields splits on whitespace while keeping a double-quoted run
// together, since submit-description names and paths may be quoted.
func splitFields(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		return s[1 : len(s)-1]
	}
	return s
}
