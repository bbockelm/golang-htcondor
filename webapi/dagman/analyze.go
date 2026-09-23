package dagman

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Severity separates "this DAG cannot start" from "this may be fine".
//
// The split is the whole value of the analysis. A DAG that discovers its
// own shape as it runs -- the SUBDAG idiom -- legitimately references
// files that do not exist yet, so a check that treats every absent file
// as an error would fire hardest on the most interesting workflows.
type Severity int

const (
	// Advisory is worth telling the caller about but is not evidence of
	// a mistake.
	Advisory Severity = iota
	// Warning is probably a mistake: it will most likely fail at run
	// time, but there are legitimate arrangements where it will not.
	Warning
	// Fatal means DAGMan provably cannot start this workflow.
	Fatal
)

func (s Severity) String() string {
	switch s {
	case Fatal:
		return "error"
	case Warning:
		return "warning"
	default:
		return "note"
	}
}

// Finding is one thing the analysis noticed.
type Finding struct {
	Severity Severity
	Message  string
	Line     int
}

// Report is what Analyze concluded.
type Report struct {
	Findings []Finding
	// Staged are the files the caller supplied, sorted.
	Staged []string
	// Required is the file list the DAGMan job must declare so the
	// schedd's spool allow-set covers everything. Computed rather than
	// asked for: an undeclared file is silently skipped at spool time,
	// not rejected, so a list the caller writes by hand fails invisibly.
	Required []string
	// Deferred are files referenced by SUBDAG nodes that are not staged.
	// These are expected to be produced during the run.
	Deferred []string
}

// Fatal reports whether anything makes the workflow unstartable.
func (r *Report) Fatal() bool {
	for _, f := range r.Findings {
		if f.Severity == Fatal {
			return true
		}
	}
	return false
}

// Errors returns the fatal findings' messages.
func (r *Report) Errors() []string {
	var out []string
	for _, f := range r.Findings {
		if f.Severity == Fatal {
			out = append(out, f.Message)
		}
	}
	return out
}

// Input is a workflow as the caller supplied it.
type Input struct {
	// DagName is the file name the DAG description will be written as.
	DagName string
	// Dag is the DAG description text.
	Dag string
	// Files are the other files supplied inline, by name.
	Files map[string]string
	// Declared are names the caller promised to upload separately, after
	// submission. They count as satisfying a reference -- the bytes are
	// not here yet, but the name will be in the spool allow-set, which is
	// what has to be decided at submit time.
	Declared []string
}

// Analyze cross-checks a parsed DAG against the files supplied with it.
//
// It answers three questions the caller cannot answer for itself:
// what must be staged and is not, what was staged and is used by nothing,
// and which of the gaps are expected to close on their own while the
// workflow runs.
func Analyze(in Input) *Report {
	d := Parse(in.Dag)
	r := &Report{}

	have := map[string]bool{}
	for name := range in.Files {
		have[name] = true
	}
	for _, name := range in.Declared {
		have[name] = true
	}

	// Referenced tracks what was asked for, so files supplied and used by
	// nothing can be reported. The DAG itself is always "used".
	referenced := map[string]bool{}
	need := func(p string, sev Severity, what string, line int) {
		if p == "" || isURL(p) || strings.HasPrefix(p, "/") {
			// A URL is fetched by whoever needs it; an absolute path
			// refers to the access point's filesystem, which we cannot
			// see from here. Neither is ours to stage.
			return
		}
		referenced[p] = true
		if have[p] {
			return
		}
		r.Findings = append(r.Findings, Finding{
			Severity: sev,
			Line:     line,
			Message:  fmt.Sprintf("%s is not among the supplied files (%s)", p, what),
		})
	}

	for _, ref := range d.Includes {
		need(ref.Path, Fatal, "INCLUDE is read when DAGMan parses the DAG, so the workflow cannot start without it", ref.Line)
	}
	for _, ref := range d.Configs {
		need(ref.Path, Fatal, "CONFIG is read when DAGMan parses the DAG", ref.Line)
	}
	for _, s := range d.Scripts {
		need(s.Executable, Warning,
			fmt.Sprintf("SCRIPT %s for node %s runs on the access point", s.When, s.Node), s.Line)
	}

	for i := range d.Nodes {
		n := &d.Nodes[i]
		switch n.Type {
		case NodeSplice:
			need(n.Descriptor, Fatal,
				fmt.Sprintf("SPLICE %s is inlined when DAGMan parses the DAG, so it must be supplied now", n.Name), n.Line)
		case NodeSubdag:
			analyzeSubdag(r, d, n, have, referenced)
		default:
			analyzeJobNode(d, n, in, need)
		}
		if n.Dir != "" {
			r.Findings = append(r.Findings, Finding{
				Severity: Fatal,
				Line:     n.Line,
				Message: fmt.Sprintf("node %s uses DIR %q, which a spooled workflow cannot honor: "+
					"the schedd flattens a spooled sandbox to basenames in one directory. "+
					"Remove the DIR and give the files distinct names.", n.Name, n.Dir),
			})
		}
	}

	checkGraph(r, d)
	checkCollisions(r, d, in)

	for name := range in.Files {
		if name == in.DagName || referenced[name] {
			continue
		}
		r.Findings = append(r.Findings, Finding{
			Severity: Warning,
			Message: fmt.Sprintf("%s was supplied but nothing in the DAG references it. "+
				"A spooled file that no job declares is silently dropped, so this is usually a "+
				"misspelling of a name the DAG does reference.", name),
		})
	}

	for _, e := range d.Errors {
		r.Findings = append(r.Findings, Finding{Severity: Warning, Line: e.Line, Message: e.Why + ": " + e.Text})
	}

	r.Staged = sortedKeys(in.Files)
	r.Required = buildRequired(in)
	sort.Slice(r.Findings, func(i, j int) bool {
		if r.Findings[i].Severity != r.Findings[j].Severity {
			return r.Findings[i].Severity > r.Findings[j].Severity
		}
		return r.Findings[i].Line < r.Findings[j].Line
	})
	return r
}

// analyzeSubdag applies the rule that makes this package usable on real
// workflows: a SUBDAG file absent at submit time is normal, because the
// idiom is for an earlier node to generate it. The useful question is not
// "is it here" but "does anything produce it, and does that happen first".
func analyzeSubdag(r *Report, d *DAG, n *Node, have, referenced map[string]bool) {
	if n.Descriptor == "" || isURL(n.Descriptor) || strings.HasPrefix(n.Descriptor, "/") {
		return
	}
	referenced[n.Descriptor] = true
	if have[n.Descriptor] {
		return
	}
	r.Deferred = append(r.Deferred, n.Descriptor)

	// Can anything plausibly produce it? We can only attribute a producer
	// when a node's submit description names the file in
	// transfer_output_files, which is often unset (the default brings
	// back everything new in the sandbox). So an unattributed file is the
	// common case and must not be reported as an error.
	producers := producersOf(d, n.Descriptor)
	if len(producers) == 0 {
		r.Findings = append(r.Findings, Finding{
			Severity: Advisory,
			Line:     n.Line,
			Message: fmt.Sprintf("SUBDAG %s reads %s, which is not supplied. That is normal when an "+
				"earlier node generates it -- DAGMan reads a sub-DAG only when the node becomes ready. "+
				"No node declares it in transfer_output_files, so this could not be verified: make sure "+
				"some ancestor of %s produces it.", n.Name, n.Descriptor, n.Name),
		})
		return
	}
	// A producer we can name lets us check the ordering, which is the
	// finding worth having: without an edge the sub-DAG node can become
	// ready before the file exists, and it fails nondeterministically.
	var unordered []string
	for _, p := range producers {
		if !reachable(d, p, n.Name) {
			unordered = append(unordered, p)
		}
	}
	if len(unordered) > 0 {
		r.Findings = append(r.Findings, Finding{
			Severity: Warning,
			Line:     n.Line,
			Message: fmt.Sprintf("SUBDAG %s reads %s, which node %s produces, but %s is not an ancestor of %s. "+
				"Nothing orders them, so %s may become ready before the file exists. "+
				"Add PARENT %s CHILD %s.",
				n.Name, n.Descriptor, strings.Join(unordered, ", "), strings.Join(unordered, ", "),
				n.Name, n.Name, unordered[0], n.Name),
		})
	}
}

// analyzeJobNode resolves a node's submit description and pulls the files
// the node itself will need. Node jobs run with Iwd set to the DAG's
// spool directory, so THEIR inputs have to be staged with the DAG -- the
// step most easily forgotten, and the one that fails at run time rather
// than at submit time.
func analyzeJobNode(d *DAG, n *Node, in Input, need func(string, Severity, string, int)) {

	body := n.InlineBody
	if !n.Inline {
		if desc, ok := d.Descriptions[strings.ToLower(n.Descriptor)]; ok {
			body = desc.Body
		} else {
			need(n.Descriptor, Warning,
				fmt.Sprintf("node %s names it as its submit description", n.Name), n.Line)
			body = in.Files[n.Descriptor]
		}
	}
	if body == "" {
		return
	}
	for _, f := range submitInputFiles(body) {
		need(f, Warning, fmt.Sprintf("node %s transfers it as input", n.Name), n.Line)
	}
}

// checkGraph reports edges naming nodes that do not exist, and cycles.
func checkGraph(r *Report, d *DAG) {
	for _, e := range d.Edges {
		if _, ok := d.NodeByName(e.Parent); !ok {
			r.Findings = append(r.Findings, Finding{Severity: Fatal, Line: e.Line,
				Message: fmt.Sprintf("PARENT %s names a node that is not declared", e.Parent)})
		}
		if _, ok := d.NodeByName(e.Child); !ok {
			r.Findings = append(r.Findings, Finding{Severity: Fatal, Line: e.Line,
				Message: fmt.Sprintf("CHILD %s names a node that is not declared", e.Child)})
		}
	}
	for _, s := range d.Scripts {
		if _, ok := d.NodeByName(s.Node); !ok {
			r.Findings = append(r.Findings, Finding{Severity: Warning, Line: s.Line,
				Message: fmt.Sprintf("SCRIPT %s names node %s, which is not declared", s.When, s.Node)})
		}
	}
	for name := range d.Vars {
		if _, ok := d.NodeByName(name); !ok {
			r.Findings = append(r.Findings, Finding{Severity: Warning,
				Message: fmt.Sprintf("VARS names node %s, which is not declared", name)})
		}
	}
	if cycle := findCycle(d); len(cycle) > 0 {
		r.Findings = append(r.Findings, Finding{Severity: Fatal,
			Message: fmt.Sprintf("the graph has a cycle: %s", strings.Join(cycle, " -> "))})
	}
}

// checkCollisions catches two distinct paths that land on the same name
// in the spool directory. The schedd rewrites a spooled sandbox to
// basenames in one flat directory, so these clobber each other with no
// diagnostic from either DAGMan or the schedd.
func checkCollisions(r *Report, d *DAG, in Input) {
	byBase := map[string]map[string]bool{}
	note := func(p string) {
		if p == "" || isURL(p) || !strings.Contains(p, "/") {
			return
		}
		b := path.Base(p)
		if byBase[b] == nil {
			byBase[b] = map[string]bool{}
		}
		byBase[b][p] = true
	}
	for i := range d.Nodes {
		body := d.Nodes[i].InlineBody
		if !d.Nodes[i].Inline {
			if desc, ok := d.Descriptions[strings.ToLower(d.Nodes[i].Descriptor)]; ok {
				body = desc.Body
			} else {
				body = in.Files[d.Nodes[i].Descriptor]
			}
		}
		for _, f := range submitInputFiles(body) {
			note(f)
		}
	}
	for base, paths := range byBase {
		if len(paths) < 2 {
			continue
		}
		var list []string
		for p := range paths {
			list = append(list, p)
		}
		sort.Strings(list)
		r.Findings = append(r.Findings, Finding{Severity: Fatal,
			Message: fmt.Sprintf("%s and %s both become %q in the spool directory, which flattens to "+
				"basenames; one would silently overwrite the other. Give them distinct names.",
				list[0], list[1], base)})
	}
}

// buildRequired is the DAGMan job's transfer_input_files: the DAG itself,
// everything supplied with it, and every name promised for later upload.
// Files referenced by the DAG but neither supplied nor promised are left
// out on purpose -- naming a file that does not exist makes the spool
// transfer fail outright, which is worse than the run-time error the
// caller has already been warned about.
func buildRequired(in Input) []string {
	set := map[string]bool{in.DagName: true}
	for name := range in.Files {
		set[name] = true
	}
	for _, name := range in.Declared {
		set[name] = true
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// producersOf finds nodes whose submit description names p in
// transfer_output_files.
func producersOf(d *DAG, p string) []string {
	var out []string
	for i := range d.Nodes {
		body := d.Nodes[i].InlineBody
		if !d.Nodes[i].Inline {
			if desc, ok := d.Descriptions[strings.ToLower(d.Nodes[i].Descriptor)]; ok {
				body = desc.Body
			}
		}
		for _, f := range submitValues(body, "transfer_output_files") {
			if f == p {
				out = append(out, d.Nodes[i].Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// reachable reports whether there is a directed path from -> to.
func reachable(d *DAG, from, to string) bool {
	adj := map[string][]string{}
	for _, e := range d.Edges {
		adj[strings.ToLower(e.Parent)] = append(adj[strings.ToLower(e.Parent)], strings.ToLower(e.Child))
	}
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(n string) bool {
		if n == strings.ToLower(to) {
			return true
		}
		if seen[n] {
			return false
		}
		seen[n] = true
		for _, c := range adj[n] {
			if walk(c) {
				return true
			}
		}
		return false
	}
	return walk(strings.ToLower(from))
}

// findCycle returns one cycle, as node names, or nil.
func findCycle(d *DAG) []string {
	adj := map[string][]string{}
	for _, e := range d.Edges {
		adj[strings.ToLower(e.Parent)] = append(adj[strings.ToLower(e.Parent)], strings.ToLower(e.Child))
	}
	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := map[string]int{}
	var stack, cycle []string
	var walk func(string) bool
	walk = func(n string) bool {
		color[n] = grey
		stack = append(stack, n)
		for _, c := range adj[n] {
			switch color[c] {
			case grey:
				// Trim the stack to the start of the cycle.
				for i, s := range stack {
					if s == c {
						cycle = append(append([]string{}, stack[i:]...), c)
						return true
					}
				}
				cycle = append(append([]string{}, stack...), c)
				return true
			case white:
				if walk(c) {
					return true
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[n] = black
		return false
	}
	for i := range d.Nodes {
		n := strings.ToLower(d.Nodes[i].Name)
		if color[n] == white {
			stack = stack[:0]
			if walk(n) {
				return cycle
			}
		}
	}
	return nil
}

func isURL(p string) bool {
	i := strings.Index(p, "://")
	return i > 0 && !strings.ContainsAny(p[:i], "/ \t")
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
