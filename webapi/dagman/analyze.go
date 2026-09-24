package dagman

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Severity separates "this DAG cannot start" from "this may be fine".
//
// The split is the whole value of the analysis. A DAG that discovers its
// own shape as it runs -- the SUBDAG idiom, and the submit file an
// earlier node writes -- legitimately references files that do not exist
// yet, so a check that treats every absent file as an error would fire
// hardest on the most interesting workflows.
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
	// Source is the INCLUDE'd or SPLICE'd file Line belongs to, empty for
	// the top-level DAG.
	Source string
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
	// Deferred are files the DAG reads only once it is running -- a
	// sub-DAG description, a node's submit file, or one node's input that
	// an earlier node produces -- that are not staged now. These are
	// expected to appear during the run.
	Deferred []string
	// JobAttrs are the DAG's SET_JOB_ATTR commands, in order, with the
	// ones this tool must own already removed (see ReservedJobAttr): a
	// caller hands these straight to SubmitOptions rather than parsing
	// the DAG a second time.
	JobAttrs []JobAttr
	// EnvSet is the DAG's ENV SET pairs, flattened. Later assignments of
	// the same variable win, as they do in the environment string
	// condor_submit_dag builds.
	EnvSet map[string]string
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

// add records a finding, naming the included file when the line number
// belongs to one rather than to the DAG the caller wrote.
func (r *Report) add(sev Severity, line int, source, msg string) {
	if source != "" {
		msg = fmt.Sprintf("%s (line %d of %s)", msg, line, source)
	}
	r.Findings = append(r.Findings, Finding{Severity: sev, Line: line, Source: source, Message: msg})
}

// deferFile records a file that will only exist once the run produces it.
func (r *Report) deferFile(p string) {
	for _, existing := range r.Deferred {
		if existing == p {
			return
		}
	}
	r.Deferred = append(r.Deferred, p)
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

// rescueName matches the rescue DAGs DAGMan writes and a caller may hand
// straight back to resubmit a partly-finished workflow. Nothing in the
// DAG text references one by name, so it must not be called unused.
var rescueName = regexp.MustCompile(`\.rescue[0-9]*`)

// analysis is the state the per-node checks share. It exists so the three
// places that resolve a node's body, and the two that defer a file, agree
// with each other -- they used to disagree, which is how a node could be
// both "unreferenced" and "required".
type analysis struct {
	r  *Report
	d  *DAG
	in Input
	// have is every name that will be in the spool allow-set: supplied
	// now, or promised for later.
	have map[string]bool
	// referenced is every name something in the DAG asked for.
	referenced map[string]bool
	// blind collects the reasons this analysis cannot see every
	// reference, which is what makes "supplied but unreferenced" a guess
	// rather than a finding.
	deferredDescs int
	deferredDags  int
	macroRefs     bool
}

// Analyze cross-checks a parsed DAG against the files supplied with it.
//
// It answers three questions the caller cannot answer for itself:
// what must be staged and is not, what was staged and is used by nothing,
// and which of the gaps are expected to close on their own while the
// workflow runs.
func Analyze(in Input) *Report {
	r := &Report{}
	d := parseText(in.Dag, &resolver{
		lookup: func(name string) (string, bool) {
			s, ok := in.Files[name]
			return s, ok
		},
		stack: []string{in.DagName},
	})

	a := &analysis{r: r, d: d, in: in, have: map[string]bool{}, referenced: map[string]bool{}}
	for name := range in.Files {
		a.have[name] = true
	}
	for _, name := range in.Declared {
		a.have[name] = true
	}

	need := func(p string, sev Severity, what string, line int, source string) {
		if p == "" || isURL(p) || strings.HasPrefix(p, "/") {
			// A URL is fetched by whoever needs it; an absolute path
			// refers to the access point's filesystem, which we cannot
			// see from here. Neither is ours to stage.
			return
		}
		a.referenced[p] = true
		if a.have[p] {
			return
		}
		r.add(sev, line, source, fmt.Sprintf("%s is not among the supplied files (%s)", p, what))
	}

	if in.DagName == "" {
		r.add(Fatal, 0, "", "the workflow has no file name for its DAG description, so nothing can be "+
			"written to the spool; give the DAG a file name such as workflow.dag")
	}

	for _, ref := range d.Includes {
		need(ref.Path, Fatal, "INCLUDE is read when DAGMan parses the DAG, so the workflow cannot start without it", ref.Line, ref.Source)
	}
	for _, ref := range d.Configs {
		need(ref.Path, Fatal, "CONFIG is read when DAGMan parses the DAG", ref.Line, ref.Source)
	}
	for _, ref := range d.DotIncludes {
		need(ref.Path, Warning, "DOT ... INCLUDE names a header file DAGMan reads to write the dot output", ref.Line, ref.Source)
	}
	for _, s := range d.Scripts {
		need(s.Executable, Warning,
			fmt.Sprintf("SCRIPT %s for node %s runs on the access point", s.When, s.Node), s.Line, s.Source)
	}

	for i := range d.Nodes {
		n := &d.Nodes[i]
		switch n.Type {
		case NodeSplice:
			need(n.Descriptor, Fatal,
				fmt.Sprintf("SPLICE %s is inlined when DAGMan parses the DAG, so it must be supplied now", n.Name), n.Line, n.Source)
		case NodeSubdag:
			if analyzeDeferredFile(r, d, in, n.Name, n.Descriptor, "SUBDAG", a.have, a.referenced, n.Line, n.Source) {
				a.deferredDags++
			}
		default:
			a.analyzeJobNode(n)
		}
		if n.Dir != "" {
			r.add(Fatal, n.Line, n.Source,
				fmt.Sprintf("node %s uses DIR %q, which a spooled workflow cannot honor: "+
					"the schedd flattens a spooled sandbox to basenames in one directory. "+
					"Remove the DIR and give the files distinct names.", n.Name, n.Dir))
		}
	}

	if len(d.Nodes) == 0 && !d.Incomplete {
		r.add(Fatal, 0, "", `the DAG declares no nodes; nothing would run. If you wrote the workflow on `+
			`one line, note that DAG syntax is line-oriented: use real newlines, not \n.`)
	}

	collectJobAttrs(r, d)
	collectEnv(r, d)
	checkDuplicateNodes(r, d)
	checkGraph(r, d)
	checkCollisions(r, d, in)
	a.checkUnreferenced()

	for _, e := range d.Errors {
		r.add(Warning, e.Line, e.Source, e.Why+": "+e.Text)
	}
	for _, e := range d.Fatals {
		r.add(Fatal, e.Line, e.Source, e.Why+": "+e.Text)
	}

	r.Staged = sortedKeys(in.Files)
	r.Required = buildRequired(in)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].Severity != r.Findings[j].Severity {
			return r.Findings[i].Severity > r.Findings[j].Severity
		}
		return r.Findings[i].Line < r.Findings[j].Line
	})
	return r
}

// checkUnreferenced reports files that were supplied and that nothing
// asked for. A spooled file no job declares is silently dropped, so a
// near-miss name is worth naming -- but only when the analysis can
// actually see every reference. When a submit description will be written
// during the run, or a file is named through a VARS macro, or a
// parse-time inclusion was not supplied, it cannot, and saying
// "misspelling" would be a guess dressed as a diagnosis.
func (a *analysis) checkUnreferenced() {
	outputs := map[string]bool{}
	for _, ref := range a.d.Outputs {
		outputs[ref.Path] = true
	}

	var blind []string
	if a.deferredDescs > 0 {
		blind = append(blind, fmt.Sprintf("%d submit descriptions are generated at run time", a.deferredDescs))
	}
	if a.deferredDags > 0 {
		blind = append(blind, fmt.Sprintf("%d sub-DAG descriptions are generated at run time", a.deferredDags))
	}
	if a.d.Incomplete {
		blind = append(blind, "an INCLUDE or SPLICE file was not supplied, so part of the DAG could not be read")
	}
	if a.macroRefs {
		blind = append(blind, "files referenced through VARS macros cannot be checked")
	}

	for _, name := range sortedKeys(a.in.Files) {
		if name == a.in.DagName || a.referenced[name] || outputs[name] || rescueName.MatchString(name) {
			continue
		}
		if len(blind) > 0 {
			a.r.add(Advisory, 0, "", fmt.Sprintf(
				"%s was supplied but nothing this analysis can read references it. That may well be "+
					"fine: %s. A spooled file that no job declares is silently dropped, so check that "+
					"whatever uses it names it.", name, strings.Join(blind, "; ")))
			continue
		}
		a.r.add(Advisory, 0, "", fmt.Sprintf(
			"%s was supplied but nothing in the DAG references it. A spooled file that no job "+
				"declares is silently dropped, so this is usually a misspelling of a name the DAG "+
				"does reference.", name))
	}
}

// analyzeDeferredFile applies the rule that makes this package usable on
// real workflows: a file DAGMan does not read until a node becomes ready
// is legitimately absent at submit time, because the idiom is for an
// earlier node to generate it. That covers a SUBDAG's .dag description
// and, just as much, a node's submit file -- writing or rewriting a
// submit file from an earlier node's output is standard practice.
//
// The useful question is therefore not "is it here" but "does anything
// produce it, and does that happen first". It returns whether the file
// was deferred.
func analyzeDeferredFile(r *Report, d *DAG, in Input, nodeName, filePath, kind string,
	have, referenced map[string]bool, line int, source string) bool {

	if filePath == "" || isURL(filePath) || strings.HasPrefix(filePath, "/") {
		return false
	}
	referenced[filePath] = true
	if have[filePath] {
		return false
	}
	r.deferFile(filePath)

	var reads, why string
	if kind == "SUBDAG" {
		reads = fmt.Sprintf("SUBDAG %s reads %s", nodeName, filePath)
		why = "DAGMan reads a sub-DAG description only when the node becomes ready"
	} else {
		reads = fmt.Sprintf("node %s uses %s as its submit description", nodeName, filePath)
		why = "DAGMan does not read a node's submit file until that node is submitted, so a submit " +
			"file generated during the run is expected and fully supported"
	}

	// Can anything plausibly produce it? We can only attribute a producer
	// when a node's submit description names the file in
	// transfer_output_files, which is often unset (the default brings
	// back everything new in the sandbox). So an unattributed file is the
	// common case and must not be reported as an error.
	producers := producersOf(d, in, filePath)
	if len(producers) == 0 {
		r.add(Advisory, line, source, fmt.Sprintf(
			"%s, which is not supplied. That is normal when an earlier node generates it: %s. "+
				"No node declares it in transfer_output_files, so this could not be verified: make "+
				"sure some ancestor of %s produces it.", reads, why, nodeName))
		return true
	}
	// A producer we can name lets us check the ordering, which is the
	// finding worth having: without an edge the node can become ready
	// before the file exists, and it fails nondeterministically.
	var unordered []string
	for _, p := range producers {
		if !reachable(d, p, nodeName) {
			unordered = append(unordered, p)
		}
	}
	if len(unordered) > 0 {
		list := strings.Join(unordered, ", ")
		r.add(Warning, line, source, fmt.Sprintf(
			"%s, which node %s produces, but %s is not an ancestor of %s. Nothing orders them, so "+
				"%s may become ready before the file exists. Add PARENT %s CHILD %s.",
			reads, list, list, nodeName, nodeName, unordered[0], nodeName))
	}
	return true
}

// bodyFor resolves a node's submit description the three ways DAGMan
// does: written inline, named by a SUBMIT-DESCRIPTION block, or held in a
// file the caller supplied. resolved is false when the text is not in
// hand -- which is not the same as the node being broken.
func bodyFor(d *DAG, n *Node, in Input) (body string, resolved bool) {
	if n.Inline {
		return n.InlineBody, true
	}
	if desc, ok := d.Descriptions[strings.ToLower(n.Descriptor)]; ok {
		return desc.Body, true
	}
	if body, ok := in.Files[n.Descriptor]; ok {
		return body, true
	}
	return "", false
}

// analyzeJobNode resolves a node's submit description and pulls the files
// the node itself will need. Node jobs run with Iwd set to the DAG's
// spool directory, so THEIR inputs have to be staged with the DAG -- the
// step most easily forgotten, and the one that fails at run time rather
// than at submit time.
func (a *analysis) analyzeJobNode(n *Node) {
	body, resolved := bodyFor(a.d, n, a.in)
	if !resolved {
		if a.have[n.Descriptor] {
			// Promised for later upload. The name is in the allow-set, so
			// the reference is satisfied, but the text is not here and its
			// own inputs cannot be checked.
			a.referenced[n.Descriptor] = true
			a.r.add(Advisory, n.Line, n.Source, fmt.Sprintf(
				"node %s takes its submit description from %s, which you declared rather than supplied, "+
					"so the files that description names cannot be checked here: every file it "+
					"references must be declared or supplied now too.", n.Name, n.Descriptor))
			return
		}
		if analyzeDeferredFile(a.r, a.d, a.in, n.Name, n.Descriptor, "JOB",
			a.have, a.referenced, n.Line, n.Source) {
			a.deferredDescs++
		}
		return
	}
	if !n.Inline {
		// A descriptor can be both a SUBMIT-DESCRIPTION name and a file
		// the caller supplied. Resolving it as the former does not make
		// the latter unused.
		a.referenced[n.Descriptor] = true
	}
	if strings.TrimSpace(body) == "" {
		return
	}
	expand := nodeExpander(a.d, n)
	if submitHasMacroInput(body, expand) {
		a.macroRefs = true
	}
	if dir := submitString(body, "initialdir", expand); dir != "" && !strings.Contains(dir, "$(") {
		a.r.add(Fatal, n.Line, n.Source, fmt.Sprintf(
			"node %s sets initialdir %q, which a spooled workflow cannot honor: the schedd flattens a "+
				"spooled sandbox to basenames in one directory, so a relative initialdir names a "+
				"subdirectory that does not exist. Remove the initialdir and give the files distinct names.",
			n.Name, dir))
	}
	for _, dir := range submitDirTransfers(body, expand) {
		a.r.add(Warning, n.Line, n.Source, fmt.Sprintf(
			"node %s transfers %q, which asks for a directory's contents: the schedd flattens a "+
				"spooled sandbox to basenames in one directory, so a directory transfer cannot "+
				"survive the rewrite. Name the files individually.", n.Name, dir))
	}
	for _, f := range submitInputFiles(body, expand) {
		a.needInput(n, f)
	}
}

// needInput cross-checks one file a node transfers in.
//
// A file that was not supplied is not necessarily missing. The commonest
// workflow shape there is -- fan out, then gather -- has each producer
// write a file that a later node reads, and NONE of those exist at submit
// time. So the question is the same one analyzeDeferredFile asks of a
// generated submit file: does something produce it, and does that happen
// first. Only when nothing produces it is "you did not supply this" the
// right answer.
func (a *analysis) needInput(n *Node, p string) {
	if p == "" || isURL(p) || strings.HasPrefix(p, "/") {
		return
	}
	a.referenced[p] = true
	if a.have[p] {
		return
	}
	var producers []string
	for _, prod := range producersOf(a.d, a.in, p) {
		if !strings.EqualFold(prod, n.Name) {
			producers = append(producers, prod)
		}
	}
	if len(producers) == 0 {
		a.r.add(Warning, n.Line, n.Source, fmt.Sprintf(
			"%s is not among the supplied files (node %s transfers it as input)", p, n.Name))
		return
	}
	a.r.deferFile(p)
	for _, prod := range producers {
		if reachable(a.d, prod, n.Name) {
			return
		}
	}
	list := strings.Join(producers, ", ")
	a.r.add(Warning, n.Line, n.Source, fmt.Sprintf(
		"node %s transfers %s as input, which node %s produces, but %s is not an ancestor of %s. "+
			"Nothing orders them, so %s may become ready before the file exists. Add PARENT %s CHILD %s.",
		n.Name, p, list, list, n.Name, n.Name, producers[0], n.Name))
}

// nodeExpander resolves a submit value the way DAGMan will for one node:
// its VARS and $(JOB) substituted, everything else left standing for the
// reader to skip.
func nodeExpander(d *DAG, n *Node) macroExpander {
	return func(v string) string {
		out, _ := expandNodeMacros(v, n, d)
		return out
	}
}

// collectJobAttrs carries the DAG's SET_JOB_ATTR commands onto the
// report, refusing the handful this tool must own.
//
// The guard exists because the manager job's submit file is not the
// caller's to write: OtherJobRemoveRequirements is what makes removing
// the workflow remove its node jobs, and IsDaemonCore is what gets
// DAGMan a command socket the schedd agrees it has. A DAG that
// overwrites either produces a workflow that looks submitted and
// misbehaves much later, so those are reported and dropped rather than
// emitted. JobBatchName is deliberately NOT reserved: condor_submit_dag
// lets a user set it (-batch-name), and a batch name that the DAG and
// the tool disagree about costs nothing but a label.
func collectJobAttrs(r *Report, d *DAG) {
	for _, a := range d.JobAttrs {
		if ReservedJobAttr(a.Name) {
			r.add(Warning, a.Line, a.Source, fmt.Sprintf(
				"SET_JOB_ATTR %s is ignored: %s is set by this server on the DAGMan manager job, and "+
					"overriding it would break %s. Everything else SET_JOB_ATTR sets is honoured.",
				a.Name, a.Name, reservedJobAttrReason(a.Name)))
			continue
		}
		r.JobAttrs = append(r.JobAttrs, a)
	}
}

// collectEnv flattens ENV SET and reports ENV GET.
//
// ENV GET is the one DAG command this path cannot honour at all. It
// copies named variables out of the environment of the process that
// submits the DAG -- condor_submit_dag, running as the user on the
// access point. Here that process is this server, in a container
// somewhere else, whose environment has nothing to do with the user's.
// Silently dropping it would give DAGMan a manager job missing exactly
// the variables the workflow was written to depend on.
func collectEnv(r *Report, d *DAG) {
	for _, g := range d.EnvGet {
		r.add(Warning, g.Line, g.Source, fmt.Sprintf(
			"ENV GET %s cannot be honoured: it copies variables from the environment of the process "+
				"that submits the DAG, and this server's environment is not the access point's. "+
				"Set them with ENV SET instead.", strings.Join(g.Names, " ")))
	}
	if len(d.EnvSet) == 0 {
		return
	}
	r.EnvSet = make(map[string]string, len(d.EnvSet))
	for _, e := range d.EnvSet {
		r.EnvSet[e.Name] = e.Value
	}
}

// checkDuplicateNodes catches the same node name declared twice, which
// DAGMan refuses outright.
func checkDuplicateNodes(r *Report, d *DAG) {
	first := map[string]int{}
	for i := range d.Nodes {
		key := strings.ToLower(d.Nodes[i].Name)
		if prev, ok := first[key]; ok {
			r.add(Fatal, d.Nodes[i].Line, d.Nodes[i].Source, fmt.Sprintf(
				"node %s is declared twice (first at line %d); DAGMan refuses a DAG with duplicate node names",
				d.Nodes[i].Name, prev))
			continue
		}
		first[key] = d.Nodes[i].Line
	}
}

// checkGraph reports edges naming nodes that do not exist, and cycles.
//
// When a parse-time inclusion could not be read the node set in hand is
// admittedly partial, so "not declared" would be this package's ignorance
// rather than the DAG's mistake, and is not reported.
func checkGraph(r *Report, d *DAG) {
	if !d.Incomplete {
		for _, e := range d.Edges {
			if _, ok := d.NodeByName(e.Parent); !ok {
				r.add(Fatal, e.Line, e.Source, fmt.Sprintf("PARENT %s names a node that is not declared", e.Parent))
			}
			if _, ok := d.NodeByName(e.Child); !ok {
				r.add(Fatal, e.Line, e.Source, fmt.Sprintf("CHILD %s names a node that is not declared", e.Child))
			}
		}
		for _, s := range d.Scripts {
			if _, ok := d.NodeByName(s.Node); !ok && !isAllNodes(s.Node) {
				r.add(Warning, s.Line, s.Source,
					fmt.Sprintf("SCRIPT %s names node %s, which is not declared", s.When, s.Node))
			}
		}
		for _, key := range sortedVarNodes(d) {
			if _, ok := d.NodeByName(key); ok || isAllNodes(key) {
				continue
			}
			name := d.VarNames[key]
			if name == "" {
				name = key
			}
			r.add(Warning, 0, "", fmt.Sprintf("VARS names node %s, which is not declared", name))
		}
	}
	if cycle := findCycle(d); len(cycle) > 0 {
		r.add(Fatal, 0, "", fmt.Sprintf("the graph has a cycle: %s", strings.Join(cycle, " -> ")))
	}
}

func sortedVarNodes(d *DAG) []string {
	out := make([]string, 0, len(d.Vars))
	for k := range d.Vars {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkCollisions catches two distinct paths that land on the same name
// in the spool directory. The schedd rewrites a spooled sandbox to
// basenames in one flat directory, so these clobber each other with no
// diagnostic from either DAGMan or the schedd -- and a bare name collides
// with a subdirectory path just as surely as two subdirectory paths do.
func checkCollisions(r *Report, d *DAG, in Input) {
	byBase := map[string]map[string]bool{}
	note := func(p string) {
		if p == "" || isURL(p) || strings.HasPrefix(p, "/") {
			return
		}
		b := path.Base(p)
		if byBase[b] == nil {
			byBase[b] = map[string]bool{}
		}
		byBase[b][p] = true
	}
	for name := range in.Files {
		note(name)
	}
	for _, s := range d.Scripts {
		note(s.Executable)
	}
	for _, refs := range [][]FileRef{d.Includes, d.Configs, d.DotIncludes} {
		for _, ref := range refs {
			note(ref.Path)
		}
	}
	for i := range d.Nodes {
		note(d.Nodes[i].Descriptor)
		body, ok := bodyFor(d, &d.Nodes[i], in)
		if !ok {
			continue
		}
		for _, f := range submitInputFiles(body, nodeExpander(d, &d.Nodes[i])) {
			note(f)
		}
	}
	bases := make([]string, 0, len(byBase))
	for b := range byBase {
		bases = append(bases, b)
	}
	sort.Strings(bases)
	for _, base := range bases {
		paths := byBase[base]
		if len(paths) < 2 {
			continue
		}
		list := make([]string, 0, len(paths))
		for p := range paths {
			list = append(list, p)
		}
		sort.Strings(list)
		r.add(Fatal, 0, "", fmt.Sprintf(
			"%s and %s both become %q in the spool directory, which flattens to basenames; one would "+
				"silently overwrite the other. Give them distinct names.", list[0], list[1], base))
	}
}

// buildRequired is the DAGMan job's transfer_input_files: the DAG itself,
// everything supplied with it, and every name promised for later upload.
// Files referenced by the DAG but neither supplied nor promised are left
// out on purpose -- naming a file that does not exist makes the spool
// transfer fail outright, which is worse than the run-time error the
// caller has already been warned about.
func buildRequired(in Input) []string {
	set := map[string]bool{}
	if in.DagName != "" {
		set[in.DagName] = true
	}
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
// transfer_output_files. It resolves the description exactly as
// analyzeJobNode does -- including from a supplied file, which it used
// not to, so a producer written in a .sub file went unseen.
func producersOf(d *DAG, in Input, p string) []string {
	var out []string
	for i := range d.Nodes {
		body, ok := bodyFor(d, &d.Nodes[i], in)
		if !ok {
			continue
		}
		for _, f := range submitValues(body, "transfer_output_files", nodeExpander(d, &d.Nodes[i])) {
			if f == p {
				out = append(out, d.Nodes[i].Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// reachable reports whether there is a directed path from -> to. A node
// reaches itself only through a real cycle, so the target is checked
// after a step, never before one.
func reachable(d *DAG, from, to string) bool {
	adj := map[string][]string{}
	for _, e := range d.Edges {
		p := strings.ToLower(e.Parent)
		adj[p] = append(adj[p], strings.ToLower(e.Child))
	}
	target := strings.ToLower(to)
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(n string) bool {
		if seen[n] {
			return false
		}
		seen[n] = true
		for _, c := range adj[n] {
			if c == target || walk(c) {
				return true
			}
		}
		return false
	}
	return walk(strings.ToLower(from))
}

// declaredNames maps a folded node name back to the spelling the DAG
// used. The graph is walked folded, because DAGMan matches node names
// case-insensitively; a message built from the folded form tells an
// author about nodes "a -> b -> c" they never wrote. Edges are a fallback
// for a name that appears only in a PARENT/CHILD line.
func declaredNames(d *DAG) map[string]string {
	out := make(map[string]string, len(d.Nodes))
	keep := func(name string) {
		if key := strings.ToLower(name); out[key] == "" {
			out[key] = name
		}
	}
	for i := range d.Nodes {
		keep(d.Nodes[i].Name)
	}
	for _, e := range d.Edges {
		keep(e.Parent)
		keep(e.Child)
	}
	return out
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
				return asDeclared(d, cycle)
			}
		}
	}
	return nil
}

// asDeclared respells a walked path with the names the DAG used.
func asDeclared(d *DAG, path []string) []string {
	names := declaredNames(d)
	out := make([]string, 0, len(path))
	for _, p := range path {
		if name := names[p]; name != "" {
			out = append(out, name)
			continue
		}
		out = append(out, p)
	}
	return out
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
