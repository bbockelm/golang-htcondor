package dagman

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/bbockelm/golang-htcondor/webapi/submitlint"
	"github.com/bbockelm/golang-htcondor/webapi/submitpolicy"
)

// Preparing a workflow for submission: everything that happens between
// "a caller handed us a DAG" and "the schedd has a submit file and a
// sandbox", with nothing in it about HOW the caller handed it over.
//
// This used to live in the MCP server, because submit_dag was the only
// surface that could submit a workflow. It is here now because the REST
// API has the same endpoint, and the rules below are not a matter of
// taste -- a workflow that reached the queue with the wrong file mode,
// an unlinted node description, or site policy missing from its inline
// blocks is broken in ways that surface hours later as a held node job
// with nothing to connect it to the submission. Two implementations of
// that would be two sets of those bugs.
//
// The mechanism is worth stating once, because nothing about it is
// obvious from either surface. SubmitRemote commits the job HELD with
// HoldReasonCode 16, which is what makes the schedd rewrite the job ad
// for spooling: Iwd becomes the job's SPOOL directory and the file lists
// collapse to basenames. condor_dagman itself is exempt from that
// rewrite because transfer_executable is false, so it keeps its absolute
// path while the workflow lands in the directory it will run in. DAGMan
// then finds the .dag in its working directory, submits node jobs from
// there, and those node jobs inherit the same Iwd -- which is why a
// node's own input files have to be staged with the DAG rather than with
// the node.
//
// The second thing worth stating: a file that is not in the job ad's
// TransferInput is SKIPPED at spool time, not rejected. So the input
// list is computed from the parsed DAG (Analyze) rather than asked for,
// and a file the caller sends that the DAG never mentions is reported
// back as a probable typo instead of vanishing.
//
// The third: the spool is written ONCE. SpoolJobFilesFromFS stats every
// name in TransferInput and fails on the first one missing, and the
// transfer's completion is what releases the hold -- after which the
// schedd refuses a second spool for the same job. There is therefore no
// "upload the big file afterwards" path for a workflow. Everything the
// workflow will ever need has to be in the one Submission below.

// DefaultMaxSubmissionBytes caps the bytes a submission may carry
// INLINE: the DAG description plus the Files map.
//
// It bounds what has to be held in memory and parsed, not what may be
// spooled: an Opaque upload is streamed and is not counted here. A
// workflow's own description -- the graph, the node submit descriptions,
// the PRE/POST scripts -- is kilobytes, and anything approaching a
// megabyte of it is data wearing a text file's clothes.
const DefaultMaxSubmissionBytes = 1 << 20

// OpaqueFile is one upload supplied with a workflow whose contents this
// package never reads: bulk data, staged by name and streamed straight
// through to the schedd.
//
// Open may be called more than once -- the spool path stats a file and
// then reads it -- and must return a fresh reader each time.
type OpaqueFile struct {
	// Name is the basename it is staged under.
	Name string
	// Size is what the spool transfer will declare. It must match what
	// Open yields: the schedd reads exactly this many bytes.
	Size int64
	// Mode, when non-zero, overrides what the DAG implies. A caller that
	// knows a file is an executable (because its upload said so) sets
	// 0o755; otherwise leave it zero and let the parse decide.
	Mode fs.FileMode
	// Open returns the bytes.
	Open func() (io.ReadCloser, error)
}

// Submission is one workflow exactly as a caller handed it over, plus
// what the access point says about itself. Nothing here is specific to
// REST or to MCP.
type Submission struct {
	// DagName is the file name the DAG description is written as in the
	// spool. Empty means "workflow.dag".
	DagName string
	// Dag is the DAG description text. Required.
	Dag string
	// Files are the other files supplied inline, by name: node submit
	// files, PRE/POST scripts, small inputs. Contents are read -- by the
	// analysis, by the lint, and by site policy.
	Files map[string]string
	// Opaque are uploads whose contents are not read. See OpaqueFile.
	Opaque []OpaqueFile

	// BatchName, MaxIdle, MaxJobs, MaxPre, MaxPost and Append shape the
	// DAGMan manager job; see SubmitOptions.
	BatchName                         string
	MaxIdle, MaxJobs, MaxPre, MaxPost int
	Append                            string

	// Instrument appends DOT and NODE_STATUS_FILE commands so the
	// workflow's structure and per-node progress can be read while it
	// runs. It is a plain bool rather than a *bool because both callers
	// default it to true before getting here: the flag exists only to
	// turn instrumentation OFF, and the reason it can be wanted off is
	// that DAGMan ABORTS a DAG whose node status file cannot be written
	// (Dag::DumpNodeStatus calls check_warning_strictness(DAG_STRICT_1),
	// dag.cpp:2435-2441, and DAGMAN_USE_STRICT defaults to 1). On a full
	// or read-only spool, instrumentation turns a degraded run into a
	// dead one.
	Instrument bool

	// MaxBytes caps the inline bytes. Zero means
	// DefaultMaxSubmissionBytes.
	MaxBytes int

	// DagmanPath, Layout and ExtraEnv describe the access point's DAGMan
	// installation; see SubmitOptions and Layout.
	DagmanPath string
	Layout     Layout
	ExtraEnv   map[string]string

	// Policy is the site's submit policy. It reaches the node jobs ONLY
	// here: DAGMan submits those itself, on the access point, long after
	// the call that prepared this returns, so the descriptions in hand
	// now are the last chance.
	Policy submitpolicy.Policy
}

// Prepared is everything the schedd needs, and everything the caller
// should tell whoever asked.
type Prepared struct {
	// DagName is the name the DAG was staged under, after defaulting.
	DagName string
	// SubmitFile is the DAGMan manager job's submit file, with site
	// policy already applied.
	SubmitFile string
	// Report is the analysis of the DAG AS THE CALLER WROTE IT. Site
	// policy is spliced into the staged text, not into this, so every
	// finding still points at a line the caller can see.
	//
	// Report.Fatal() is deliberately NOT an error from Prepare: a dry
	// run has to report every fatal finding, and answering with one
	// error hides the other four. A caller that is really submitting
	// checks it and refuses.
	Report *Report
	// Notes are the findings plus the per-node submit lint, rendered as
	// text, in the order a caller should show them.
	Notes []string
	// Instrumentation says what was appended, or why nothing was.
	Instrumentation Instrumentation

	// staged is the sandbox: the instrumented DAG, the policy-rewritten
	// inline files, and the opaque uploads, each with the mode it has to
	// land with.
	staged map[string]stagedFile
}

// stagedFile is one entry of the sandbox. Exactly one of data and open
// is set: inline files are already in memory, and an opaque upload is
// streamed so that a multi-gigabyte shared input never has to be.
type stagedFile struct {
	data []byte
	open func() (io.ReadCloser, error)
	size int64
	mode fs.FileMode
}

// Names is the sandbox's contents, sorted.
func (p *Prepared) Names() []string {
	out := make([]string, 0, len(p.staged))
	for name := range p.staged {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// FS is the sandbox as an fs.FS, ready for Schedd.SpoolJobFilesFromFS.
func (p *Prepared) FS() fs.FS {
	// Inline files go through fstest.MapFS, which is the shape the
	// spool path has always been handed. An opaque upload cannot: MapFS
	// holds bytes, and the whole point of Opaque is that these bytes are
	// never all in memory at once. stageFS below serves both.
	return &stageFS{files: p.staged}
}

// stageFS is a flat, read-only fs.FS over a prepared sandbox.
//
// Flat is not a simplification here, it is the constraint: the schedd
// collapses a spooled sandbox to basenames in one directory, so a
// sandbox with a subdirectory in it is a sandbox that will not survive
// the trip, and Prepare refuses one long before this.
type stageFS struct{ files map[string]stagedFile }

func (s *stageFS) Open(name string) (fs.File, error) {
	f, ok := s.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if f.open == nil {
		return &stageFile{
			name: name,
			rc:   io.NopCloser(bytes.NewReader(f.data)),
			size: int64(len(f.data)),
			mode: f.mode,
		}, nil
	}
	rc, err := f.open()
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &stageFile{name: name, rc: rc, size: f.size, mode: f.mode}, nil
}

// Stat answers without opening, so the spool path's stat-then-read does
// not open a large upload twice.
func (s *stageFS) Stat(name string) (fs.FileInfo, error) {
	f, ok := s.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	size := f.size
	if f.open == nil {
		size = int64(len(f.data))
	}
	return stageInfo{name: name, size: size, mode: f.mode}, nil
}

// stageFile is one opened opaque upload.
type stageFile struct {
	name string
	rc   io.ReadCloser
	size int64
	mode fs.FileMode
}

func (f *stageFile) Read(p []byte) (int, error) { return f.rc.Read(p) }
func (f *stageFile) Close() error               { return f.rc.Close() }
func (f *stageFile) Stat() (fs.FileInfo, error) {
	return stageInfo{name: f.name, size: f.size, mode: f.mode}, nil
}

type stageInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (i stageInfo) Name() string      { return i.name }
func (i stageInfo) Size() int64       { return i.size }
func (i stageInfo) Mode() fs.FileMode { return i.mode }
func (i stageInfo) IsDir() bool       { return false }
func (i stageInfo) Sys() any          { return nil }

// ModTime is the zero time. A spooled sandbox is built here and now, and
// the schedd records its own catalog at stage-in; there is no earlier
// modification time to claim.
func (i stageInfo) ModTime() time.Time { return time.Time{} }

// Prepare turns a Submission into everything the schedd needs.
//
// Every error it returns is about what the CALLER sent, and is theirs to
// fix: a name the spool cannot carry, more inline bytes than this path
// is for, a node description that sets an attribute site policy owns. A
// workflow that is merely WRONG -- a cycle, a PARENT naming a node that
// does not exist -- is not an error here: it comes back in
// Prepared.Report, so a dry run can report all of it at once.
func Prepare(s Submission) (*Prepared, error) {
	if strings.TrimSpace(s.Dag) == "" {
		return nil, fmt.Errorf("the DAG description is empty; the workflow's own text is what this submits")
	}
	dagName := strings.TrimSpace(s.DagName)
	if dagName == "" {
		dagName = "workflow.dag"
	}
	if err := CheckName(dagName, "dag_name"); err != nil {
		return nil, err
	}

	// The flat-sandbox rule, enforced on every name before anything is
	// parsed. A name with a directory in it does not fail at submit
	// time; it arrives flattened, which is how two files silently become
	// one.
	opaqueNames := make([]string, 0, len(s.Opaque))
	for _, o := range s.Opaque {
		opaqueNames = append(opaqueNames, o.Name)
	}
	for _, name := range append(sortedKeys(s.Files), opaqueNames...) {
		if err := CheckName(name, "file"); err != nil {
			return nil, err
		}
		if name == dagName {
			return nil, fmt.Errorf("file %q collides with the DAG's own name; "+
				"pass the DAG description as the dag field, not as a file", name)
		}
	}
	if dup := firstDuplicate(append(sortedKeys(s.Files), opaqueNames...)); dup != "" {
		return nil, fmt.Errorf("file %q was supplied twice; a spooled sandbox is one flat "+
			"directory, so one of them would silently overwrite the other", dup)
	}
	// A .sub file is a submit description, and site policy has to be
	// spliced into it (policyForStagedFile below). An opaque one cannot
	// be: nothing read it. Refusing is the only safe answer -- the
	// alternative is a node job that quietly escaped the site's
	// overrides.
	for _, o := range s.Opaque {
		if strings.HasSuffix(o.Name, ".sub") && !s.Policy.IsZero() {
			return nil, fmt.Errorf("%s is a node submit description but was not supplied as text, "+
				"so this access point's submit policy cannot be applied to it; send it as a text "+
				"file small enough to read", o.Name)
		}
	}
	if err := checkInlineSize(s); err != nil {
		return nil, err
	}

	// The analysis reads what the CALLER wrote. Site policy is spliced
	// into the text that gets staged (below), but a finding has to point
	// at a line the caller can see.
	report := Analyze(Input{
		DagName: dagName,
		Dag:     s.Dag,
		Files:   s.Files,
		Opaque:  opaqueNames,
		// Nothing can be added to a workflow's spool after submission,
		// so there is no set of names to promise for later.
		Declared: nil,
	})
	parsed := Parse(s.Dag)
	notes := append(FindingStrings(report), LintDescriptions(parsed, s.Files)...)

	submitFile, err := SubmitFile(SubmitOptions{
		DagName: dagName,
		// Explicit configuration wins; otherwise the schedd's own BIN
		// decides, and only then the package default.
		DagmanPath:  s.DagmanPath,
		BinDir:      s.Layout.BinDir,
		DisablePort: s.Layout.DisablePort,
		// Deliberately empty: -CsdVersion describes the condor_submit
		// that wrote the file, and no server here is one. DAGMan uses
		// its own version when the argument is absent, which is the only
		// version that is true of the access point.
		CondorVersion: "",
		ConfigFile:    SoleConfigFile(parsed),
		InputFiles:    report.Required,
		BatchName:     s.BatchName,
		MaxIdle:       s.MaxIdle,
		MaxJobs:       s.MaxJobs,
		MaxPre:        s.MaxPre,
		MaxPost:       s.MaxPost,
		// Straight from the analysis rather than from a second parse:
		// the report already dropped the attributes this path owns and
		// told the caller which ones those were, and re-deriving them
		// here would be a second answer to the same question.
		JobAttrs: report.JobAttrs,
		EnvSet:   report.EnvSet,
		ExtraEnv: s.ExtraEnv,
		Append:   s.Append,
	})
	if err != nil {
		return nil, err
	}
	applied, err := s.Policy.Apply(submitFile)
	if err != nil {
		return nil, fmt.Errorf("the DAGMan manager job: %w", err)
	}
	if err := CheckNodePolicy(s.Policy, parsed, s.Files); err != nil {
		return nil, err
	}

	out := &Prepared{DagName: dagName, SubmitFile: applied, Report: report, Notes: notes}

	// The staged DAG is instrumented: two commands appended so DAGMan
	// writes its own structure and per-node status into the spool, which
	// is the only way to read either back out of a spooled workflow (see
	// Instrument). The analysis above ran on the CALLER's text, so every
	// finding still points at a line they wrote.
	staged := PolicyForInlineDescriptions(s.Policy, s.Dag)
	if s.Instrument {
		staged, out.Instrumentation = Instrument(staged, dagName, s.Files)
	} else {
		out.Instrumentation.Skipped = "instrumentation was turned off: nothing was appended to the DAG, " +
			"so its structure and per-node status cannot be read while it runs."
	}
	if out.Instrumentation.Skipped != "" {
		out.Notes = append(out.Notes, out.Instrumentation.Skipped)
	}

	out.staged = map[string]stagedFile{
		dagName: {data: []byte(staged), mode: 0o644},
	}
	exec := ExecutableStagedNames(parsed, allNames(s))
	for name, body := range s.Files {
		data, err := PolicyForStagedFile(s.Policy, name, body)
		if err != nil {
			return nil, fmt.Errorf("file %q: %w", name, err)
		}
		out.staged[name] = stagedFile{data: []byte(data), mode: StagedMode(name, exec)}
	}
	for _, o := range s.Opaque {
		mode := o.Mode
		if mode == 0 {
			mode = StagedMode(o.Name, exec)
		}
		out.staged[o.Name] = stagedFile{open: o.Open, size: o.Size, mode: mode}
	}
	return out, nil
}

// allNames is every staged name, as the set ExecutableStagedNames needs
// to decide whether a name the DAG runs is one of ours. The values are
// empty for an opaque upload: only membership is ever asked.
func allNames(s Submission) map[string]string {
	out := make(map[string]string, len(s.Files)+len(s.Opaque))
	for name, body := range s.Files {
		out[name] = body
	}
	for _, o := range s.Opaque {
		if _, ok := out[o.Name]; !ok {
			out[o.Name] = ""
		}
	}
	return out
}

// firstDuplicate returns the first name that appears twice in a sorted
// list, or "".
func firstDuplicate(sorted []string) string {
	sort.Strings(sorted)
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return sorted[i]
		}
	}
	return ""
}

// checkInlineSize refuses a workflow whose inline bytes are past what
// this path is for.
//
// Opaque uploads are not counted: they are streamed, bounded by whatever
// the transport allows, and are exactly the thing this limit is meant to
// push callers towards. What is counted is the text that has to be held,
// parsed, linted and policy-rewritten.
func checkInlineSize(s Submission) error {
	limit := s.MaxBytes
	if limit <= 0 {
		limit = DefaultMaxSubmissionBytes
	}
	total := len(s.Dag)
	for _, body := range s.Files {
		total += len(body)
	}
	if total <= limit {
		return nil
	}
	return fmt.Errorf("this workflow is %d bytes of DAG + inline files, over the %d byte limit. "+
		"Only the workflow's own description belongs inline -- the DAG, the node submit "+
		"descriptions and the PRE/POST scripts. Bulk data goes either as a file upload in this "+
		"same request, or to the execute machines directly as an HTTP/HTTPS/OSDF URL in a node "+
		"job's transfer_input_files", total, limit)
}

// CheckName refuses a staged file name the spool or DAGMan's own lexer
// would not carry intact. what names the field, for the diagnostic.
//
// Two separate rules are at work:
//
//   - The spool directory is FLAT: the schedd collapses a spooled
//     sandbox to basenames in one directory, so a name with a directory
//     in it does not fail, it arrives somewhere else.
//   - The DAG lexer (src/condor_utils/dag_parser.cpp:30-77) splits on
//     whitespace and treats " and ' as quote characters. A name becomes
//     a file in the spool AND an argument to the commands instrumentation
//     appends: an unbalanced quote is a fatal "Invalid quoting: no ending
//     quote found", a newline ends the command and makes the rest an
//     unknown one, and a balanced pair parses but is stripped, so DAGMan
//     writes a file under a name nobody reported. A control character in
//     a spooled file name is a problem well beyond instrumentation.
func CheckName(name, what string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%s: a staged file needs a name", what)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("%s %q must be a bare file name with no directories: the schedd flattens a "+
			"spooled sandbox to basenames in one directory", what, name)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%s %q is not a file name", what, name)
	}
	for _, r := range name {
		switch {
		case r == '"' || r == '\'':
			return fmt.Errorf("%s %q contains a quote character, which DAGMan's parser reads as "+
				"quoting and which kills the workflow with a parse error; use only letters, "+
				"digits, and . _ + -", what, name)
		case unicode.IsSpace(r):
			return fmt.Errorf("%s %q contains whitespace, which DAGMan's parser splits on; "+
				"use only letters, digits, and . _ + -", what, name)
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("%s %q contains a control character; use only letters, digits, "+
				"and . _ + -", what, name)
		}
	}
	return nil
}

// SoleConfigFile returns the DAG's CONFIG file when it names exactly
// one. DAGMan reads it through _CONDOR_DAGMAN_CONFIG_FILE rather than
// from the DAG, because the -Config argument and the DAG's own CONFIG
// command are mutually exclusive; more than one CONFIG is a workflow
// that already disagrees with itself, and guessing which to honour would
// be worse than letting DAGMan report it.
func SoleConfigFile(parsed *DAG) string {
	if parsed == nil || len(parsed.Configs) != 1 {
		return ""
	}
	return parsed.Configs[0].Path
}

// StagedMode makes scripts executable. A PRE/POST script spooled 0644
// fails with EACCES the moment DAGMan tries to run it, and the error
// surfaces as a node failure with no obvious cause.
//
// exec is the set of staged names the DAG itself runs, computed from the
// parse. The extension test that remains is a fallback for a file the
// parse could not attribute -- a script named only in a node's
// arguments, say -- and is why "setup" with no extension used to arrive
// unrunnable.
func StagedMode(name string, exec map[string]bool) fs.FileMode {
	if exec[name] {
		return 0o755
	}
	if strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".py") || strings.HasSuffix(name, ".pl") {
		return 0o755
	}
	return 0o644
}

// ExecutableStagedNames is every staged file the workflow will try to
// execute: a PRE/POST/HOLD script, or a submit description's executable
// naming a file staged alongside it.
func ExecutableStagedNames(parsed *DAG, files map[string]string) map[string]bool {
	out := map[string]bool{}
	if parsed == nil {
		return out
	}
	mark := func(name string) {
		// "./setup" and "setup" are the same staged file; a DAG written
		// either way has to arrive runnable.
		name = strings.TrimPrefix(strings.TrimSpace(name), "./")
		if name == "" || strings.ContainsAny(name, `/\`) {
			return
		}
		if _, ok := files[name]; ok {
			out[name] = true
		}
	}
	for _, sc := range parsed.Scripts {
		mark(sc.Executable)
	}
	for _, d := range NamedSubmitDescriptions(parsed, files) {
		mark(SubmitExecutable(d.Body))
	}
	return out
}

// SubmitDescription is one submit description a submission carries,
// named so a diagnostic about it can say which one.
type SubmitDescription struct {
	Name string
	Body string
}

// NamedSubmitDescriptions collects every submit description in a
// submission: the inline node bodies, the named SUBMIT-DESCRIPTION
// blocks, and the staged .sub files.
func NamedSubmitDescriptions(parsed *DAG, files map[string]string) []SubmitDescription {
	var out []SubmitDescription
	if parsed != nil {
		for _, n := range parsed.Nodes {
			if n.Inline && strings.TrimSpace(n.InlineBody) != "" {
				out = append(out, SubmitDescription{Name: "node " + n.Name, Body: n.InlineBody})
			}
		}
		names := make([]string, 0, len(parsed.Descriptions))
		for k := range parsed.Descriptions {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			d := parsed.Descriptions[k]
			out = append(out, SubmitDescription{Name: "SUBMIT-DESCRIPTION " + d.Name, Body: d.Body})
		}
	}
	staged := make([]string, 0, len(files))
	for name := range files {
		if strings.HasSuffix(name, ".sub") {
			staged = append(staged, name)
		}
	}
	sort.Strings(staged)
	for _, name := range staged {
		out = append(out, SubmitDescription{Name: name, Body: files[name]})
	}
	return out
}

// LintDescriptions runs the single-job submit lint over every node
// description in the workflow.
//
// The node jobs are the ones that do the work, and until this existed
// nothing looked at them: a plain job submission refuses `executable =
// /bin/true` with no transfer_executable, while the same description
// inside a DAG reached the queue and held every node. DAGMan submits
// those jobs hours later, so the hold arrives with nothing to connect it
// to the submission.
//
// A fatal finding is reported as a warning rather than refusing the
// workflow: site policy is spliced into these descriptions after the
// lint runs and may well set the very directive the lint wants, and a
// remote submission that refused a description the schedd would have
// accepted is worse than one that says so and submits.
func LintDescriptions(parsed *DAG, files map[string]string) []string {
	var notes []string
	prelude := SuppliedMacros(parsed)
	for _, d := range NamedSubmitDescriptions(parsed, files) {
		insp := submitlint.Inspect(prelude + submitBodyForLint(d.Body))
		if insp.Fatal != nil {
			notes = append(notes, fmt.Sprintf("warning: %s: %s", d.Name, insp.Fatal.Error()))
		}
		for _, w := range insp.Warnings {
			notes = append(notes, fmt.Sprintf("warning: %s: %s", d.Name, w))
		}
	}
	if oauthNodes := OAuthServiceNodes(parsed, files); len(oauthNodes) > 0 {
		notes = append([]string{fmt.Sprintf("note: %s ask for OAuth credentials (use_oauth_services). "+
			"DAGMan submits node jobs itself, long after this submission, so nothing here can check "+
			"them: the credentials must already be stored when the node runs, or that node holds.",
			strings.Join(oauthNodes, ", "))}, notes...)
	}
	return notes
}

// dagVarAssignment matches the left-hand side of one VARS assignment,
// `Name="value"`.
var dagVarAssignment = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)[ \t]*=`)

// dagmanSuppliedMacros are the submit macros DAGMan defines for every
// node it submits (dagman_submit.cpp), which a node description may
// reference without defining.
var dagmanSuppliedMacros = []string{
	"JOB", "RETRY", "MAX_RETRIES", "DAG_STATUS", "FAILED_COUNT",
	"DAGManJobId", "DAG_PARENT_NAMES", "NODE_NAME",
}

// SuppliedMacros renders, as submit-file assignments, every macro a node
// description may use without defining: the DAG's own VARS and DAGMan's
// built-ins.
//
// Without them the lint's undefined-macro check fires on $(NodeName) in
// the standard VARS idiom -- a warning on the most ordinary DAG there
// is, which teaches a caller to ignore the notes.
func SuppliedMacros(parsed *DAG) string {
	names := map[string]bool{}
	if parsed != nil {
		for _, vals := range parsed.Vars {
			for _, v := range vals {
				for _, m := range dagVarAssignment.FindAllStringSubmatch(v, -1) {
					names[m[1]] = true
				}
			}
		}
	}
	for _, n := range dagmanSuppliedMacros {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	var b strings.Builder
	for _, n := range sorted {
		fmt.Fprintf(&b, "%s = \n", n)
	}
	return b.String()
}

// submitBodyForLint makes an inline description parseable on its own. An
// inline body has no queue statement -- DAGMan supplies it -- and
// without one the submit parser produces no job ad and the lint sees
// nothing at all.
func submitBodyForLint(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if f := strings.Fields(line); len(f) > 0 && strings.EqualFold(f[0], "queue") {
			return body
		}
	}
	return body + "\nqueue\n"
}

// submitExecutableLine matches one `executable =` assignment.
var submitExecutableLine = regexp.MustCompile(`(?im)^[ \t]*executable[ \t]*=[ \t]*(.*?)[ \t]*$`)

// SubmitExecutable returns a submit description's executable, which is
// the last assignment of it: submit commands are macro assignments and
// the last one before queue is the effective one.
func SubmitExecutable(body string) string {
	m := submitExecutableLine.FindAllStringSubmatch(body, -1)
	if len(m) == 0 {
		return ""
	}
	return strings.Trim(m[len(m)-1][1], `"'`)
}

// useOAuthServices matches the submit command that makes a job wait for
// a credential.
var useOAuthServices = regexp.MustCompile(`(?im)^[ \t]*use_oauth_services[ \t]*=`)

// OAuthServiceNodes names the descriptions that ask for a credential.
func OAuthServiceNodes(parsed *DAG, files map[string]string) []string {
	var out []string
	for _, d := range NamedSubmitDescriptions(parsed, files) {
		if useOAuthServices.MatchString(d.Body) {
			out = append(out, d.Name)
		}
	}
	return out
}

// PolicyForStagedFile applies the site's submit policy to a staged node
// submit description, and leaves everything else alone.
//
// Deciding what is a submit description by extension is a heuristic, and
// a wrong guess would splice submit-file text into a shell script. So
// the test is deliberately narrow: the name ends in .sub, which is the
// convention DAGMan itself assumes (DAG_SUBMIT_FILE_SUFFIX).
func PolicyForStagedFile(p submitpolicy.Policy, name, body string) (string, error) {
	if p.IsZero() || !strings.HasSuffix(name, ".sub") {
		return body, nil
	}
	return p.Apply(body)
}

// CheckNodePolicy refuses a workflow whose node descriptions set, as a
// custom attribute, a job attribute the site's overrides control. The
// inline descriptions get the overrides from PolicyForInlineDescriptions,
// which splices rather than calling Apply, so they are checked here; the
// staged .sub files are checked here too so the refusal names the first
// offending description whichever kind it is.
func CheckNodePolicy(p submitpolicy.Policy, parsed *DAG, files map[string]string) error {
	if p.IsZero() {
		return nil
	}
	for _, d := range NamedSubmitDescriptions(parsed, files) {
		if err := p.Check(d.Body); err != nil {
			return fmt.Errorf("%s: %w", d.Name, err)
		}
	}
	return nil
}

// PolicyForInlineDescriptions splices the site's submit policy into
// every inline submit description in a DAG.
//
// Without this the shape both surfaces recommend -- everything inline,
// nothing to stage -- is the one shape site policy does not reach, since
// PolicyForStagedFile only ever sees a separate .sub file.
//
// The insertion is by line rather than by parse, because the output has
// to be the caller's DAG with lines added: reprinting a parsed graph
// would silently drop every command the parser does not model. Defaults
// go directly after the opening delimiter and overrides directly before
// the closing one, which is the same last-assignment-wins rule
// submitpolicy uses -- an inline body has no queue statement, so the end
// of the block IS "before queue".
func PolicyForInlineDescriptions(p submitpolicy.Policy, dagText string) string {
	if p.IsZero() {
		return dagText
	}
	defaults := policyBlock(p.Defaults)
	overrides := policyBlock(p.Overrides)
	if len(defaults) == 0 && len(overrides) == 0 {
		return dagText
	}

	lines := strings.Split(dagText, "\n")
	out := make([]string, 0, len(lines)+len(defaults)+len(overrides))
	end := ""
	for i := 0; i < len(lines); i++ {
		if end != "" {
			if isInlineClose(lines[i], end) {
				out = append(out, overrides...)
				out = append(out, lines[i])
				end = ""
				continue
			}
			out = append(out, lines[i])
			continue
		}
		// A DAG command may be continued with a trailing backslash, so
		// the opening delimiter can sit several physical lines below the
		// keyword. Emit them all, then decide from the joined form.
		start := i
		logical := trimContinuation(lines[i])
		for isContinued(lines[i]) && i+1 < len(lines) {
			i++
			logical += " " + trimContinuation(lines[i])
		}
		out = append(out, lines[start:i+1]...)
		if e, ok := inlineDescOpen(logical); ok {
			end = e
			out = append(out, defaults...)
		}
	}
	return strings.Join(out, "\n")
}

// policyBlock renders one half of the policy as submit-file lines,
// marked so someone reading the staged DAG can see where they came from.
func policyBlock(content string) []string {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	out := []string{"  # --- site submit policy (applied by the HTCondor API server) ---"}
	for _, line := range strings.Split(strings.Trim(content, "\n"), "\n") {
		out = append(out, "  "+strings.TrimRight(line, "\r"))
	}
	return append(out, "  # --- end site submit policy ---")
}

func isContinued(line string) bool {
	return strings.HasSuffix(strings.TrimSpace(line), `\`)
}

func trimContinuation(line string) string {
	return strings.TrimSuffix(strings.TrimSpace(line), `\`)
}

// inlineDescOpen reports whether a DAG command opens an inline submit
// description, and what closes it. Mirrors get_inline_desc_end in
// condor_dagman/parse.cpp: the description token is the third field of
// JOB/FINAL/SERVICE/PROVISIONER and of SUBMIT-DESCRIPTION alike, "{"
// closes with "}", and "@=tag" closes with "@tag".
func inlineDescOpen(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", false
	}
	switch strings.ToUpper(strings.ReplaceAll(fields[0], "-", "_")) {
	case "JOB", "FINAL", "SERVICE", "PROVISIONER", "SUBMIT_DESCRIPTION":
	default:
		return "", false
	}
	switch tok := fields[2]; {
	case strings.HasPrefix(tok, "{"):
		return "}", true
	case strings.HasPrefix(tok, "@="):
		return "@" + tok[2:], true
	}
	return "", false
}

// isInlineClose reports whether a line closes an inline description.
// DAGMan re-lexes whatever follows the delimiter as further node
// options, so "} DIR sub" closes the block too.
func isInlineClose(line, end string) bool {
	t := strings.TrimSpace(line)
	return t == end || strings.HasPrefix(t, end+" ") || strings.HasPrefix(t, end+"\t")
}

// FindingStrings renders an analysis as lines a caller can show.
func FindingStrings(report *Report) []string {
	out := make([]string, 0, len(report.Findings))
	for _, f := range report.Findings {
		if f.Line > 0 {
			out = append(out, fmt.Sprintf("%s (line %d): %s", f.Severity, f.Line, f.Message))
		} else {
			out = append(out, fmt.Sprintf("%s: %s", f.Severity, f.Message))
		}
	}
	return out
}

// OutName is DAGMan's own log, named after the DAG: SubmitFile
// sets _CONDOR_DAGMAN_LOG to the DAG name minus ".dag" plus
// ".dagman.out". Empty in, placeholder out.
func OutName(dagFile string) string {
	if dagFile == "" {
		return "<dag>.dagman.out"
	}
	return strings.TrimSuffix(dagFile, ".dag") + ".dagman.out"
}

// RescueName is the rescue DAG DAGMan writes when nodes fail:
// DagmanUtils::RescueDagName appends ".rescue" and a three-digit number
// to the PRIMARY DAG FILE NAME -- "diamond.dag.rescue001", not
// "diamond.rescue001".
func RescueName(dagFile string) string {
	if dagFile == "" {
		return "<dag>.dag.rescue001"
	}
	return dagFile + ".rescue001"
}

// NodeConstraint matches a workflow's node jobs.
//
// DAGMan submits each node as its own cluster, so a caller holding the
// manager's cluster id has nothing that matches them: DAGManJobId is the
// only link, and it carries the manager's CLUSTER, not its job id.
func NodeConstraint(cluster int) string {
	return fmt.Sprintf("DAGManJobId == %d", cluster)
}
