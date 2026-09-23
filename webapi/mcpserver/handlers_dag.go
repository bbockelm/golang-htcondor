package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing/fstest"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/dagman"
)

// A DAGMan workflow submitted from here is an ordinary scheduler-universe
// job whose spooled sandbox happens to contain a graph.
//
// The mechanism is worth stating once, because nothing about it is
// obvious from the tool's surface. SubmitRemote commits the job HELD with
// HoldReasonCode 16, which is what makes the schedd rewrite the job ad
// for spooling: Iwd becomes the job's SPOOL directory and the file lists
// collapse to basenames. condor_dagman itself is exempt from that rewrite
// because transfer_executable is false, so it keeps its absolute path
// while the workflow lands in the directory it will run in. DAGMan then
// finds the .dag in its working directory, submits node jobs from there,
// and those node jobs inherit the same Iwd -- which is why a node's own
// input files have to be staged with the DAG rather than with the node.
//
// The second thing worth stating: a file that is not in the job ad's
// TransferInput is SKIPPED at spool time, not rejected. So the input list
// is computed from the parsed DAG rather than asked for, and a file the
// caller sends that the DAG never mentions is reported back as a probable
// typo instead of vanishing.
//
// The third: the spool is written ONCE. SpoolJobFilesFromFS stats every
// name in TransferInput and fails on the first one missing, and the
// transfer's completion is what releases the hold -- after which the
// schedd refuses a second spool for the same job. There is therefore no
// "upload the big file afterwards" path for a workflow, which is why
// bulk data has to arrive by URL at the execute node instead.

// submitDagDescription is what the model reads before it calls.
//
// It is a raw string literal on purpose. The example below is the shape
// this tool wants callers to write, and it only teaches that shape if it
// arrives as lines: written with "\n" escapes inside a quoted Go string
// the JSON encoder doubles them, and the model is shown one long line of
// literal backslash-n.
const submitDagDescription = `Submit a DAGMan workflow: a graph of jobs with dependencies, retries and pre/post scripts.
Write the workflow in ordinary DAG syntax and pass it as "dag". Prefer inline SUBMIT-DESCRIPTION blocks,
so the whole workflow is one self-contained file with nothing else to stage:

  SUBMIT-DESCRIPTION work {
    executable = /bin/sh
    transfer_executable = false
    arguments = "-c 'echo hi'"
  }
  JOB A work
  JOB B work
  PARENT A CHILD B

Anything the DAG references by file name -- separate .sub files, PRE/POST scripts, small inputs -- goes in
"files" as name -> contents, IN THIS SAME CALL. There is no second chance: a workflow's sandbox is spooled
once, at submit time, and a name that was not sent then can never be added to it afterwards.
Bulk data must NOT go through this call. Give the node jobs HTTP/HTTPS/OSDF URLs in their own
transfer_input_files instead, so the execute machines fetch the bytes directly; everything else has to be
small enough to pass in "files" here (dag plus files is capped at 1 MiB).
The DAG is parsed before submission and the workflow is refused if it cannot start (a cycle, a PARENT
naming an undeclared node, a missing SPLICE or INCLUDE); anything more doubtful comes back as a note.
A SUBDAG whose .dag file an earlier node generates is expected and supported: only its name is needed now.
Use dry_run to check a workflow without submitting it.`

// dagStatusDescription is dag_status's. The scope sentence is the one
// every read tool carries: which jobs the answer covers is not something
// a model can infer from the answer itself.
const dagStatusDescription = `Report progress of a running DAGMan workflow: how many nodes are done, ready, queued, failed or
unready, the state of its node jobs, and whether the DAG is in recovery. DAGMan publishes these into its own
job ad, so this is a single cheap query rather than a log scrape. Pass the cluster id that submit_dag returned.
Returns YOUR OWN workflows; MCP admins get every user's. Each answer states which scope it used.`

// dagTools are the workflow tools, kept together so the catalogue entry
// and the dispatch stay in one place.
func dagTools() []Tool {
	return []Tool{
		{
			Name:        "submit_dag",
			Description: submitDagDescription,
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dag": map[string]interface{}{
						"type":        "string",
						"description": "DAG description file contents (JOB, PARENT/CHILD, SCRIPT, RETRY, SUBMIT-DESCRIPTION, ...)",
					},
					"files": map[string]interface{}{
						"type": "object",
						"description": "Files the DAG references, as name -> contents: node submit files, PRE/POST scripts, " +
							"small inputs. Names must be bare (no directories): the spool directory is flat. This is the " +
							"only chance to supply them; nothing can be added to the workflow's spool afterwards.",
						"additionalProperties": map[string]interface{}{"type": "string"},
					},
					"dag_name": map[string]interface{}{
						"type":        "string",
						"description": "File name to write the DAG as (default \"workflow.dag\")",
					},
					"batch_name": map[string]interface{}{
						"type":        "string",
						"description": "JobBatchName for the workflow, as shown by condor_q -batch",
					},
					"max_idle": map[string]interface{}{"type": "integer", "description": "Throttle: maximum idle node jobs"},
					"max_jobs": map[string]interface{}{"type": "integer", "description": "Throttle: maximum node jobs submitted at once"},
					"max_pre":  map[string]interface{}{"type": "integer", "description": "Throttle: maximum concurrent PRE scripts"},
					"max_post": map[string]interface{}{"type": "integer", "description": "Throttle: maximum concurrent POST scripts"},
					"append":   map[string]interface{}{"type": "string", "description": "Extra submit-file lines for the DAGMan manager job itself"},
					"dry_run":  map[string]interface{}{"type": "boolean", "description": "Parse and check the workflow, report what would be submitted, and submit nothing"},
				},
				"required": []string{"dag"},
			},
		},
		{
			Name:        "dag_status",
			Description: dagStatusDescription,
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"job_id": map[string]interface{}{
						"type":        []string{"string", "integer"},
						"description": "The DAGMan job's cluster id, as returned by submit_dag (1234, \"1234\" or \"1234.0\")",
					},
					"include_nodes": map[string]interface{}{
						"type":        "boolean",
						"description": "Also list the workflow's node jobs with their per-node status (default false)",
					},
				},
				"required": []string{"job_id"},
			},
		},
	}
}

// toolSubmitDag submits a DAGMan workflow.
func (s *Server) toolSubmitDag(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	dagText := stringArg(args, "dag")
	if strings.TrimSpace(dagText) == "" {
		return nil, fmt.Errorf("dag is required: the contents of a DAG description file")
	}
	dagName := strings.TrimSpace(stringArg(args, "dag_name"))
	if dagName == "" {
		dagName = "workflow.dag"
	}
	if strings.ContainsAny(dagName, `/\`) {
		return nil, fmt.Errorf("dag_name %q must be a bare file name: a spooled sandbox is one flat directory", dagName)
	}

	files, err := stringMapArg(args, "files")
	if err != nil {
		return nil, err
	}
	for name := range files {
		if strings.ContainsAny(name, `/\`) {
			return nil, fmt.Errorf("file %q: names must be bare, with no directories -- "+
				"the schedd flattens a spooled sandbox to basenames in one directory", name)
		}
		if name == dagName {
			return nil, fmt.Errorf("file %q collides with dag_name; pass the DAG description as `dag`, not in `files`", name)
		}
	}
	if err := checkDagSubmissionSize(dagText, files); err != nil {
		return nil, err
	}

	// The analysis reads what the CALLER wrote. Site policy is spliced
	// into the text that gets staged (below), but a finding has to point
	// at a line the caller can see.
	report := dagman.Analyze(dagman.Input{
		DagName: dagName,
		Dag:     dagText,
		Files:   files,
		// Nothing can be added to a workflow's spool after submission,
		// so there is no set of names to promise for later.
		Declared: nil,
	})
	parsed := dagman.Parse(dagText)
	notes := append(findingStrings(report), lintNodeDescriptions(parsed, files)...)

	submitFile, err := s.dagmanSubmitFile(ctx, dagName, parsed, report, args)
	if err != nil {
		return nil, err
	}

	if boolFlag(args, "dry_run") {
		// A dry run reports rather than refuses, fatal findings
		// included: the caller asked what is wrong with this workflow,
		// and answering with one error hides the other four.
		return dagDryRunResult(dagName, s.submitPolicy.Apply(submitFile), report, notes), nil
	}
	if report.Fatal() {
		return nil, fmt.Errorf("this workflow cannot start:\n  - %s",
			strings.Join(report.Errors(), "\n  - "))
	}

	staged := fstest.MapFS{
		// Site submit policy reaches the node jobs only here. DAGMan
		// submits those itself, on the access point, long after this
		// call returns, so the descriptions we are handed now are the
		// last chance -- inline blocks in the DAG included, which is the
		// shape this tool recommends.
		dagName: &fstest.MapFile{Data: []byte(s.policyForInlineDescriptions(dagText)), Mode: 0o644},
	}
	execSet := executableStagedNames(parsed, files)
	for name, body := range files {
		staged[name] = &fstest.MapFile{
			Data: []byte(s.policyForStagedFile(name, body)),
			Mode: stagedMode(name, execSet),
		}
	}

	schedd := s.getSchedd()
	clusterID, procAds, err := schedd.SubmitRemote(ctx, s.submitPolicy.Apply(submitFile))
	if err != nil {
		return nil, fmt.Errorf("submitting the DAGMan job failed: %w", err)
	}
	if err := schedd.SpoolJobFilesFromFS(ctx, procAds, staged); err != nil {
		jobID := fmt.Sprintf("%d.0", clusterID)
		res, rmErr := schedd.RemoveJobsByID(ctx, []string{jobID}, "spooling the workflow failed")
		removed := rmErr == nil && res != nil && res.Success > 0
		if !removed && s.logger != nil {
			s.logger.Warn(logging.DestinationMCP, "could not remove the DAGMan job after a spool failure",
				"job_id", jobID, "error", rmErr)
		}
		return nil, errors.New(spoolFailureMessage(clusterID, removed, err))
	}

	if note := s.checkOAuthServicesNeeded(ctx, clusterID); note != "" {
		notes = append(notes, strings.TrimSpace(note))
	}
	return dagSubmitResult(clusterID, dagName, report, notes), nil
}

// dagmanSubmitFile builds the manager job's submit file, filling in what
// the access point's own configuration says about its DAGMan
// installation.
func (s *Server) dagmanSubmitFile(ctx context.Context, dagName string,
	parsed *dagman.DAG, report *dagman.Report, args map[string]interface{}) (string, error) {
	binDir, disablePort := s.dagmanLayout(ctx)
	return dagman.SubmitFile(dagman.SubmitOptions{
		DagName: dagName,
		// Explicit configuration wins; otherwise the schedd's own BIN
		// decides, and only then the package default.
		DagmanPath:  s.dagmanPath,
		BinDir:      binDir,
		DisablePort: disablePort,
		// Deliberately empty: -CsdVersion describes the condor_submit
		// that wrote the file, and this server is not one. DAGMan uses
		// its own version when the argument is absent, which is the
		// only version that is true of the access point.
		CondorVersion: "",
		ConfigFile:    soleConfigFile(parsed),
		InputFiles:    report.Required,
		BatchName:     stringArg(args, "batch_name"),
		MaxIdle:       intArg(args, "max_idle", 0),
		MaxJobs:       intArg(args, "max_jobs", 0),
		MaxPre:        intArg(args, "max_pre", 0),
		MaxPost:       intArg(args, "max_post", 0),
		ExtraEnv:      s.dagmanEnv,
		Append:        stringArg(args, "append"),
	})
}

// soleConfigFile returns the DAG's CONFIG file when it names exactly
// one. DAGMan reads it through _CONDOR_DAGMAN_CONFIG_FILE rather than
// from the DAG, because the -Config argument and the DAG's own CONFIG
// command are mutually exclusive; more than one CONFIG is a workflow
// that already disagrees with itself, and guessing which to honour would
// be worse than letting DAGMan report it.
func soleConfigFile(parsed *dagman.DAG) string {
	if parsed == nil || len(parsed.Configs) != 1 {
		return ""
	}
	return parsed.Configs[0].Path
}

// checkDagSubmissionSize refuses a workflow whose inline bytes are past
// what this path is for. Everything here is copied into a job ad's spool
// through one MCP call, so the ceiling is the conversation's, not the
// schedd's.
func checkDagSubmissionSize(dagText string, files map[string]string) error {
	total := len(dagText)
	for _, body := range files {
		total += len(body)
	}
	if total <= maxDagSubmissionBytes {
		return nil
	}
	return fmt.Errorf("this workflow is %d bytes of dag + files, over the %d byte limit for one submit_dag call. "+
		"Only the workflow's own description belongs here -- the DAG, the node submit descriptions and the "+
		"PRE/POST scripts. Bulk data goes to the execute machines directly: put HTTP/HTTPS/OSDF URLs in the "+
		"node jobs' transfer_input_files instead of staging the bytes through this call",
		total, maxDagSubmissionBytes)
}

// stagedMode makes scripts executable. A PRE/POST script spooled 0644
// fails with EACCES the moment DAGMan tries to run it, and the error
// surfaces as a node failure with no obvious cause.
//
// exec is the set of staged names the DAG itself runs, computed from the
// parse. The extension test that remains is a fallback for a file the
// parse could not attribute -- a script named only in a node's
// arguments, say -- and is why "setup" with no extension used to arrive
// unrunnable.
func stagedMode(name string, exec map[string]bool) fs.FileMode {
	if exec[name] {
		return 0o755
	}
	if strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".py") || strings.HasSuffix(name, ".pl") {
		return 0o755
	}
	return 0o644
}

// executableStagedNames is every staged file the workflow will try to
// execute: a PRE/POST/HOLD script, or a submit description's executable
// naming a file staged alongside it.
func executableStagedNames(parsed *dagman.DAG, files map[string]string) map[string]bool {
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
	for _, d := range namedSubmitDescriptions(parsed, files) {
		mark(submitExecutable(d.body))
	}
	return out
}

// submitDescription is one submit description this call was handed,
// named so a diagnostic about it can say which one.
type submitDescription struct {
	name string
	body string
}

// namedSubmitDescriptions collects every submit description in the
// submission: the inline node bodies, the named SUBMIT-DESCRIPTION
// blocks, and the staged .sub files.
func namedSubmitDescriptions(parsed *dagman.DAG, files map[string]string) []submitDescription {
	var out []submitDescription
	if parsed != nil {
		for _, n := range parsed.Nodes {
			if n.Inline && strings.TrimSpace(n.InlineBody) != "" {
				out = append(out, submitDescription{name: "node " + n.Name, body: n.InlineBody})
			}
		}
		names := make([]string, 0, len(parsed.Descriptions))
		for k := range parsed.Descriptions {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			d := parsed.Descriptions[k]
			out = append(out, submitDescription{name: "SUBMIT-DESCRIPTION " + d.Name, body: d.Body})
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
		out = append(out, submitDescription{name: name, body: files[name]})
	}
	return out
}

// lintNodeDescriptions runs the submit_job lint over every node
// description in the workflow.
//
// The node jobs are the ones that do the work, and until now nothing
// looked at them: submit_job refuses `executable = /bin/true` with no
// transfer_executable, while the same description inside a DAG reached
// the queue and held every node. DAGMan submits those jobs hours later,
// so the hold arrives with nothing to connect it to this call.
//
// A fatal finding is reported as a warning rather than refusing the
// workflow: site policy is spliced into these descriptions after the
// lint runs and may well set the very directive the lint wants, and a
// remote submission that refused a description the schedd would have
// accepted is worse than one that says so and submits.
func lintNodeDescriptions(parsed *dagman.DAG, files map[string]string) []string {
	var notes []string
	prelude := dagSuppliedMacros(parsed)
	for _, d := range namedSubmitDescriptions(parsed, files) {
		insp := inspectSubmitFile(prelude + submitBodyForLint(d.body))
		if insp.fatal != nil {
			notes = append(notes, fmt.Sprintf("warning: %s: %s", d.name, insp.fatal.Error()))
		}
		for _, w := range insp.warnings {
			notes = append(notes, fmt.Sprintf("warning: %s: %s", d.name, w))
		}
	}
	if oauthNodes := oauthServiceNodes(parsed, files); len(oauthNodes) > 0 {
		notes = append([]string{fmt.Sprintf("note: %s ask for OAuth credentials (use_oauth_services). "+
			"DAGMan submits node jobs itself, long after this call, so nothing here can check them: the "+
			"credentials must already be stored when the node runs, or that node holds. Check them now with "+
			"get_credential_status and store what is missing with store_service_credential",
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

// dagSuppliedMacros renders, as submit-file assignments, every macro a
// node description may use without defining: the DAG's own VARS and
// DAGMan's built-ins.
//
// Without them the lint's undefined-macro check fires on $(NodeName) in
// the standard VARS idiom -- a warning on the most ordinary DAG there
// is, which teaches a caller to ignore the notes.
func dagSuppliedMacros(parsed *dagman.DAG) string {
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

// submitExecutable returns a submit description's executable, which is
// the last assignment of it: submit commands are macro assignments and
// the last one before queue is the effective one.
var submitExecutableLine = regexp.MustCompile(`(?im)^[ \t]*executable[ \t]*=[ \t]*(.*?)[ \t]*$`)

func submitExecutable(body string) string {
	m := submitExecutableLine.FindAllStringSubmatch(body, -1)
	if len(m) == 0 {
		return ""
	}
	return strings.Trim(m[len(m)-1][1], `"'`)
}

// useOAuthServices matches the submit command that makes a job wait for
// a credential.
var useOAuthServices = regexp.MustCompile(`(?im)^[ \t]*use_oauth_services[ \t]*=`)

func oauthServiceNodes(parsed *dagman.DAG, files map[string]string) []string {
	var out []string
	for _, d := range namedSubmitDescriptions(parsed, files) {
		if useOAuthServices.MatchString(d.body) {
			out = append(out, d.name)
		}
	}
	return out
}

// spoolFailureMessage explains a workflow that reached the queue and then
// failed to spool.
//
// Always naming the cluster is the point. The manager job exists either
// way, and whether it is still there decides what the caller must do
// next -- so "0 jobs removed" is not a success, and reporting it as one
// leaves a held job in the queue that nothing in the answer accounts for.
func spoolFailureMessage(clusterID int, removed bool, cause error) string {
	msg := fmt.Sprintf("the schedd accepted the DAGMan job but spooling the workflow failed: %v.", cause)
	if removed {
		return msg + fmt.Sprintf(" The DAGMan job %d.0 was removed.", clusterID)
	}
	return msg + fmt.Sprintf(" The DAGMan job %d.0 could NOT be removed and is still in the queue, "+
		"held and unable to run; remove it with remove_job.", clusterID)
}

// policyForStagedFile applies the site's submit policy to a staged node
// submit description, and leaves everything else alone.
//
// Deciding what is a submit description by extension is a heuristic, and
// a wrong guess would splice submit-file text into a shell script. So the
// test is deliberately narrow: the name ends in .sub, which is the
// convention DAGMan itself assumes (DAG_SUBMIT_FILE_SUFFIX).
func (s *Server) policyForStagedFile(name, body string) string {
	if s.submitPolicy.IsZero() || !strings.HasSuffix(name, ".sub") {
		return body
	}
	return s.submitPolicy.Apply(body)
}

// policyForInlineDescriptions splices the site's submit policy into every
// inline submit description in a DAG.
//
// Without this the tool's own recommended shape -- everything inline,
// nothing to stage -- is the one shape site policy does not reach, since
// policyForStagedFile only ever sees a separate .sub file.
//
// The insertion is by line rather than by parse, because the output has
// to be the caller's DAG with lines added: reprinting a parsed graph
// would silently drop every command the parser does not model. Defaults
// go directly after the opening delimiter and overrides directly before
// the closing one, which is the same last-assignment-wins rule
// submitpolicy uses -- an inline body has no queue statement, so the end
// of the block IS "before queue".
func (s *Server) policyForInlineDescriptions(dagText string) string {
	if s.submitPolicy.IsZero() {
		return dagText
	}
	defaults := policyBlock(s.submitPolicy.Defaults)
	overrides := policyBlock(s.submitPolicy.Overrides)
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

func dagDryRunResult(dagName, submitFile string, report *dagman.Report, notes []string) map[string]interface{} {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Dry run: nothing was submitted.\n\nDAG file: %s\n", dagName)
	if report.Fatal() {
		fmt.Fprintf(&sb, "\nThis workflow CANNOT be submitted as written:\n  - %s\n",
			strings.Join(report.Errors(), "\n  - "))
	}
	writeDagNotes(&sb, report, notes)
	fmt.Fprintf(&sb, "\nThe DAGMan manager job would be submitted as:\n\n%s", submitFile)
	structured := map[string]interface{}{
		"dry_run":     true,
		"dag_name":    dagName,
		"submit_file": submitFile,
		"input_files": report.Required,
		"notes":       notes,
		"fatal":       report.Fatal(),
		"errors":      report.Errors(),
		"deferred":    report.Deferred,
	}
	return withStructured(map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": sb.String()}},
		"metadata": structured,
	}, structured)
}

func dagSubmitResult(clusterID int, dagName string, report *dagman.Report, notes []string) map[string]interface{} {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Submitted DAGMan workflow %s as cluster %d.\n", dagName, clusterID)
	fmt.Fprintf(&sb, "Staged into the workflow's spool directory: %s\n", strings.Join(report.Required, ", "))
	writeDagNotes(&sb, report, notes)
	fmt.Fprintf(&sb, "\n%s\n", dagWaitAdvice(clusterID))
	fmt.Fprintf(&sb, "%s\n", dagOutputAdvice(clusterID))
	fmt.Fprintf(&sb, "Removing job %d.0 removes the whole workflow, including node jobs already running.\n", clusterID)

	structured := map[string]interface{}{
		"cluster_id":  clusterID,
		"job_id":      fmt.Sprintf("%d.0", clusterID),
		"dag_name":    dagName,
		"input_files": report.Required,
		"notes":       notes,
		"deferred":    report.Deferred,
	}
	return withStructured(map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": sb.String()}},
		"metadata": structured,
	}, structured)
}

// dagWaitAdvice is how to wait for a workflow.
//
// watch_jobs takes a constraint, not a job id, and "done" does fire for
// the manager job: a remotely-submitted job carries LeaveJobInQueue, so
// it sits at JobStatus 4 rather than vanishing. Telling a caller to
// "watch_jobs on cluster N" instead left it guessing at an argument that
// does not exist, and the fallback it guessed was a dag_status loop.
func dagWaitAdvice(clusterID int) string {
	return fmt.Sprintf(`To wait for the whole workflow, register watch_jobs(constraint="ClusterId == %d", `+
		`event="done") and collect it with check_watches -- do not call dag_status in a loop. `+
		`Use dag_status for a one-off "how far along is it".`, clusterID)
}

// dagOutputAdvice is where a finished workflow's results are. Node
// outputs return to the DAG's Iwd, which is the manager job's spool --
// not to any node job's sandbox, which is gone.
func dagOutputAdvice(clusterID int) string {
	return fmt.Sprintf(`Node outputs come back into the workflow's own spool directory. Retrieve them with `+
		`get_job_output(job_id="%d.0") -- that returns the whole spool, including DAGMan's own `+
		`<dag>.dagman.out log.`, clusterID)
}

// writeDagNotes renders the analysis.
func writeDagNotes(sb *strings.Builder, report *dagman.Report, notes []string) {
	if len(notes) > 0 {
		sb.WriteString("\nNotes:\n")
		for _, n := range notes {
			fmt.Fprintf(sb, "  - %s\n", n)
		}
	}
	if len(report.Deferred) > 0 {
		fmt.Fprintf(sb, "\nExpected to be produced while the workflow runs: %s\n",
			strings.Join(report.Deferred, ", "))
	}
}

func findingStrings(report *dagman.Report) []string {
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

// dagProgressAttrs are what DAGMan publishes into its own job ad
// (condor_dagman/dagman_classad.cpp). Reading them is why this tool is a
// query rather than a log parser.
var dagProgressAttrs = []string{
	"ClusterId", "ProcId", "Owner", "JobStatus", "JobBatchName", "Cmd", "Args", "Arguments",
	"HoldReason", "HoldReasonCode",
	"DAG_NodesTotal", "DAG_NodesDone", "DAG_NodesReady", "DAG_NodesQueued",
	"DAG_NodesPrerun", "DAG_NodesPostrun", "DAG_NodesFailed", "DAG_NodesUnready",
	"DAG_NodesFutile", "DAG_Status", "DAG_InRecovery", "DAG_AdUpdateTime",
	"DAG_JobsSubmitted", "DAG_JobsIdle", "DAG_JobsRunning", "DAG_JobsHeld", "DAG_JobsCompleted",
}

// dagStatusNames maps DAG_Status to the enum in dagman_utils.h.
var dagStatusNames = map[int64]string{
	0: "OK",
	1: "ERROR",
	2: "NODE_FAILED",
	3: "ABORT (a node hit its ABORT-DAG-ON value)",
	4: "REMOVED",
	5: "CYCLE (the graph has a cycle)",
	6: "HALTED",
}

// dagClusterArg reads the cluster id a caller passed.
//
// It accepts a JSON number as well as a string because submit_dag hands
// back cluster_id as an integer, and an agent that passes its own
// structured output straight back in is doing the obvious thing. The
// value is parsed rather than spliced: owner scoping confines a normal
// user whatever they send, but an MCP admin's constraint is used as
// written.
func dagClusterArg(args map[string]interface{}) (int, error) {
	var raw string
	switch v := args["job_id"].(type) {
	case string:
		raw = strings.TrimSpace(v)
	case float64:
		raw = strconv.FormatInt(int64(v), 10)
	case int:
		raw = strconv.Itoa(v)
	case int64:
		raw = strconv.FormatInt(v, 10)
	case json.Number:
		raw = v.String()
	case nil:
		return 0, fmt.Errorf("job_id is required: the cluster id submit_dag returned")
	default:
		return 0, fmt.Errorf("job_id must be a cluster id, not %T", v)
	}
	if raw == "" {
		return 0, fmt.Errorf("job_id is required: the cluster id submit_dag returned")
	}
	if i := strings.Index(raw, "."); i >= 0 {
		raw = raw[:i]
	}
	cluster, err := strconv.Atoi(raw)
	if err != nil || cluster < 0 {
		return 0, fmt.Errorf("job_id %q is not a cluster id; pass what submit_dag returned (1234 or \"1234.0\")",
			stringArg(args, "job_id"))
	}
	return cluster, nil
}

// toolDagStatus reports a workflow's progress.
func (s *Server) toolDagStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	cluster, err := dagClusterArg(args)
	if err != nil {
		return nil, err
	}

	scope, ok := s.ownerScope(ctx, tierRead)
	if !ok {
		return nil, fmt.Errorf("no authenticated caller to scope this query to")
	}
	constraint := fmt.Sprintf("ClusterId == %d", cluster)
	if !scope.AllUsers {
		scoped, err := ownerScopedConstraint(scope.Owner, constraint)
		if err != nil {
			return nil, err
		}
		constraint = scoped
	}

	ads, _, err := s.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: dagProgressAttrs,
		Limit:      1,
		FetchOpts:  fetchOptsFor(scope),
		Owner:      scope.Owner,
	})
	if err != nil {
		return nil, fmt.Errorf("querying the DAGMan job failed: %w", err)
	}
	if len(ads) == 0 {
		return nil, fmt.Errorf("no job with cluster id %d %s. "+
			"A finished workflow leaves the queue; look for it with query_job_archive instead", cluster, scope.Note())
	}
	ad := ads[0]

	sb := &strings.Builder{}
	sb.WriteString(renderDagStatus(cluster, scope, ad))
	if boolFlag(args, "include_nodes") {
		s.appendNodeJobs(ctx, sb, cluster, scope)
	}

	return dagStatusResult(sb.String(), cluster, ad), nil
}

// renderDagStatus turns a DAGMan job ad into the report a caller reads.
//
// Split out from toolDagStatus so the decisions in it -- above all,
// whether a held manager job is spooling or stuck -- can be exercised
// against a crafted ad. Those two states are the same JobStatus and
// differ only in a hold code, and getting them confused tells a caller to
// keep waiting on a workflow that is already dead.
func renderDagStatus(cluster int, scope OwnerScope, ad *classad.ClassAd) string {
	total, hasTotal := ad.EvaluateAttrInt("DAG_NodesTotal")
	var sb strings.Builder
	fmt.Fprintf(&sb, "DAGMan workflow %d.0 %s\n", cluster, scope.Note())
	if name, ok := ad.EvaluateAttrString("JobBatchName"); ok && name != "" {
		fmt.Fprintf(&sb, "batch name: %s\n", name)
	}
	status, _ := ad.EvaluateAttrInt("JobStatus")
	fmt.Fprintf(&sb, "manager job status: %s\n", describeJobStatus(int(status)))

	// A finished manager job means the results are sitting in its spool,
	// which is the one place a caller does not think to look: the node
	// jobs' own sandboxes are long gone, and their output came back here.
	finish := func() string {
		if status == 4 {
			fmt.Fprintf(&sb, "\n%s\n", dagOutputAdvice(cluster))
		}
		return sb.String()
	}

	// A hold is the one manager-job state that must never be reported as
	// "still starting up". Spooling input is also a hold (code 16) and
	// does clear on its own, so the two are indistinguishable in JobStatus
	// alone -- and telling a caller to keep waiting on a hold that will
	// never clear is how an agent spends its whole budget on a workflow
	// that died before it began.
	holdCode, hasHold := ad.EvaluateAttrInt("HoldReasonCode")
	if status == 5 && (!hasHold || holdCode != 16) {
		reason, _ := ad.EvaluateAttrString("HoldReason")
		if reason == "" {
			reason = "no reason recorded"
		}
		fmt.Fprintf(&sb, "\nThis workflow is STUCK: the DAGMan job is held for a reason that will not clear "+
			"on its own -- %s\nIt will make no progress until the cause is fixed and the job is released "+
			"(release_job) or removed (remove_job). Do not wait on it.\n", reason)
		return finish()
	}

	if !hasTotal {
		if status == 5 {
			sb.WriteString("\nThe workflow is held while its input spools, which clears on its own once the " +
				"files arrive.\n")
		} else {
			sb.WriteString("\nDAGMan has not published progress yet. It publishes into its own job ad once it " +
				"has parsed the DAG and started running, so this is normal for a workflow that was just " +
				"submitted.\n")
		}
		return finish()
	}

	if st, ok := ad.EvaluateAttrInt("DAG_Status"); ok {
		name, known := dagStatusNames[st]
		if !known {
			name = fmt.Sprintf("unrecognized status %d", st)
		}
		fmt.Fprintf(&sb, "DAG status: %s\n", name)
	}
	if rec, ok := ad.EvaluateAttrBool("DAG_InRecovery"); ok && rec {
		sb.WriteString("DAGMan is in RECOVERY: it is rebuilding its state from the node logs after a restart.\n")
	}

	fmt.Fprintf(&sb, "\nnodes: %d total", total)
	for _, p := range []struct {
		attr, label string
	}{
		{"DAG_NodesDone", "done"},
		{"DAG_NodesQueued", "queued"},
		{"DAG_NodesReady", "ready"},
		{"DAG_NodesUnready", "unready"},
		{"DAG_NodesPrerun", "in PRE"},
		{"DAG_NodesPostrun", "in POST"},
		{"DAG_NodesFailed", "FAILED"},
		{"DAG_NodesFutile", "futile"},
	} {
		if v, ok := ad.EvaluateAttrInt(p.attr); ok && v > 0 {
			fmt.Fprintf(&sb, ", %d %s", v, p.label)
		}
	}
	sb.WriteString("\n")

	fmt.Fprintf(&sb, "node jobs:")
	for _, p := range []struct {
		attr, label string
	}{
		{"DAG_JobsSubmitted", "submitted"},
		{"DAG_JobsRunning", "running"},
		{"DAG_JobsIdle", "idle"},
		{"DAG_JobsHeld", "HELD"},
		{"DAG_JobsCompleted", "completed"},
	} {
		if v, ok := ad.EvaluateAttrInt(p.attr); ok {
			fmt.Fprintf(&sb, " %d %s;", v, p.label)
		}
	}
	sb.WriteString("\n")

	if failed, ok := ad.EvaluateAttrInt("DAG_NodesFailed"); ok && failed > 0 {
		fmt.Fprintf(&sb, "\n%d node(s) failed. The reason is in the node's own job -- query_job_archive with "+
			"constraint DAGManJobId == %d shows how each node job ended.\n", failed, cluster)
		sb.WriteString("DAGMan wrote a rescue DAG (<dag>.dag.rescue001) into the workflow's spool listing " +
			"the nodes that still need to run. To resume, fetch it with get_job_output and submit a new " +
			"workflow with the same dag_name, passing the rescue file in files.\n")
	}
	if futile, ok := ad.EvaluateAttrInt("DAG_NodesFutile"); ok && futile > 0 {
		fmt.Fprintf(&sb, "%d node(s) are futile: they can never run because an ancestor failed.\n", futile)
	}
	return finish()
}

// appendNodeJobs lists the workflow's node jobs. They are linked to the
// manager by DAGManJobId, which DAGMan sets on every job it submits.
func (s *Server) appendNodeJobs(ctx context.Context, sb *strings.Builder, cluster int, scope OwnerScope) {
	constraint := fmt.Sprintf("DAGManJobId == %d", cluster)
	if !scope.AllUsers {
		scoped, err := ownerScopedConstraint(scope.Owner, constraint)
		if err != nil {
			return
		}
		constraint = scoped
	}
	ads, _, err := s.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: []string{"ClusterId", "ProcId", "JobStatus", "DAGNodeName", "HoldReason"},
		Limit:      200,
		FetchOpts:  fetchOptsFor(scope),
		Owner:      scope.Owner,
	})
	if err != nil {
		fmt.Fprintf(sb, "\n(could not list node jobs: %v)\n", err)
		return
	}
	if len(ads) == 0 {
		sb.WriteString("\nNo node jobs are in the queue right now. Nodes that have already finished leave it; " +
			"query_job_archive with the same constraint finds them.\n")
		return
	}
	sb.WriteString("\nnode jobs in the queue:\n")
	for _, ad := range ads {
		c, _ := ad.EvaluateAttrInt("ClusterId")
		p, _ := ad.EvaluateAttrInt("ProcId")
		st, _ := ad.EvaluateAttrInt("JobStatus")
		name, _ := ad.EvaluateAttrString("DAGNodeName")
		fmt.Fprintf(sb, "  %d.%d  %-10s  %s", c, p, describeJobStatus(int(st)), name)
		if reason, ok := ad.EvaluateAttrString("HoldReason"); ok && reason != "" {
			fmt.Fprintf(sb, "  [held: %s]", reason)
		}
		sb.WriteString("\n")
	}
}

func dagStatusResult(text string, cluster int, ad interface {
	EvaluateAttrInt(string) (int64, bool)
}) map[string]interface{} {
	// cluster_id is an integer here because it is an integer in
	// submit_dag's result, and a client that feeds one tool's output to
	// the other should not have to convert between them.
	structured := map[string]interface{}{"cluster_id": cluster}
	// The manager job's own status, alongside the workflow's. They answer
	// different questions and a caller needs both: a DAG that reports no
	// progress because DAGMan has not started yet is waiting, and one that
	// reports none because the manager already exited is finished or
	// broken. Without this the two are indistinguishable.
	if v, ok := ad.EvaluateAttrInt("JobStatus"); ok {
		structured["job_status"] = v
	}
	// The hold code is what separates "spooling, will clear" from "stuck".
	if v, ok := ad.EvaluateAttrInt("HoldReasonCode"); ok {
		structured["hold_reason_code"] = v
	}
	for _, attr := range []string{
		"DAG_NodesTotal", "DAG_NodesDone", "DAG_NodesReady", "DAG_NodesQueued",
		"DAG_NodesFailed", "DAG_NodesUnready", "DAG_NodesFutile", "DAG_Status",
		"DAG_JobsIdle", "DAG_JobsRunning", "DAG_JobsHeld", "DAG_JobsCompleted",
	} {
		if v, ok := ad.EvaluateAttrInt(attr); ok {
			structured[strings.ToLower(attr)] = v
		}
	}
	return withStructured(map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": text}},
		"metadata": structured,
	}, structured)
}

// stringMapArg reads a JSON object of string values.
func stringMapArg(args map[string]interface{}, key string) (map[string]string, error) {
	raw, ok := args[key]
	if !ok || raw == nil {
		return map[string]string{}, nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an object of file name -> contents", key)
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%q] must be a string; a file's contents cannot be %T", key, k, v)
		}
		out[k] = s
	}
	return out, nil
}

// boolFlag reads an optional boolean argument, defaulting to false.
//
// It accepts the string forms too: a model that has been told the
// parameter is a boolean still sends "true" often enough that treating
// that as false would make a flag look broken rather than mistyped.
func boolFlag(args map[string]interface{}, key string) bool {
	switch v := args[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true") || v == "1"
	default:
		return false
	}
}

// dagmanLayout is what the access point's own configuration says about
// its DAGMan installation: the directory its binaries are in, and
// whether DAGMan is configured to run without a command port.
//
// Both are asked of the SCHEDD, once, because both are properties of the
// machine this server submits to and not of the machine it runs on --
// which is exactly why HTTP_API_DAGMAN_PATH had to be configured by hand
// before. DC_CONFIG_VAL is a READ-level command, so this needs no
// privilege.
//
// Everything about it fails soft. An error, an unset knob, or an empty
// value all mean "unknown", and unknown means the previous behaviour:
// the package default path and a command port. An empty BIN in
// particular must not become "/condor_dagman" -- the "Not defined" reply
// daemon core sends is matched by content, and a reply that does not
// match it exactly would otherwise be treated as a real directory.
func (s *Server) dagmanLayout(ctx context.Context) (binDir string, disablePort bool) {
	s.dagmanLayoutOnce.Do(func() {
		discover := s.dagmanLayoutFn
		if discover == nil {
			discover = s.discoverDagmanLayout
		}
		s.dagmanLayoutBin, s.dagmanLayoutNoPort = discover(ctx)
	})
	return s.dagmanLayoutBin, s.dagmanLayoutNoPort
}

// discoverDagmanLayout asks the schedd. Never fails a submission: a
// refusal here costs the defaults, not the workflow.
func (s *Server) discoverDagmanLayout(ctx context.Context) (string, bool) {
	schedd := s.getSchedd()
	if schedd == nil {
		return "", false
	}
	binDir := s.scheddConfigVal(ctx, schedd, "BIN")
	if binDir != "" && !path.IsAbs(binDir) {
		// A relative BIN cannot be joined onto anything meaningful from
		// here: this process is not in the access point's filesystem.
		binDir = ""
	}
	disable := isConfigTrue(s.scheddConfigVal(ctx, schedd, "DAGMAN_DISABLE_PORT"))
	if s.logger != nil {
		s.logger.Debug(logging.DestinationMCP, "DAGMan layout discovered from the schedd",
			"bin", binDir, "disable_port", disable)
	}
	return binDir, disable
}

// scheddConfigVal reads one knob, treating every kind of "no answer" the
// same. daemon core reports an unset parameter as the literal string
// "Not defined", which ConfigVal recognizes -- but a daemon that phrases
// it differently would hand back that sentence as a value, so the prefix
// is checked here too.
func (s *Server) scheddConfigVal(ctx context.Context, schedd *htcondor.Schedd, name string) string {
	value, ok, err := schedd.ConfigVal(ctx, name)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug(logging.DestinationMCP, "could not read a config value from the schedd",
				"knob", name, "error", err)
		}
		return ""
	}
	if !ok {
		return ""
	}
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "Not defined") {
		return ""
	}
	return value
}

// isConfigTrue reads HTCondor's boolean spelling.
func isConfigTrue(v string) bool {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "TRUE", "T", "YES", "Y", "1":
		return true
	}
	return false
}
