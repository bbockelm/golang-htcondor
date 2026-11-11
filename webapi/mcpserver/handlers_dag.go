package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/dagman"
	"github.com/bbockelm/golang-htcondor/webapi/internal/jobargs"
)

// A DAGMan workflow submitted from here is an ordinary scheduler-universe
// job whose spooled sandbox happens to contain a graph. How that works,
// and why a workflow's sandbox can never be added to afterwards, is in
// webapi/dagman/prepare.go -- which is also where everything between
// "the caller handed us a DAG" and "the schedd has a submit file and a
// sandbox" now lives, because the REST API submits workflows too and the
// two surfaces must not drift.
//
// What is left here is the MCP tool: the schema a model reads, the
// argument coercion a model needs, and the prose the result is rendered
// as.

// submitDagDescription is what the model reads before it calls.
//
// It is a raw string literal on purpose. The example below is the shape
// this tool wants callers to write, and it only teaches that shape if it
// arrives as lines: written with "\n" escapes inside a quoted Go string
// the JSON encoder doubles them, and the model is shown one long line of
// literal backslash-n.
const submitDagDescription = `Submit a DAGMan workflow: a graph of jobs with dependencies, retries and pre/post scripts.
Write the workflow in ordinary DAG syntax and pass it as "dag". Prefer inline SUBMIT-DESCRIPTION blocks,
so the whole workflow is one self-contained file with nothing else to stage. One description serves every
node of a stage; VARS gives each node its own values:

  SUBMIT-DESCRIPTION work {
    executable = /bin/sh
    transfer_executable = false
    arguments = "-c 'echo hi > out_$(sample).txt'"
    transfer_output_files = out_$(sample).txt
  }
  JOB A work
  JOB B work
  VARS A sample="1"
  VARS B sample="2"
  JOB GATHER {
    executable = /bin/sh
    transfer_executable = false
    arguments = "-c 'cat out_1.txt out_2.txt > all.txt'"
    transfer_input_files = out_1.txt, out_2.txt
    transfer_output_files = all.txt
  }
  PARENT A B CHILD GATHER

Node outputs land in the workflow's directory. A downstream node picks one up by name in
transfer_input_files; declare it in the producer's transfer_output_files so the pre-submit check can see
who produces it.
Files named in a SCRIPT line or as a node's executable are staged executable; other files are not.
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

// dagTools are the workflow tools, kept together so the catalogue entry
// and the dispatch stay in one place.
//
// There is only one. A workflow's progress used to have a tool of its
// own, which did nothing get_job could not: it read the manager job's
// ad, which is where DAGMan publishes its node counts. A
// second tool for the same query is a second thing a model has to know
// exists -- and the one it reaches for, having just been handed a job
// id, is get_job. So the rendering moved there (renderDagSection) and
// the tool went away.
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
					"instrument": map[string]interface{}{
						"type": "boolean",
						"description": "Default true: append DOT and NODE_STATUS_FILE commands so the workflow's " +
							"structure and per-node progress can be read while it runs. Set false if the " +
							"workflow must run even when its spool cannot be written -- DAGMan ABORTS a DAG " +
							"whose node status file cannot be written (DAGMAN_USE_STRICT defaults to 1), so on " +
							"a full or read-only spool instrumentation turns a degraded run into a dead one. " +
							"With it off there is no graph and no per-node state for this workflow.",
					},
				},
				"required": []string{"dag"},
			},
		},
	}
}

// toolSubmitDag submits a DAGMan workflow.
//
// It is argument coercion, one call to dagman.Prepare, and the submit
// plus spool pair. Everything a workflow is checked for lives in
// Prepare, so the REST endpoint checks it the same way.
func (s *Server) toolSubmitDag(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	files, err := stringMapArg(args, "files")
	if err != nil {
		return nil, err
	}
	layout := s.dagmanLayout(ctx)
	prep, err := dagman.Prepare(dagman.Submission{
		DagName:    strings.TrimSpace(stringArg(args, "dag_name")),
		Dag:        stringArg(args, "dag"),
		Files:      files,
		BatchName:  stringArg(args, "batch_name"),
		MaxIdle:    intArg(args, "max_idle", 0),
		MaxJobs:    intArg(args, "max_jobs", 0),
		MaxPre:     intArg(args, "max_pre", 0),
		MaxPost:    intArg(args, "max_post", 0),
		Append:     stringArg(args, "append"),
		Instrument: instrumentRequested(args),
		MaxBytes:   maxDagSubmissionBytes,
		DagmanPath: s.dagmanPath,
		Layout:     layout,
		ExtraEnv:   s.dagmanEnv,
		Policy:     s.submitPolicy,
	})
	if err != nil {
		return nil, err
	}

	if boolFlag(args, "dry_run") {
		// A dry run reports rather than refuses, fatal findings
		// included: the caller asked what is wrong with this workflow,
		// and answering with one error hides the other four.
		return dagDryRunResult(prep), nil
	}
	if prep.Report.Fatal() {
		return nil, fmt.Errorf("this workflow cannot start:\n  - %s",
			strings.Join(prep.Report.Errors(), "\n  - "))
	}

	// The routed AP in multi-AP mode: the spool goes where the job went.
	schedd := s.scheddFor(ctx)
	// submitApplied, not submitRemote: Prepare already applied the site's
	// submit policy to this file, and applying it twice is refused.
	clusterID, procAds, err := s.submitApplied(ctx, prep.SubmitFile)
	if err != nil {
		return nil, fmt.Errorf("submitting the DAGMan job failed: %w", err)
	}
	if err := schedd.SpoolJobFilesFromFS(ctx, procAds, prep.FS()); err != nil {
		jobID := fmt.Sprintf("%d.0", clusterID)
		res, rmErr := schedd.RemoveJobsByID(ctx, []string{jobID}, "spooling the workflow failed")
		removed := rmErr == nil && res != nil && res.Success > 0
		if !removed && s.logger != nil {
			s.logger.Warn(logging.DestinationMCP, "could not remove the DAGMan job after a spool failure",
				"job_id", jobID, "error", rmErr)
		}
		return nil, errors.New(spoolFailureMessage(clusterID, removed, err))
	}

	notes := prep.Notes
	if note := s.checkOAuthServicesNeeded(ctx, clusterID); note != "" {
		notes = append(notes, strings.TrimSpace(note))
	}
	return dagSubmitResult(clusterID, prep, notes), nil
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

func dagDryRunResult(prep *dagman.Prepared) map[string]interface{} {
	report := prep.Report
	var sb strings.Builder
	fmt.Fprintf(&sb, "Dry run: nothing was submitted.\n\nDAG file: %s\n", prep.DagName)
	if report.Fatal() {
		fmt.Fprintf(&sb, "\nThis workflow CANNOT be submitted as written:\n  - %s\n",
			strings.Join(report.Errors(), "\n  - "))
	}
	writeDagNotes(&sb, report, prep.Notes)
	fmt.Fprintf(&sb, "\nThe DAGMan manager job would be submitted as:\n\n%s", prep.SubmitFile)
	structured := map[string]interface{}{
		"dry_run":     true,
		"dag_name":    prep.DagName,
		"submit_file": prep.SubmitFile,
		"input_files": report.Required,
		"notes":       prep.Notes,
		"fatal":       report.Fatal(),
		"errors":      report.Errors(),
		"deferred":    report.Deferred,
	}
	return withStructured(map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": sb.String()}},
		"metadata": structured,
	}, structured)
}

func dagSubmitResult(clusterID int, prep *dagman.Prepared, notes []string) map[string]interface{} {
	report := prep.Report
	instr := prep.Instrumentation
	var sb strings.Builder
	fmt.Fprintf(&sb, "Submitted DAGMan workflow %s as cluster %d.\n", prep.DagName, clusterID)
	fmt.Fprintf(&sb, "Staged into the workflow's spool directory: %s\n", strings.Join(report.Required, ", "))
	writeDagNotes(&sb, report, notes)
	fmt.Fprintf(&sb, "\n%s\n", dagWaitAdvice(clusterID))
	fmt.Fprintf(&sb, "%s\n", dagOutputAdvice(clusterID, prep.DagName))
	fmt.Fprintf(&sb, "%s\n", dagNodeJobAdvice(clusterID))
	fmt.Fprintf(&sb, "Removing job %d.0 removes the whole workflow, including node jobs already running.\n", clusterID)
	switch {
	case instr.DotFile != "" && instr.StatusFile != "":
		fmt.Fprintf(&sb, "DAGMan writes this workflow's structure to %s and its per-node status to %s in "+
			"the workflow's spool, so the graph and how far along each node is can be read while it "+
			"runs.\n", instr.DotFile, instr.StatusFile)
	case instr.Skipped != "":
		// Named here as well as in the notes: a caller that is about to
		// go looking for a graph should learn there is none from the
		// same paragraph that would otherwise have told it where to
		// look.
		fmt.Fprintf(&sb, "%s\n", instr.Skipped)
	}

	structured := map[string]interface{}{
		"cluster_id":  clusterID,
		"job_id":      fmt.Sprintf("%d.0", clusterID),
		"dag_name":    prep.DagName,
		"input_files": report.Required,
		"notes":       notes,
		"deferred":    report.Deferred,
		// The workflow's node jobs are not in its cluster: DAGMan submits
		// them itself, each as its own cluster, and the only thing tying
		// them to the manager is this attribute. Handing the constraint
		// over ready-made is the difference between a caller querying the
		// nodes and a caller querying the manager job again and
		// concluding the workflow has no jobs.
		"node_constraint": dagNodeConstraint(clusterID),
		// The files the instrumentation will produce, so a caller that
		// wants the graph knows what to look for in the spool.
		"dot_file":    instr.DotFile,
		"status_file": instr.StatusFile,
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
// does not exist, and the fallback it guessed was a polling loop.
func dagWaitAdvice(clusterID int) string {
	return fmt.Sprintf(`To wait for the whole workflow, register watch_jobs(constraint="ClusterId == %d", `+
		`event="done") and collect it with check_watches -- do not call get_job in a loop. `+
		`Use get_job(job_id="%d.0") for a one-off "how far along is it".`, clusterID, clusterID)
}

// dagNodeConstraint matches the workflow's node jobs.
//
// DAGMan submits each node as its own cluster, so a caller holding the
// manager's cluster id has nothing that matches them: DAGManJobId is the
// only link, and it carries the manager's CLUSTER, not its job id.
func dagNodeConstraint(cluster int) string {
	return dagman.NodeConstraint(cluster)
}

// dagNodeJobAdvice is how to look at the work itself rather than at the
// manager. Said at submit time because that is when a caller has the
// cluster id in hand and is about to go looking for jobs that are not in
// it.
func dagNodeJobAdvice(cluster int) string {
	return fmt.Sprintf(`Node jobs carry %s and DAGNodeName. List them with query_jobs(constraint=%q); `+
		`finished ones with query_job_archive on the same constraint.`,
		dagNodeConstraint(cluster), dagNodeConstraint(cluster))
}

// dagOutputAdvice is where a finished workflow's results are. Node
// outputs return to the DAG's Iwd, which is the manager job's spool --
// not to any node job's sandbox, which is gone.
//
// dagFile is the workflow's own .dag name when it is known, so the log
// can be named rather than described: "diamond.dagman.out" is a file the
// caller can look for in what get_job_output returns, and
// "<dag>.dagman.out" is a riddle.
func dagOutputAdvice(clusterID int, dagFile string) string {
	return fmt.Sprintf(`Node outputs come back into the workflow's own spool directory. Retrieve them with `+
		`get_job_output(job_id="%d.0") -- that returns the whole spool, including DAGMan's own `+
		`%s log.`, clusterID, dagmanOutName(dagFile))
}

// dagmanOutName is DAGMan's own log, named after the DAG: SubmitFile
// sets _CONDOR_DAGMAN_LOG to the DAG name minus ".dag" plus
// ".dagman.out". Empty in, placeholder out.
func dagmanOutName(dagFile string) string {
	return dagman.OutName(dagFile)
}

// dagRescueName is the rescue DAG DAGMan writes when nodes fail:
// DagmanUtils::RescueDagName appends ".rescue" and a three-digit number
// to the PRIMARY DAG FILE NAME -- "diamond.dag.rescue001", not
// "diamond.rescue001".
func dagRescueName(dagFile string) string {
	return dagman.RescueName(dagFile)
}

// dagFileFromAd recovers the workflow's .dag file name from the manager
// job's arguments, so the section can name the files a caller has to
// look for instead of printing a placeholder.
//
// The ad is the only place it survives: nothing stores the DAG name as
// an attribute, and the spool directory it lives in is not visible from
// here. SubmitFile writes "-Dag <name>" into an "new syntax" argument
// list, so the value is the token after -Dag.
func dagFileFromAd(ad *classad.ClassAd) string {
	raw, ok := ad.EvaluateAttrString("Arguments")
	if !ok || raw == "" {
		raw, ok = ad.EvaluateAttrString("Args")
		if !ok {
			return ""
		}
	}
	tokens := jobargs.SplitV2(raw)
	for i, tok := range tokens {
		if strings.EqualFold(tok, "-Dag") && i+1 < len(tokens) {
			return tokens[i+1]
		}
	}
	return ""
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

// isDagManJob reports whether a job ad belongs to a DAGMan manager job,
// which is what makes get_job add the workflow section.
//
// Two tests, because neither alone covers the life of a workflow.
// DAG_NodesTotal is conclusive but only appears once DAGMan has parsed
// the DAG and published -- so a workflow that is still spooling, or held
// and never going to start, would not be recognized by it, which is
// precisely when a caller most needs to be told what they are looking
// at. Cmd is there from the moment the job is submitted; it is the
// access point's condor_dagman path, so it is matched on the basename
// rather than compared to this server's idea of where DAGMan lives.
func isDagManJob(ad *classad.ClassAd) bool {
	if _, ok := ad.EvaluateAttrInt("DAG_NodesTotal"); ok {
		return true
	}
	cmd, ok := ad.EvaluateAttrString("Cmd")
	if !ok {
		return false
	}
	cmd = strings.TrimSpace(cmd)
	return cmd == "condor_dagman" || strings.HasSuffix(cmd, "/condor_dagman")
}

// appendDagSection is what get_job does with a job ad that turns out to
// be a DAGMan manager: it adds the workflow report to the text and the
// progress counts to the structured result, and leaves an ordinary job's
// answer exactly as it was.
//
// Split out from the handler so both halves of that decision -- the
// section appears for a workflow, and does NOT appear for anything else
// -- can be tested without a schedd.
func appendDagSection(text string, structured map[string]interface{}, cluster int, ad *classad.ClassAd) string {
	if !isDagManJob(ad) {
		return text
	}
	structured["dag"] = dagStructuredFields(ad)
	return text + renderDagSection(cluster, ad)
}

// renderDagSection turns a DAGMan job ad into the workflow report
// get_job appends to a manager job's answer.
//
// Split out from the handler so the decisions in it -- above all,
// whether a held manager job is spooling or stuck -- can be exercised
// against a crafted ad. Those two states are the same JobStatus and
// differ only in a hold code, and getting them confused tells a caller to
// keep waiting on a workflow that is already dead.
func renderDagSection(cluster int, ad *classad.ClassAd) string {
	dagFile := dagFileFromAd(ad)
	total, hasTotal := ad.EvaluateAttrInt("DAG_NodesTotal")
	var sb strings.Builder
	sb.WriteString("\n--- DAGMan workflow ---\n")
	if dagFile != "" {
		fmt.Fprintf(&sb, "DAG file: %s\n", dagFile)
	}
	status, _ := ad.EvaluateAttrInt("JobStatus")

	// A finished manager job means the results are sitting in its spool,
	// which is the one place a caller does not think to look: the node
	// jobs' own sandboxes are long gone, and their output came back here.
	finish := func() string {
		fmt.Fprintf(&sb, "\nNode jobs still in the queue: query_jobs(constraint=%q). "+
			"Finished ones: query_job_archive with the same constraint; a failed node's job carries "+
			"DAGNodeName and its exit code / HoldReason.\n", dagNodeConstraint(cluster))
		if status == 4 {
			fmt.Fprintf(&sb, "%s\n", dagOutputAdvice(cluster, dagFile))
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
		fmt.Fprintf(&sb, "DAGMan wrote a rescue DAG (%s) into the workflow's spool listing "+
			"the nodes that still need to run. To resume, fetch it with get_job_output and submit a new "+
			"workflow with the same dag_name, passing the rescue file in files.\n", dagRescueName(dagFile))
	}
	if futile, ok := ad.EvaluateAttrInt("DAG_NodesFutile"); ok && futile > 0 {
		fmt.Fprintf(&sb, "%d node(s) are futile: they can never run because an ancestor failed.\n", futile)
	}
	return finish()
}

// dagStructuredFields is the workflow's progress as structured data,
// which get_job files under "dag".
//
// The manager job's own status travels with the DAG's, because they
// answer different questions and a caller needs both: a DAG that reports
// no progress because DAGMan has not started yet is waiting, and one
// that reports none because the manager already exited is finished or
// broken. Without this the two are indistinguishable. The hold code is
// what separates "spooling, will clear" from "stuck".
func dagStructuredFields(ad *classad.ClassAd) map[string]interface{} {
	out := map[string]interface{}{}
	// These two are named, not derived: lower-casing the attribute is how
	// every DAG_* key is spelled, and it would turn JobStatus into
	// "jobstatus" rather than the "job_status" the schema publishes.
	for key, attr := range map[string]string{"job_status": "JobStatus", "hold_reason_code": "HoldReasonCode"} {
		if v, ok := ad.EvaluateAttrInt(attr); ok {
			out[key] = v
		}
	}
	for _, attr := range []string{
		"DAG_NodesTotal", "DAG_NodesDone", "DAG_NodesReady", "DAG_NodesQueued",
		"DAG_NodesFailed", "DAG_NodesUnready", "DAG_NodesFutile", "DAG_Status",
		"DAG_JobsIdle", "DAG_JobsRunning", "DAG_JobsHeld", "DAG_JobsCompleted",
	} {
		if v, ok := ad.EvaluateAttrInt(attr); ok {
			out[strings.ToLower(attr)] = v
		}
	}
	if f := dagFileFromAd(ad); f != "" {
		out["dag_file"] = f
	}
	return out
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

// instrumentRequested reads submit_dag's instrument flag, which is the
// one boolean argument this package has whose absence does not mean
// false: a workflow nobody said anything about is instrumented, and the
// flag exists only to turn that OFF.
//
// It accepts the string forms for the same reason boolFlag does -- a
// model told the parameter is a boolean still sends "false" often
// enough that reading it as "not false" would make the escape hatch look
// broken to exactly the caller who needs it.
func instrumentRequested(args map[string]interface{}) bool {
	switch v := args["instrument"].(type) {
	case bool:
		return v
	case string:
		if strings.EqualFold(v, "false") || v == "0" {
			return false
		}
	}
	return true
}

// dagmanLayout is what the access point's own configuration says about
// its DAGMan installation, asked of the SCHEDD once per access point.
//
// Asked of the schedd because both halves are properties of the machine
// this server submits TO and not of the machine it runs on -- which is
// exactly why HTTP_API_DAGMAN_PATH had to be configured by hand before.
// Everything about it fails soft: an error, an unset knob or an empty
// value all mean "unknown", and unknown means the package defaults.
func (s *Server) dagmanLayout(ctx context.Context) dagman.Layout {
	return s.dagmanLayouts.Get(ctx, routedSchedd(ctx), func(ctx context.Context) dagman.Layout {
		if s.dagmanLayoutFn != nil {
			return s.dagmanLayoutFn(ctx)
		}
		// A nil *Schedd must not reach DiscoverLayout as an interface:
		// a typed nil is not nil, and the method call would panic
		// instead of falling back to the defaults.
		schedd := s.scheddFor(ctx)
		if schedd == nil {
			return dagman.Layout{}
		}
		var debug func(string, ...any)
		if s.logger != nil {
			debug = func(msg string, args ...any) {
				s.logger.Debug(logging.DestinationMCP, msg, args...)
			}
		}
		return dagman.DiscoverLayout(ctx, schedd, debug)
	})
}
