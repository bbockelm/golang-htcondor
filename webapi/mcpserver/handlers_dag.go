package mcpserver

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing/fstest"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/version"
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

// dagTools are the workflow tools, kept together so the catalogue entry
// and the dispatch stay in one place.
func dagTools() []Tool {
	return []Tool{
		{
			Name: "submit_dag",
			Description: "Submit a DAGMan workflow: a graph of jobs with dependencies, retries and pre/post scripts. " +
				"Write the workflow in ordinary DAG syntax and pass it as `dag`. " +
				"Prefer inline SUBMIT-DESCRIPTION blocks so the whole workflow is one self-contained file with nothing else to stage:\n" +
				"  SUBMIT-DESCRIPTION work {\\n    executable = /bin/sh\\n    transfer_executable = false\\n    arguments = \\\"-c 'echo hi'\\\"\\n  }\\n" +
				"  JOB A work\\n  JOB B work\\n  PARENT A CHILD B\n" +
				"Anything the DAG references by file name -- separate .sub files, PRE/POST scripts, small inputs -- goes in `files` " +
				"as name -> contents, in this same call. The DAG is parsed before submission and the workflow is refused if it " +
				"cannot start (a cycle, a PARENT naming an undeclared node, a missing SPLICE or INCLUDE); anything more doubtful " +
				"comes back as a note. " +
				"Do NOT inline bulk data: give node jobs HTTP/HTTPS URLs in transfer_input_files so the execute machines fetch it " +
				"directly. If bulk data must go through the access point, name it in `additional_input_files` here and upload it " +
				"with create_input_upload_url afterwards -- a file not named at submit time is silently dropped. " +
				"A SUBDAG whose .dag file an earlier node generates is expected and supported: only its name is needed now. " +
				"Track the running workflow with dag_status, and watch_jobs on the returned cluster id.",
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
							"small inputs. Names must be bare (no directories): the spool directory is flat.",
						"additionalProperties": map[string]interface{}{"type": "string"},
					},
					"dag_name": map[string]interface{}{
						"type":        "string",
						"description": "File name to write the DAG as (default \"workflow.dag\")",
					},
					"additional_input_files": map[string]interface{}{
						"type": "array",
						"description": "Names of files that will be uploaded after submission via create_input_upload_url. " +
							"Naming them here is required: the schedd fixes the set of acceptable file names at submit time and " +
							"silently discards anything else.",
						"items": map[string]interface{}{"type": "string"},
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
			Name: "dag_status",
			Description: "Report progress of a running DAGMan workflow: how many nodes are done, ready, queued, failed or " +
				"unready, the state of its node jobs, and whether the DAG is in recovery. DAGMan publishes these into its own " +
				"job ad, so this is a single cheap query rather than a log scrape. Pass the cluster id that submit_dag returned.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"job_id": map[string]interface{}{
						"type":        "string",
						"description": "The DAGMan job's cluster id, as returned by submit_dag (\"1234\" or \"1234.0\")",
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
	declared, err := stringSliceArg(args, "additional_input_files")
	if err != nil {
		return nil, err
	}

	report := dagman.Analyze(dagman.Input{
		DagName:  dagName,
		Dag:      dagText,
		Files:    files,
		Declared: declared,
	})
	if report.Fatal() {
		return nil, fmt.Errorf("this workflow cannot start:\n  - %s",
			strings.Join(report.Errors(), "\n  - "))
	}

	submitFile, err := dagman.SubmitFile(dagman.SubmitOptions{
		DagName:       dagName,
		DagmanPath:    s.dagmanPath,
		CondorVersion: version.CondorVersionString(version.GetBuild().BuildID()),
		InputFiles:    report.Required,
		BatchName:     stringArg(args, "batch_name"),
		MaxIdle:       intArg(args, "max_idle", 0),
		MaxJobs:       intArg(args, "max_jobs", 0),
		MaxPre:        intArg(args, "max_pre", 0),
		MaxPost:       intArg(args, "max_post", 0),
		ExtraEnv:      s.dagmanEnv,
		Append:        stringArg(args, "append"),
	})
	if err != nil {
		return nil, err
	}

	if boolFlag(args, "dry_run") {
		return dagDryRunResult(dagName, submitFile, report), nil
	}

	// Site submit policy reaches the manager job the way it reaches every
	// other submission. It does NOT reach the node jobs: DAGMan submits
	// those itself, on the access point, long after this call returns.
	// Applying it to the node descriptions we were handed is the only
	// chance there is, so it happens here too -- otherwise an operator's
	// mandatory accounting group would cover the one job that does no
	// work and none of the ones that do.
	staged := fstest.MapFS{
		dagName: &fstest.MapFile{Data: []byte(dagText), Mode: 0o644},
	}
	for name, body := range files {
		staged[name] = &fstest.MapFile{Data: []byte(s.policyForStagedFile(name, body)), Mode: stagedMode(name)}
	}

	schedd := s.getSchedd()
	clusterID, procAds, err := schedd.SubmitRemote(ctx, s.submitPolicy.Apply(submitFile))
	if err != nil {
		return nil, fmt.Errorf("submitting the DAGMan job failed: %w", err)
	}
	if err := schedd.SpoolJobFilesFromFS(ctx, procAds, staged); err != nil {
		jobID := fmt.Sprintf("%d.0", clusterID)
		if _, rmErr := schedd.RemoveJobsByID(ctx, []string{jobID}, "spooling the workflow failed"); rmErr != nil {
			s.logger.Warn(logging.DestinationMCP, "could not remove the DAGMan job after a spool failure",
				"job_id", jobID, "error", rmErr)
		}
		return nil, fmt.Errorf("the schedd accepted the DAGMan job but spooling the workflow failed: %w", err)
	}

	return dagSubmitResult(clusterID, dagName, report, declared), nil
}

// stagedMode makes scripts executable. A PRE/POST script spooled 0644
// fails with EACCES the moment DAGMan tries to run it, and the error
// surfaces as a node failure with no obvious cause.
func stagedMode(name string) fs.FileMode {
	if strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".py") || strings.HasSuffix(name, ".pl") {
		return 0o755
	}
	return 0o644
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

func dagDryRunResult(dagName, submitFile string, report *dagman.Report) map[string]interface{} {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Dry run: nothing was submitted.\n\nDAG file: %s\n", dagName)
	writeDagNotes(&sb, report, nil)
	fmt.Fprintf(&sb, "\nThe DAGMan manager job would be submitted as:\n\n%s", submitFile)
	structured := map[string]interface{}{
		"dry_run":     true,
		"dag_name":    dagName,
		"submit_file": submitFile,
		"input_files": report.Required,
		"notes":       findingStrings(report),
		"deferred":    report.Deferred,
	}
	return withStructured(map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": sb.String()}},
		"metadata": structured,
	}, structured)
}

func dagSubmitResult(clusterID int, dagName string, report *dagman.Report, declared []string) map[string]interface{} {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Submitted DAGMan workflow %s as cluster %d.\n", dagName, clusterID)
	fmt.Fprintf(&sb, "Staged into the workflow's spool directory: %s\n", strings.Join(report.Required, ", "))
	writeDagNotes(&sb, report, declared)
	fmt.Fprintf(&sb, "\nFollow it with dag_status(job_id=\"%d\"), or watch_jobs on cluster %d to be told when it finishes.\n",
		clusterID, clusterID)
	fmt.Fprintf(&sb, "Removing job %d.0 removes the whole workflow, including node jobs already running.\n", clusterID)

	structured := map[string]interface{}{
		"cluster_id":  clusterID,
		"job_id":      fmt.Sprintf("%d.0", clusterID),
		"dag_name":    dagName,
		"input_files": report.Required,
		"notes":       findingStrings(report),
		"deferred":    report.Deferred,
	}
	return withStructured(map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": sb.String()}},
		"metadata": structured,
	}, structured)
}

// writeDagNotes renders the analysis. Outstanding uploads come last and
// as an instruction, because that is the step a caller drops: the
// workflow is in the queue and looks submitted, but it cannot run until
// the bytes arrive.
func writeDagNotes(sb *strings.Builder, report *dagman.Report, declared []string) {
	if notes := findingStrings(report); len(notes) > 0 {
		sb.WriteString("\nNotes:\n")
		for _, n := range notes {
			fmt.Fprintf(sb, "  - %s\n", n)
		}
	}
	if len(report.Deferred) > 0 {
		fmt.Fprintf(sb, "\nExpected to be produced while the workflow runs: %s\n",
			strings.Join(report.Deferred, ", "))
	}
	if len(declared) > 0 {
		files := append([]string(nil), declared...)
		sort.Strings(files)
		fmt.Fprintf(sb, "\nSTILL REQUIRED: you named %s as coming later. The workflow is held until they arrive; "+
			"upload them with create_input_upload_url.\n", strings.Join(files, ", "))
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

// toolDagStatus reports a workflow's progress.
func (s *Server) toolDagStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	jobID := strings.TrimSpace(stringArg(args, "job_id"))
	if jobID == "" {
		return nil, fmt.Errorf("job_id is required: the cluster id submit_dag returned")
	}
	cluster := jobID
	if i := strings.Index(cluster, "."); i >= 0 {
		cluster = cluster[:i]
	}

	scope, ok := s.ownerScope(ctx, tierRead)
	if !ok {
		return nil, fmt.Errorf("no authenticated caller to scope this query to")
	}
	constraint := fmt.Sprintf("ClusterId == %s", cluster)
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
		return nil, fmt.Errorf("no job with cluster id %s %s. "+
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
func renderDagStatus(cluster string, scope OwnerScope, ad *classad.ClassAd) string {
	total, hasTotal := ad.EvaluateAttrInt("DAG_NodesTotal")
	var sb strings.Builder
	fmt.Fprintf(&sb, "DAGMan workflow %s.0 %s\n", cluster, scope.Note())
	if name, ok := ad.EvaluateAttrString("JobBatchName"); ok && name != "" {
		fmt.Fprintf(&sb, "batch name: %s\n", name)
	}
	status, _ := ad.EvaluateAttrInt("JobStatus")
	fmt.Fprintf(&sb, "manager job status: %s\n", describeJobStatus(int(status)))

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
		return sb.String()
	}

	if !hasTotal {
		if status == 5 {
			sb.WriteString("\nThe workflow is held while its input spools, which clears on its own once the " +
				"files arrive. If you named files in additional_input_files, it is waiting for those.\n")
		} else {
			sb.WriteString("\nDAGMan has not published progress yet. It publishes into its own job ad once it " +
				"has parsed the DAG and started running, so this is normal for a workflow that was just " +
				"submitted.\n")
		}
		return sb.String()
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
			"constraint DAGManJobId == %s shows how each node job ended.\n", failed, cluster)
	}
	if futile, ok := ad.EvaluateAttrInt("DAG_NodesFutile"); ok && futile > 0 {
		fmt.Fprintf(&sb, "%d node(s) are futile: they can never run because an ancestor failed.\n", futile)
	}
	return sb.String()
}

// appendNodeJobs lists the workflow's node jobs. They are linked to the
// manager by DAGManJobId, which DAGMan sets on every job it submits.
func (s *Server) appendNodeJobs(ctx context.Context, sb *strings.Builder, cluster string, scope OwnerScope) {
	constraint := fmt.Sprintf("DAGManJobId == %s", cluster)
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

func dagStatusResult(text, cluster string, ad interface {
	EvaluateAttrInt(string) (int64, bool)
}) map[string]interface{} {
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

// stringSliceArg reads a JSON array of strings.
func stringSliceArg(args map[string]interface{}, key string) ([]string, error) {
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array of file names", key)
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s must contain only strings, not %T", key, v)
		}
		if strings.ContainsAny(s, `/\`) {
			return nil, fmt.Errorf("%s: %q must be a bare file name", key, s)
		}
		out = append(out, s)
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
