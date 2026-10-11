package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Multi-AP actions over MCP: a single-job tool is routed to the access
// point its job id names, and runs as it does on a single-AP server
// against that AP's schedd (scheddFor reads the route from the context).
// remove_jobs fans out to every member.

// multiAPActionTools are the single-job tools multi-AP mode serves.
var multiAPActionTools = map[string]bool{
	"remove_job":                 true,
	"hold_job":                   true,
	"release_job":                true,
	"edit_job":                   true,
	"get_job_stdout":             true,
	"get_job_stderr":             true,
	"get_job_output":             true,
	"upload_job_input":           true,
	"create_input_upload_url":    true,
	"create_output_download_url": true,
	"tail_job_output":            true,
	"exec_in_job":                true,
}

// multiAPReadOnlyActionTools change nothing on the AP; the rest of
// multiAPActionTools do (create_input_upload_url only mints, but the
// upload it enables lands through the share route, which notes it).
var multiAPReadOnlyActionTools = map[string]bool{
	"get_job_stdout":             true,
	"get_job_stderr":             true,
	"get_job_output":             true,
	"tail_job_output":            true,
	"create_output_download_url": true,
	"create_input_upload_url":    true,
}

// multiAPClusterTools take a bare cluster ("123") to mean every proc of
// it, as they do on a single-AP server.
var multiAPClusterTools = map[string]bool{
	"upload_job_input":           true,
	"create_input_upload_url":    true,
	"create_output_download_url": true,
}

// routedSchedd is the AP a call was routed to, or "".
func routedSchedd(ctx context.Context) string {
	if t, ok := multiap.TargetFrom(ctx); ok {
		return t.Member.Name
	}
	return ""
}

// singleJobTool returns the single-AP implementation of a routed tool.
func (s *Server) singleJobTool(name string) func(context.Context, map[string]interface{}) (interface{}, error) {
	switch name {
	case "remove_job":
		return s.toolRemoveJob
	case "hold_job":
		return s.toolHoldJob
	case "release_job":
		return s.toolReleaseJob
	case "edit_job":
		return s.toolEditJob
	case "get_job_stdout":
		return s.toolGetJobStdout
	case "get_job_stderr":
		return s.toolGetJobStderr
	case "get_job_output":
		return s.toolGetJobOutputFiles
	case "upload_job_input":
		return s.toolUploadJobInput
	case "create_input_upload_url":
		return s.toolCreateInputUploadURL
	case "create_output_download_url":
		return s.toolCreateOutputDownloadURL
	case "tail_job_output":
		return s.toolTailJobOutput
	case "exec_in_job":
		return s.toolExecInJob
	}
	return nil
}

// routeJobArgs reads the job a tool call names -- job_id through the
// codec, or schedd with cluster and proc -- and routes it. The id must
// be complete: a bare cluster.proc is refused with the caller's
// candidates, never guessed. It returns the routed context, and args with
// job_id rewritten to the local cluster.proc the single-AP tool parses.
func (s *Server) routeJobArgs(ctx context.Context, name string, args map[string]interface{}) (context.Context, map[string]interface{}, jobid.ID, error) {
	user, err := s.multiCaller(ctx)
	if err != nil {
		return nil, nil, jobid.ID{}, err
	}
	var id jobid.ID
	text := stringArg(args, "job_id")
	switch {
	case text != "":
		if id, err = s.multi.Codec.Parse(text); err != nil {
			return nil, nil, jobid.ID{}, fmt.Errorf("invalid job_id: %w", err)
		}
	default:
		c, okc := args["cluster"].(float64)
		if !okc {
			return nil, nil, jobid.ID{}, fmt.Errorf("job_id is required: the complete id from query_jobs, e.g. 123.0@ap1.example.org")
		}
		p, _ := args["proc"].(float64)
		id = jobid.ID{Cluster: int64(c), Proc: int64(p)}
	}
	if !id.Complete() {
		id.Schedd = stringArg(args, "schedd")
	}
	m, err := s.multi.Route(ctx, user, id)
	if err != nil {
		if cands := multiap.CandidatesOf(err); len(cands) > 0 {
			b, _ := json.Marshal(cands)
			return nil, nil, jobid.ID{}, fmt.Errorf("%w. Candidates (pass one job_id): %s", err, b)
		}
		return nil, nil, jobid.ID{}, err
	}
	id = id.WithSchedd(m.Name)

	local := fmt.Sprintf("%d.%d", id.Cluster, id.Proc)
	if multiAPClusterTools[name] && text != "" && s.multi.Codec.Format(id) != text {
		// The codec read an id it does not render back the same way: a
		// cluster with no proc ("123@ap1"), which the codec completes
		// to proc 0. These tools read a bare cluster as every proc of
		// it, and keep doing so here.
		local = fmt.Sprintf("%d", id.Cluster)
	}
	routed := maps.Clone(args)
	routed["job_id"] = local
	delete(routed, "schedd")
	return multiap.WithTarget(ctx, multiap.Target{Member: m, ID: id}), routed, id, nil
}

// multiActionTool runs a single-job tool against its job's AP.
func (s *Server) multiActionTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	ctx, routed, id, err := s.routeJobArgs(ctx, name, args)
	if err != nil {
		return nil, err
	}
	if !multiAPReadOnlyActionTools[name] {
		// Until the hub has seen this change, a bulk action must not skip
		// the AP on the hub's word.
		s.multi.NoteWrite(id.Schedd)
	}
	result, err := s.singleJobTool(name)(ctx, routed)
	if err != nil {
		return nil, err
	}
	return noteRoutedJob(result, s.multi.Codec.Format(id), fmt.Sprintf("%d.%d", id.Cluster, id.Proc), id.Schedd), nil
}

// noteRoutedJob adds the job's access point to a single-AP tool's
// answer: schedd and the complete job_id in the structured content, and
// a line naming them in the text.
func noteRoutedJob(result interface{}, full, local, schedd string) interface{} {
	m, ok := result.(map[string]interface{})
	if !ok {
		return result
	}
	for _, key := range []string{"structuredContent", "metadata"} {
		sc, ok := m[key].(map[string]interface{})
		if !ok {
			continue
		}
		sc["schedd"] = schedd
		if v, ok := sc["job_id"].(string); ok && v == local {
			sc["job_id"] = full
		}
	}
	if content, ok := m["content"].([]map[string]interface{}); ok && len(content) > 0 {
		if t, ok := content[0]["text"].(string); ok {
			content[0]["text"] = t + fmt.Sprintf("\n[job %s, on access point %s]", full, schedd)
		}
	}
	return m
}

// multiRemoveJobsTool is remove_jobs over every AP.
func (s *Server) multiRemoveJobsTool(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	llmConstraint := stringArg(args, "constraint")
	if llmConstraint == "" {
		return nil, fmt.Errorf("constraint is required")
	}
	reason := stringArg(args, "reason")
	if reason == "" {
		reason = "Removed via MCP bulk operation"
	}
	user, err := s.multiCaller(ctx)
	if err != nil {
		return nil, err
	}
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	routed := func(c context.Context, m apregistry.Member) context.Context {
		return multiap.WithTarget(c, multiap.Target{Member: m})
	}
	rep, err := s.multi.FanOut(ctx, multiap.BulkRequest{
		User: user, Owner: ownerFromActor(actor), Constraint: llmConstraint,
		AllUsers: func(ap string) bool {
			m, ok := s.multi.Registry.Get(ap)
			return ok && s.allowsAllUsers(routed(ctx, m), actor, tierMutate)
		},
		FreshWithin: s.multi.BulkFresh,
	}, func(legCtx context.Context, m apregistry.Member) (multiap.BulkOutcome, error) {
		apCtx := routed(legCtx, m)
		constraint, ok := s.scopeToOwner(apCtx, llmConstraint, tierMutate)
		if !ok {
			return multiap.BulkOutcome{}, fmt.Errorf("authentication required")
		}
		res, err := s.scheddFor(apCtx).RemoveJobs(apCtx, constraint, reason)
		var refused *htcondor.JobActionRefusedError
		switch {
		case errors.As(err, &refused) && refused.Results != nil:
			res, err = refused.Results, nil
		case errors.Is(err, htcondor.ErrNoJobsMatched):
			return multiap.BulkOutcome{}, nil
		}
		if err != nil {
			return multiap.BulkOutcome{}, err
		}
		return multiap.BulkOutcome{Counts: multiap.CountsOf(res)}, nil
	})
	if err != nil {
		return nil, err
	}
	structured := map[string]interface{}{
		"action":            "remove",
		"constraint":        llmConstraint,
		"total":             rep.Totals.Total,
		"success":           rep.Totals.Success,
		"permission_denied": rep.Totals.PermissionDenied,
		"not_found":         rep.Totals.NotFound,
		"already_done":      rep.Totals.AlreadyDone,
		"bad_status":        rep.Totals.BadStatus,
		"complete":          rep.Complete,
		"access_points":     rep.APs,
	}
	text := fmt.Sprintf("Removed %d of %d job(s) matching constraint '%s' across %d access point(s).\nPer access point: %s",
		rep.Totals.Success, rep.Totals.Total, llmConstraint, len(rep.APs), rep.BulkSummary())
	if !rep.Complete {
		text += "\nNot every access point was reached; jobs there were not removed. Retry once it is back."
	}
	return withStructured(map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": text}},
		"metadata": structured,
	}, structured), nil
}

var actionScheddArgSchema = map[string]interface{}{
	"type":        "string",
	"description": "The access point the job is on (its schedd name), when job_id is a bare cluster.proc.",
}

// multiAPActionNote is appended to a routed tool's description.
const multiAPActionNote = " On this server, which fronts several access points, job_id must be the complete id " +
	"query_jobs returns (e.g. 123.0@ap1.example.org), or pass schedd alongside a bare 123.0; " +
	"a bare cluster.proc alone is refused with the candidates."

// multiAPActionToolDef adapts a single-AP tool definition to multi-AP
// mode: the description says job ids must be complete, and the schema
// gains an optional schedd.
func multiAPActionToolDef(t Tool) Tool {
	switch {
	case t.Name == "remove_jobs":
		t.Description += " Runs on every access point this server fronts and reports the outcome for each."
		return t
	case !multiAPActionTools[t.Name]:
		return t
	}
	t.Description += multiAPActionNote
	schema := maps.Clone(t.InputSchema)
	if props, ok := schema["properties"].(map[string]interface{}); ok {
		props = maps.Clone(props)
		props["schedd"] = actionScheddArgSchema
		schema["properties"] = props
	}
	t.InputSchema = schema
	return t
}
