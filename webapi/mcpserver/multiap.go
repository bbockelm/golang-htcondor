package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Multi-AP mode: the server fronts every access point matching a
// collector constraint, and serves only reads, from the federation hub.
//
// The catalogue is an ALLOWLIST (multiAPTools). A tool not named there is
// neither listed nor callable: it would act on "the" schedd, and in this
// mode there is none. getSchedd counts any call that reaches it anyway.

// multiAPReadTools are served by the multi-AP implementations below.
var multiAPReadTools = map[string]bool{
	"query_jobs":         true,
	"get_job":            true,
	"query_job_archive":  true,
	"aggregate_jobs":     true,
	"list_access_points": true,
}

// multiAPPassthroughTools need no schedd and are served as in single-AP
// mode.
var multiAPPassthroughTools = map[string]bool{
	"whoami":      true,
	"get_version": true,
	"doc_guide":   true,
	"skills_list": true,
	"skills_get":  true,
}

// multiAPToolAllowed reports whether multi-AP mode serves a tool.
func multiAPToolAllowed(name string) bool {
	return multiAPReadTools[name] || multiAPPassthroughTools[name] || isCondorDocTool(name)
}

// errMultiAPTool refuses a tool multi-AP mode does not serve.
func errMultiAPTool(name string) error {
	return fmt.Errorf("the %q tool is not available on this multi-access-point server yet; "+
		"it serves query_jobs, get_job, query_job_archive, aggregate_jobs and list_access_points", name)
}

// multiAPCatalog replaces the single-AP catalogue: passthrough tools as
// they are, the read tools in their multi-AP form, nothing else.
func multiAPCatalog(tools []Tool) []Tool {
	out := make([]Tool, 0, len(tools))
	for _, t := range tools {
		if multiAPToolAllowed(t.Name) && !multiAPReadTools[t.Name] {
			out = append(out, t)
		}
	}
	return append(out, multiAPToolDefs()...)
}

var scheddArgSchema = map[string]interface{}{
	"type":        "string",
	"description": "Limit the answer to one access point, by its schedd name (see list_access_points).",
}

func multiAPToolDefs() []Tool {
	listProps := func(extra string) map[string]interface{} {
		return map[string]interface{}{
			"constraint": map[string]interface{}{"type": "string", "description": "ClassAd constraint (default: all of your " + extra + ")."},
			"projection": map[string]interface{}{
				"type": "array", "items": map[string]interface{}{"type": "string"},
				"description": describeProjection(defaultJobAttrs),
			},
			"limit":      map[string]interface{}{"type": "integer", "description": "Maximum rows (default 50, ceiling 500)."},
			"page_token": map[string]interface{}{"type": "string", "description": "next_page_token from the previous answer, to continue."},
			"schedd":     scheddArgSchema,
		}
	}
	return []Tool{
		{
			Name: "query_jobs",
			Description: "List YOUR jobs in the queue on every access point this server fronts. Each job carries schedd, cluster and proc " +
				"(a job id is all three: the same cluster.proc exists on different access points) and job_id, the single-token form get_job accepts. " +
				"The answer's sources block lists access points whose data is not current.",
			InputSchema: map[string]interface{}{"type": "object", "properties": listProps("queued jobs")},
		},
		{
			Name: "query_job_archive",
			Description: "List YOUR completed jobs on every access point this server fronts, newest first. " +
				"Each record carries schedd, cluster, proc and job_id; continue with next_page_token.",
			InputSchema: map[string]interface{}{"type": "object", "properties": listProps("completed jobs")},
		},
		{
			Name: "get_job",
			Description: "Read one of YOUR jobs, queued or completed. Pass job_id as returned by query_jobs (\"123.0@ap1.example.org\"), " +
				"or schedd, cluster and proc. A bare \"123.0\" works only if exactly one access point has that job of yours; " +
				"otherwise the answer lists the candidates.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"job_id":  map[string]interface{}{"type": "string", "description": "The job's id, e.g. 123.0@ap1.example.org."},
					"schedd":  scheddArgSchema,
					"cluster": map[string]interface{}{"type": "integer"},
					"proc":    map[string]interface{}{"type": "integer"},
				},
			},
		},
		{
			Name: "aggregate_jobs",
			Description: "Count YOUR jobs (table \"jobs\") or completed jobs (table \"history\") across every access point, optionally grouped. " +
				"Group by ScheddName for a per-access-point count.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"table":      map[string]interface{}{"type": "string", "enum": []string{"jobs", "history"}},
					"constraint": map[string]interface{}{"type": "string"},
					"group_by":   map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
					"schedd":     scheddArgSchema,
				},
			},
		},
		{
			Name:        "list_access_points",
			Description: "List the access points this server fronts, and whether the data for each is current.",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
	}
}

// callMultiAPTool dispatches a tool in multi-AP mode. handled is false
// for a passthrough tool, which the caller dispatches as usual.
func (s *Server) callMultiAPTool(ctx context.Context, name string, args map[string]interface{}) (result interface{}, handled bool, err error) {
	switch name {
	case "query_jobs":
		result, err = s.multiListTool(ctx, args, false)
	case "query_job_archive":
		result, err = s.multiListTool(ctx, args, true)
	case "get_job":
		result, err = s.multiGetJobTool(ctx, args)
	case "aggregate_jobs":
		result, err = s.multiAggregateTool(ctx, args)
	case "list_access_points":
		result = s.multiListAPsTool()
	default:
		if !multiAPToolAllowed(name) {
			return nil, true, errMultiAPTool(name)
		}
		return nil, false, nil
	}
	return result, true, err
}

// multiCaller is the caller's User attribute value. No admin exemption:
// cross-user reads are per AP and not part of the read-only mode.
func (s *Server) multiCaller(ctx context.Context) (string, error) {
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		return "", fmt.Errorf("authentication required: this server returns only your own jobs, and your identity could not be established")
	}
	return s.multi.UserFor(actor)
}

func stringListArg(args map[string]interface{}, key string) []string {
	raw, _ := args[key].([]interface{})
	var out []string
	for _, v := range raw {
		if s, _ := v.(string); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// rowMap renders a row for structured output: the ad's attributes plus
// schedd, cluster, proc and job_id.
func (s *Server) rowMap(r multiap.Row) (map[string]interface{}, error) {
	b, err := s.multi.RowJSON(r)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func sourcesNote(src multiap.Sources) string {
	if len(src.Degraded) == 0 {
		return fmt.Sprintf("[sources: %d access point(s), all current]", src.APs)
	}
	parts := make([]string, 0, len(src.Degraded))
	for _, d := range src.Degraded {
		p := d.Schedd + " " + d.State
		if d.StalenessSeconds != nil {
			p += fmt.Sprintf(" (%ds behind)", *d.StalenessSeconds)
		}
		parts = append(parts, p)
	}
	return fmt.Sprintf("[sources: %d access point(s), %d current; not current: %s]", src.APs, src.Fresh, strings.Join(parts, ", "))
}

func (s *Server) multiListTool(ctx context.Context, args map[string]interface{}, history bool) (interface{}, error) {
	user, err := s.multiCaller(ctx)
	if err != nil {
		return nil, err
	}
	limit := 50
	if v, ok := args["limit"].(float64); ok {
		limit = int(v)
	}
	limit, _ = clampToolLimit(limit)
	projection, _ := projectionOrDefault(stringListArg(args, "projection"), defaultJobAttrs)
	req := multiap.ListRequest{
		User: user, Constraint: stringArg(args, "constraint"), Projection: projection,
		Limit: limit, PageToken: stringArg(args, "page_token"), Schedd: stringArg(args, "schedd"),
	}
	var rows []multiap.Row
	var res *multiap.ListResult
	if history {
		rows, res, err = s.multi.ListHistory(ctx, req)
	} else {
		res, err = s.multi.ListJobs(ctx, req, func(r multiap.Row) bool {
			rows = append(rows, r)
			return true
		})
	}
	if err != nil {
		return nil, err
	}
	items := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		m, err := s.rowMap(r)
		if err != nil {
			return nil, err
		}
		items = append(items, m)
	}
	key, what := "jobs", "job(s)"
	if history {
		key, what = "records", "completed job(s)"
	}
	structured := map[string]interface{}{
		key:          items,
		"count":      len(items),
		"constraint": req.Constraint,
		"source":     "hub",
		"has_more":   res.HasMore,
		"sources":    res.Sources,
	}
	itemsJSON, _ := json.Marshal(items)
	text := fmt.Sprintf("Found %d %s:\n%s\n", len(items), what, itemsJSON)
	if res.NextPageToken != "" {
		structured["next_page_token"] = res.NextPageToken
		text += "More: pass page_token=" + res.NextPageToken + "\n"
	}
	if res.Err != nil {
		structured["error"] = res.Err.Error()
		text += "The answer stopped early: " + res.Err.Error() + "\n"
	}
	text += sourcesNote(res.Sources) + "\n" + OwnerScope{Owner: user}.Note()
	return structuredTextResult(text, structured), nil
}

func (s *Server) multiGetJobTool(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	user, err := s.multiCaller(ctx)
	if err != nil {
		return nil, err
	}
	var id jobid.ID
	if text := stringArg(args, "job_id"); text != "" {
		if id, err = s.multi.Codec.Parse(text); err != nil {
			return nil, fmt.Errorf("invalid job_id: %w", err)
		}
	} else {
		c, okc := args["cluster"].(float64)
		p, _ := args["proc"].(float64)
		if !okc {
			return nil, fmt.Errorf("job_id, or schedd with cluster and proc, is required")
		}
		id = jobid.ID{Schedd: stringArg(args, "schedd"), Cluster: int64(c), Proc: int64(p)}
	}
	res, err := s.multi.GetJob(ctx, user, id, nil)
	if cands, ok := multiap.IsAmbiguous(err); ok {
		b, _ := json.Marshal(cands)
		return nil, fmt.Errorf("%w. Candidates (pass one job_id): %s", err, b)
	}
	if err != nil {
		return nil, err
	}
	m, err := s.rowMap(res.Row)
	if err != nil {
		return nil, err
	}
	ref := s.multi.Ref(res.Row)
	structured := map[string]interface{}{
		"job": m, "job_id": ref.JobID, "schedd": ref.Schedd, "cluster": ref.Cluster, "proc": ref.Proc,
		"archived": res.Row.Archived, "source": res.Source,
	}
	jobJSON, _ := json.MarshalIndent(m, "", "  ")
	text := fmt.Sprintf("Job %s:\n%s\n", ref.JobID, jobJSON)
	if res.Row.Archived {
		text += "This job has left the queue; this is its history record.\n"
	}
	if res.Degraded != nil {
		structured["degraded"] = res.Degraded
		text += fmt.Sprintf("Access point %s is %s, so this may be out of date.\n", res.Degraded.Schedd, res.Degraded.State)
	}
	return structuredTextResult(text, structured), nil
}

func (s *Server) multiAggregateTool(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	user, err := s.multiCaller(ctx)
	if err != nil {
		return nil, err
	}
	table := stringArg(args, "table")
	if table == "" {
		table = "jobs"
	}
	groupBy := stringListArg(args, "group_by")
	rows, sources, err := s.multi.Aggregate(ctx, user, table, stringArg(args, "constraint"), groupBy, stringArg(args, "schedd"))
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Aggregate COUNT over %q (%d group(s))", table, len(rows))
	if len(groupBy) > 0 {
		fmt.Fprintf(&b, " by %s", strings.Join(groupBy, ", "))
	}
	b.WriteString(":\n")
	groups := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		if len(groupBy) > 0 {
			fmt.Fprintf(&b, "  %s = %s\n", strings.Join(r.Group, "/"), strings.Join(r.Values, ","))
		} else {
			fmt.Fprintf(&b, "  count = %s\n", strings.Join(r.Values, ","))
		}
		groups = append(groups, map[string]interface{}{"key": r.Group, "count": strings.Join(r.Values, ",")})
	}
	b.WriteString(sourcesNote(sources) + "\n" + OwnerScope{Owner: user}.Note())
	structured := aggregateStructured(groups, groupBy, table, "hub", false)
	structured["sources"] = sources
	return structuredTextResult(b.String(), structured), nil
}

func (s *Server) multiListAPsTool() interface{} {
	aps := s.multi.APs()
	sources := s.multi.Sources()
	var b strings.Builder
	fmt.Fprintf(&b, "%d access point(s):\n", len(aps))
	for _, ap := range aps {
		fmt.Fprintf(&b, "  %s: %s", ap.Schedd, ap.Hub.State)
		if ap.Hub.StalenessSeconds != nil {
			fmt.Fprintf(&b, " (%ds behind)", *ap.Hub.StalenessSeconds)
		}
		if !ap.InCollector {
			b.WriteString("; not currently advertised")
		}
		b.WriteString("\n")
	}
	return structuredTextResult(b.String(), map[string]interface{}{
		"access_points": aps, "sources": sources, "count": len(aps),
	})
}

// multiAPInstructions is the identity paragraph of the initialize text in
// multi-AP mode.
func multiAPInstructions(constraint string) string {
	return "This server fronts several HTCondor access points (the schedds matching " + constraint + "); " +
		"list_access_points names them. It is read-only for now: query_jobs, query_job_archive, get_job and aggregate_jobs " +
		"read your jobs on all of them. A job is identified by schedd, cluster and proc together: the same cluster.proc " +
		"can exist on two access points. Copy job_id from an answer rather than composing one. Answers name the access " +
		"points whose data is not current.\n\n"
}

// MultiAPScheddCalls reports how many times the single-schedd accessor
// was called in multi-AP mode. Anything but zero is a tool that escaped
// the allowlist; tests assert it.
func (s *Server) MultiAPScheddCalls() int64 { return s.multiScheddCalls.Load() }

// ToolNames lists the catalogue a caller with ctx's scopes is offered.
func (s *Server) ToolNames(ctx context.Context) []string {
	tools := s.toolsFor(ctx)
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = t.Name
	}
	return out
}
