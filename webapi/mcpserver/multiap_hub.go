package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Multi-AP mode: the tools served over the federation hub, or routed to
// one AP, beyond the job reads and actions.

// multiAPHubTools are served in multi-AP mode: the watch tools by their
// single-AP implementations (one evaluator over the hub, for every AP),
// analyze_issues over the hub, the epoch and transfer history tools by
// multiEpochsTool, and query_pool against the collector the APs share.
var multiAPHubTools = map[string]bool{
	"watch_jobs":       true,
	"check_watches":    true,
	"cancel_watch":     true,
	"create_watch_url": true,
	// Every AP's held jobs and run attempts, from the hub.
	"analyze_issues": true,
	// From the hub's epoch_history, or routed to one AP's schedd.
	"query_job_epochs":       true,
	"query_transfer_history": true,
	// The pool's collector, which every AP shares.
	"query_pool": true,
}

// multiAPWatchNote is what watch_jobs adds on a multi-AP server.
const multiAPWatchNote = "\n\nOn this server a watch covers your jobs on every access point: add ScheddName to the constraint " +
	"to watch one. Each job it reports carries its access point (schedd); the same cluster.proc on two access points is " +
	"two jobs. A job on an access point whose data is not current is not reported finished until that data catches up " +
	"or its history record arrives."

// multiAPEpochsNote is what the epoch and transfer history tools add.
const multiAPEpochsNote = "\n\nOn this server it covers your records on every access point when the federation hub keeps run-attempt " +
	"history; pass job_id (or schedd) to read one job (or one access point). Where the hub does not keep it, a job_id or " +
	"schedd is required and the read goes to that access point. Each record carries its access point (ScheddName)."

// multiAPHubToolDef adjusts a served tool's description and schema for
// multi-AP mode.
func multiAPHubToolDef(t Tool) Tool {
	switch t.Name {
	case "watch_jobs":
		t.Description += multiAPWatchNote
	case "query_job_epochs", "query_transfer_history":
		t.Description += multiAPEpochsNote
		schema := maps.Clone(t.InputSchema)
		if props, ok := schema["properties"].(map[string]interface{}); ok {
			props = maps.Clone(props)
			props["job_id"] = map[string]interface{}{
				"type":        "string",
				"description": "One job's records, by the job_id query_jobs returns (e.g. 123.0@ap1.example.org).",
			}
			props["schedd"] = scheddArgSchema
			schema["properties"] = props
		}
		t.InputSchema = schema
	}
	return t
}

// multiEpochsTool serves query_job_epochs and query_transfer_history in
// multi-AP mode: from the hub's epoch_history when it federates it, else
// routed to the AP that the job_id or schedd names; with neither, a read
// the hub cannot serve is refused rather than fanned out to every AP's
// history file.
func (s *Server) multiEpochsTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	user, err := s.multiCaller(ctx)
	if err != nil {
		return nil, err
	}
	source, typeName := htcondor.HistorySourceJobEpoch, "job epochs"
	if name == "query_transfer_history" {
		source, typeName = htcondor.HistorySourceTransfer, "transfer history"
	}
	var id *jobid.ID
	if text := stringArg(args, "job_id"); text != "" {
		parsed, err := s.multi.Codec.Parse(text)
		if err != nil {
			return nil, fmt.Errorf("invalid job_id: %w", err)
		}
		resolved, err := s.multi.ResolveJob(ctx, user, parsed)
		if cands, ok := multiap.IsAmbiguous(err); ok {
			b, _ := json.Marshal(cands)
			return nil, fmt.Errorf("%w. Candidates (pass one job_id): %s", err, b)
		}
		if err != nil {
			return nil, err
		}
		id = &resolved
	}
	schedd := stringArg(args, "schedd")
	if id != nil && schedd != "" && !strings.EqualFold(schedd, id.Schedd) {
		return nil, fmt.Errorf("job_id %s is not on %s; pass one", s.multi.Codec.Format(*id), schedd)
	}
	var adTypes []string
	if source == htcondor.HistorySourceTransfer {
		adTypes = multiap.TransferAdTypes
		if raw, ok := args["transfer_types"].([]interface{}); ok && len(raw) > 0 {
			adTypes = nil
			for _, v := range raw {
				t, _ := v.(string)
				if t = strings.TrimSuffix(strings.ToUpper(t), "_FILES"); t == "INPUT" || t == "OUTPUT" || t == "CHECKPOINT" {
					adTypes = append(adTypes, t)
				}
			}
		}
	}

	if s.multi.Hub.Federates(multiap.TableEpochHistory) {
		limit := 50
		if v, ok := args["limit"].(float64); ok {
			limit = int(v)
		}
		limit, _ = clampToolLimit(limit)
		projection, note := projectionOrDefault(stringListArg(args, "projection"), defaultAttrsFor(source))
		rows, res, err := s.multi.ListEpochs(ctx, multiap.EpochRequest{
			User: user, Constraint: stringArg(args, "constraint"), Projection: projection, Limit: limit,
			Schedd: schedd, Job: id, AdTypes: adTypes,
		})
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
		itemsJSON, _ := json.Marshal(items)
		text := fmt.Sprintf("Found %d %s record(s):\n%s\n", len(items), typeName, itemsJSON)
		if res.HasMore {
			text += "More records match; narrow the constraint or raise limit.\n"
		}
		text += note + "\n" + sourcesNote(res.Sources) + "\n" + OwnerScope{Owner: user}.Note()
		return structuredTextResult(text, map[string]interface{}{
			"records": items, "count": len(items), "source": "hub", "has_more": res.HasMore, "sources": res.Sources,
		}), nil
	}

	target := schedd
	if id != nil {
		target = id.Schedd
	}
	if target == "" {
		return nil, fmt.Errorf("%s; pass job_id or schedd to read %s from one access point",
			multiap.ErrEpochsNotFederated.Msg, typeName)
	}
	t := multiap.Target{}
	if id != nil {
		t.ID = *id
		t.Member, err = s.multi.Route(ctx, user, *id)
	} else {
		t.Member, err = s.multi.RouteRead(ctx, user, target)
	}
	if err != nil {
		return nil, err
	}
	if s.multi.VerifyCaller != nil {
		if err := s.multi.VerifyCaller(ctx, t.Member, user); err != nil {
			return nil, err
		}
	}
	routed := maps.Clone(args)
	delete(routed, "job_id")
	delete(routed, "schedd")
	if id != nil {
		job := fmt.Sprintf("ClusterId == %d && ProcId == %d", id.Cluster, id.Proc)
		if c := strings.TrimSpace(stringArg(args, "constraint")); c != "" {
			safe, err := classadBalanced(c)
			if err != nil {
				return nil, fmt.Errorf("constraint is not a valid ClassAd expression: %w", err)
			}
			job = fmt.Sprintf("(%s) && (%s)", job, safe)
		}
		routed["constraint"] = job
	}
	result, err := s.toolQueryHistory(multiap.WithTarget(ctx, t), routed, source, typeName)
	if err != nil {
		return nil, err
	}
	if id != nil {
		return noteRoutedJob(result, s.multi.Codec.Format(*id), "", t.Member.Name), nil
	}
	if m, ok := result.(map[string]interface{}); ok {
		if sc, ok := m["structuredContent"].(map[string]interface{}); ok {
			sc["schedd"] = t.Member.Name
		}
	}
	return result, nil
}
