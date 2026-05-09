package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/httpserver/chat"
)

// scheddTool is the interface a tool implementation needs satisfied
// from the surrounding Handler. Pulled to a small interface so the
// tool tests can inject a fake schedd without spinning up the whole
// HTTP server.
type scheddTool interface {
	getSchedd() *htcondor.Schedd
}

// chatTool is a small concrete struct that satisfies chat.Tool with
// fields instead of methods on a per-tool type. Cuts boilerplate —
// every tool below is a `chatTool{...}` literal plus an Execute
// closure.
type chatTool struct {
	name        string
	description string
	schema      json.RawMessage
	clientSide  bool
	confirm     bool
	exec        func(ctx context.Context, actor string, input json.RawMessage) (string, error)
}

func (t *chatTool) Name() string                 { return t.name }
func (t *chatTool) Description() string          { return t.description }
func (t *chatTool) InputSchema() json.RawMessage { return t.schema }
func (t *chatTool) ClientSide() bool             { return t.clientSide }
func (t *chatTool) RequiresConfirmation() bool   { return t.confirm }
func (t *chatTool) Execute(ctx context.Context, actor string, in json.RawMessage) (string, error) {
	if t.exec == nil {
		// Client-side tool: the engine never calls Execute on a
		// client-side tool, but a misconfigured registry shouldn't
		// silently pass.
		return "", errors.New("chat: tool has no server-side executor")
	}
	return t.exec(ctx, actor, in)
}

// buildChatTools is the real implementation, called from
// handlers_chat.go's stub. Each server-side tool here enforces owner
// scoping: the LLM can pass any constraint it likes, and we rewrite
// it to AND in `Owner == "<actor>"` before issuing the schedd RPC.
// The single-job mutations (hold/release/remove) read the job ad
// first and refuse if Owner != actor — defense in depth so a
// schedd ACL gap can't be exploited via the chat path.
func (s *Handler) buildChatTools() []chat.Tool {
	return []chat.Tool{
		s.toolQueryJobs(),
		s.toolHoldJob(),
		s.toolReleaseJob(),
		s.toolRemoveJob(),
		toolSetFilter(),
		toolExpandBatch(),
		toolHighlightJob(),
	}
}

// ---------------------------------------------------------------------
// Server-side tools
// ---------------------------------------------------------------------

// queryJobsArgs is what the LLM passes as the tool input.
type queryJobsArgs struct {
	// Constraint is a ClassAd expression filter (e.g. `JobStatus == 5`
	// for held jobs, `BatchName == "training-run"`). The chat layer
	// always ANDs in `Owner == "<actor>"` before issuing.
	Constraint string `json:"constraint,omitempty"`
	// Limit caps the result count. Defaults to 50 server-side; we
	// also clamp here so the LLM can't ask for 100k rows that flood
	// the context window.
	Limit int `json:"limit,omitempty"`
}

func (s *Handler) toolQueryJobs() chat.Tool {
	return &chatTool{
		name: "query_jobs",
		description: `List the user's jobs, optionally filtered by a ClassAd ` +
			`expression in 'constraint' (HTCondor's classad query language). ` +
			`Common attributes: JobStatus (1=Idle, 2=Running, 3=Removed, 4=Completed, 5=Held), ` +
			`HoldReason, BatchName (JobBatchName), QDate (epoch seconds), ClusterId, ProcId, ` +
			`Owner, Cmd (command), Args. Returns up to 'limit' (default 50) most recent jobs.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"constraint": {
					"type": "string",
					"description": "Optional ClassAd filter expression. Auto-scoped to the authenticated user."
				},
				"limit": {
					"type": "integer",
					"description": "Max jobs to return (1-200; default 50).",
					"minimum": 1,
					"maximum": 200
				}
			}
		}`),
		exec: func(ctx context.Context, actor string, in json.RawMessage) (string, error) {
			var args queryJobsArgs
			if err := json.Unmarshal(in, &args); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}
			limit := args.Limit
			if limit <= 0 {
				limit = 50
			}
			if limit > 200 {
				limit = 200
			}
			constraint := scopeToOwner(actor, args.Constraint)

			schedd := s.getSchedd()
			ads, _, err := schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
				Limit: limit,
				Projection: []string{
					"ClusterId", "ProcId", "JobStatus", "HoldReason", "HoldReasonCode",
					"Owner", "Cmd", "Args", "QDate", "JobStartDate", "JobBatchName",
					"NumShadowStarts",
				},
			})
			if err != nil {
				return "", fmt.Errorf("schedd query: %w", err)
			}

			summary := make([]map[string]any, 0, len(ads))
			for _, ad := range ads {
				summary = append(summary, summarizeJobForChat(ad))
			}
			out, _ := json.Marshal(map[string]any{
				"jobs":       summary,
				"count":      len(summary),
				"constraint": constraint,
			})
			return string(out), nil
		},
	}
}

// jobActionArgs is the shared input shape for hold/release/remove.
type jobActionArgs struct {
	ClusterID int    `json:"cluster_id"`
	ProcID    int    `json:"proc_id"`
	Reason    string `json:"reason,omitempty"`
}

func (a *jobActionArgs) jobID() string {
	return fmt.Sprintf("%d.%d", a.ClusterID, a.ProcID)
}

func (s *Handler) toolHoldJob() chat.Tool {
	return s.singleJobActionTool(
		"hold_job",
		`Place a held lock on one of the user's jobs (ClassAd JobStatus=5). `+
			`Held jobs stop running and stay in the queue until released. Use `+
			`'reason' to record why. Requires user confirmation by default.`,
		"Held via chat assistant",
		func(ctx context.Context, schedd *htcondor.Schedd, constraint, reason string) (*htcondor.JobActionResults, error) {
			return schedd.HoldJobs(ctx, constraint, reason)
		},
	)
}

func (s *Handler) toolReleaseJob() chat.Tool {
	return s.singleJobActionTool(
		"release_job",
		`Release a held job back to the idle queue so HTCondor can run it again. `+
			`Use after the user has fixed whatever caused the hold. Requires user `+
			`confirmation by default.`,
		"Released via chat assistant",
		func(ctx context.Context, schedd *htcondor.Schedd, constraint, reason string) (*htcondor.JobActionResults, error) {
			return schedd.ReleaseJobs(ctx, constraint, reason)
		},
	)
}

func (s *Handler) toolRemoveJob() chat.Tool {
	return s.singleJobActionTool(
		"remove_job",
		`Remove (cancel + delete) one of the user's jobs from the queue. This is `+
			`permanent — the job won't be retried. Requires user confirmation by `+
			`default. Use 'reason' to record why.`,
		"Removed via chat assistant",
		func(ctx context.Context, schedd *htcondor.Schedd, constraint, reason string) (*htcondor.JobActionResults, error) {
			return schedd.RemoveJobs(ctx, constraint, reason)
		},
	)
}

// singleJobActionTool factors the shared structure for hold/release/
// remove: parse args, verify the target is owned by the actor, build
// a constraint that names that exact job AND the owner (so a schedd
// without strict ACLs still can't accidentally touch someone else's
// job), invoke the schedd action, return a structured result.
func (s *Handler) singleJobActionTool(
	name, description, defaultReason string,
	action func(ctx context.Context, schedd *htcondor.Schedd, constraint, reason string) (*htcondor.JobActionResults, error),
) chat.Tool {
	return &chatTool{
		name:        name,
		description: description,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"cluster_id": {"type": "integer", "description": "ClusterId of the target job"},
				"proc_id":    {"type": "integer", "description": "ProcId of the target job"},
				"reason":     {"type": "string",  "description": "Optional human-readable reason"}
			},
			"required": ["cluster_id", "proc_id"]
		}`),
		confirm: true,
		exec: func(ctx context.Context, actor string, in json.RawMessage) (string, error) {
			var args jobActionArgs
			if err := json.Unmarshal(in, &args); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}
			if args.ClusterID <= 0 || args.ProcID < 0 {
				return "", fmt.Errorf("cluster_id must be > 0 and proc_id must be >= 0")
			}

			schedd := s.getSchedd()

			// Step 1: confirm the target job exists AND is owned by
			// the authenticated user. Without this any LLM whose
			// constraint-rewrite was somehow bypassed could nuke
			// another user's job; with it, the worst case is a
			// "no such job" reply.
			ownerConstraint := fmt.Sprintf("ClusterId == %d && ProcId == %d && Owner == %s",
				args.ClusterID, args.ProcID, classadStringLit(actor))
			ads, _, err := schedd.QueryWithOptions(ctx, ownerConstraint, &htcondor.QueryOptions{
				Limit:      1,
				Projection: []string{"ClusterId", "ProcId", "Owner", "JobStatus"},
			})
			if err != nil {
				return "", fmt.Errorf("ownership check: %w", err)
			}
			if len(ads) == 0 {
				return "", fmt.Errorf("job %s either does not exist or is not owned by %s",
					args.jobID(), actor)
			}

			// Step 2: dispatch the action. Constraint includes the
			// owner check redundantly so the schedd's per-RPC ACL
			// is also satisfied by content, not just by token
			// identity.
			reason := strings.TrimSpace(args.Reason)
			if reason == "" {
				reason = defaultReason
			}
			results, err := action(ctx, schedd, ownerConstraint, reason)
			if err != nil {
				return "", fmt.Errorf("schedd %s: %w", name, err)
			}
			out, _ := json.Marshal(map[string]any{
				"action":            name,
				"job_id":            args.jobID(),
				"affected":          results.Success,
				"not_found":         results.NotFound,
				"permission_denied": results.PermissionDenied,
				"bad_status":        results.BadStatus,
				"already_done":      results.AlreadyDone,
				"errors":            results.Error,
				"reason":            reason,
			})
			return string(out), nil
		},
	}
}

// ---------------------------------------------------------------------
// Client-side tool stubs
//
// These don't execute on the server — the engine forwards the
// tool_use to the SPA, which runs the registered handler in the
// browser and posts the result back. The schemas here are what the
// LLM sees; the SPA-side handler is responsible for the actual
// effect (see frontend/src/components/ChatPanel.tsx in Phase 4).
// ---------------------------------------------------------------------

func toolSetFilter() chat.Tool {
	return &chatTool{
		name: "set_filter",
		description: `Apply a substring filter to the jobs table the user is looking ` +
			`at — keeping only rows whose batch name, cluster id, command line, owner, ` +
			`or display status contains the query. Use to narrow the user's view to ` +
			`what they asked about, e.g. "show me my held jobs" → set_filter("held"), ` +
			`or "the training-run batch" → set_filter("training-run"). Pass the empty ` +
			`string to clear the filter.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"query": {
					"type": "string",
					"description": "Substring to match against batch rows; empty string clears."
				}
			},
			"required": ["query"]
		}`),
		clientSide: true,
	}
}

func toolExpandBatch() chat.Tool {
	return &chatTool{
		name: "expand_batch",
		description: `Open the inline expanded view for a batch (cluster) so the user ` +
			`can see all the job rows it contains. Use after answering a question that ` +
			`points at a specific batch.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"cluster_id": {
					"type": "integer",
					"description": "ClusterId of the batch to expand"
				}
			},
			"required": ["cluster_id"]
		}`),
		clientSide: true,
	}
}

func toolHighlightJob() chat.Tool {
	return &chatTool{
		name: "highlight_job",
		description: `Briefly highlight a specific job row in the table (visual flash) ` +
			`to draw the user's attention. Use sparingly, after answering a question ` +
			`about that exact job.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"cluster_id": {"type": "integer"},
				"proc_id":    {"type": "integer"}
			},
			"required": ["cluster_id", "proc_id"]
		}`),
		clientSide: true,
	}
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// scopeToOwner is the centerpiece of the chat layer's owner-scoping
// guarantee. Whatever ClassAd expression the LLM passes, we wrap it
// so the result evaluates to (Owner == "<actor>") AND (whatever the
// LLM asked for). The LLM cannot remove or escape the leading clause
// — the AND-wrapper is unconditional.
//
// Empty-string actor is rejected at the handler layer, not here, so
// this function never produces a `Owner == ""` constraint that
// matches everything.
func scopeToOwner(actor, llmConstraint string) string {
	owner := fmt.Sprintf("Owner == %s", classadStringLit(actor))
	c := strings.TrimSpace(llmConstraint)
	if c == "" {
		return owner
	}
	return fmt.Sprintf("(%s) && (%s)", owner, c)
}

// classadStringLit quotes a value as a ClassAd string literal,
// escaping internal quotes. ClassAd uses C-style backslash escapes
// for the few special chars in identifiers; usernames are tightly
// constrained so this is mostly belt-and-braces against a
// hypothetical odd Owner value.
func classadStringLit(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// summarizeJobForChat picks the small set of fields useful to the
// LLM out of a full job ClassAd and renders them as plain Go types
// the json encoder can serialize. We keep it minimal to avoid
// blowing the LLM's context with attributes it'll never use.
func summarizeJobForChat(ad *classad.ClassAd) map[string]any {
	out := map[string]any{}
	if v, ok := readInt(ad, "ClusterId"); ok {
		out["cluster_id"] = v
	}
	if v, ok := readInt(ad, "ProcId"); ok {
		out["proc_id"] = v
	}
	if v, ok := readInt(ad, "JobStatus"); ok {
		out["job_status"] = v
		out["job_status_name"] = jobStatusName(v)
	}
	if v, ok := readString(ad, "Owner"); ok {
		out["owner"] = v
	}
	if v, ok := readString(ad, "Cmd"); ok {
		out["cmd"] = v
	}
	if v, ok := readString(ad, "Args"); ok && v != "" {
		out["args"] = v
	}
	if v, ok := readString(ad, "JobBatchName"); ok && v != "" {
		out["batch_name"] = v
	}
	if v, ok := readString(ad, "HoldReason"); ok && v != "" {
		out["hold_reason"] = v
	}
	if v, ok := readInt(ad, "HoldReasonCode"); ok && v != 0 {
		out["hold_reason_code"] = v
	}
	if v, ok := readInt(ad, "QDate"); ok {
		out["qdate"] = v
	}
	if v, ok := readInt(ad, "JobStartDate"); ok && v != 0 {
		out["start_date"] = v
	}
	if v, ok := readInt(ad, "NumShadowStarts"); ok && v != 0 {
		out["num_shadow_starts"] = v
	}
	return out
}

// readString / readInt are tiny helpers for pulling typed values out
// of a ClassAd without stack-trace-y error surfaces. The chat tool
// is best-effort: missing fields just don't appear in the summary.
func readString(ad *classad.ClassAd, name string) (string, bool) {
	expr, found := ad.Lookup(name)
	if !found {
		return "", false
	}
	s, err := expr.Eval(nil).StringValue()
	if err != nil {
		return "", false
	}
	return s, true
}

func readInt(ad *classad.ClassAd, name string) (int, bool) {
	expr, found := ad.Lookup(name)
	if !found {
		return 0, false
	}
	v := expr.Eval(nil)
	if i, err := v.IntValue(); err == nil {
		return int(i), true
	}
	if s, err := v.StringValue(); err == nil {
		if n, err := strconv.Atoi(s); err == nil {
			return n, true
		}
	}
	return 0, false
}

// jobStatusName labels the integer JobStatus with the conventional
// name so the LLM doesn't have to memorize the table. Unknown codes
// pass through as a numeric string.
func jobStatusName(code int) string {
	switch code {
	case 1:
		return "idle"
	case 2:
		return "running"
	case 3:
		return "removed"
	case 4:
		return "completed"
	case 5:
		return "held"
	case 6:
		return "transferring_output"
	case 7:
		return "suspended"
	default:
		return fmt.Sprintf("unknown(%d)", code)
	}
}

// ensure scheddTool is satisfied by *Handler (compile-time check)
var _ scheddTool = (*Handler)(nil)
