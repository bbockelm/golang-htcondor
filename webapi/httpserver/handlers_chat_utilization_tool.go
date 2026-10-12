package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/chat"
	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// The in-page chat's analyze_utilization: the user's own finished jobs,
// analysed exactly as the Utilization page's "Mine" view analyses them --
// the same scope, the same read and the same cached answer, so asking the
// chat after looking at the page costs nothing -- rendered the way the
// MCP tool renders it.

// chatRequestKey carries the chat request on the context the engine runs
// tools under. The page's scope and its rule for reading from the mirror
// are decided from the request, and a chat tool is otherwise handed only
// the caller's name.
type chatRequestKey struct{}

func chatRequestFrom(ctx context.Context) *http.Request {
	r, _ := ctx.Value(chatRequestKey{}).(*http.Request)
	return r
}

type chatUtilizationArgs struct {
	Days       int    `json:"days,omitempty"`
	Constraint string `json:"constraint,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	// Everyone asks for the page's pool-wide view. utilizationScope gives
	// it only to the callers the page gives it to (administrators, and
	// project leads for their projects); anyone else gets their own.
	Everyone bool `json:"everyone,omitempty"`
}

func (s *Handler) toolAnalyzeUtilization() chat.Tool {
	return &chatTool{
		name: "analyze_utilization",
		description: `How well the user's finished jobs (completed or removed in the last 1, 7 or 30 days) used the ` +
			`CPU, memory, disk and GPUs they requested, grouped into workflows, with every suggestion for the next ` +
			`submission: the submit-file lines to change, what that would have saved, how confident it is, and how many ` +
			`more jobs could run at once. Memory is each job's peak. Pass workflow (a name, part of one, or a key from an ` +
			`earlier answer) for one workflow's percentiles. Use it for "am I asking for too much memory?" or "what ` +
			`should I request?" rather than reading job history yourself. Covers the user's own jobs; everyone=true ` +
			`covers everyone's for administrators (and a project lead's projects), as the Utilization page does.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"days": {"type": "integer", "enum": [1, 7, 30], "description": "How far back to look (default 7)."},
				"constraint": {"type": "string", "description": "Optional ClassAd filter over job attributes, e.g. JobBatchName == \"sweep\"."},
				"workflow": {"type": "string", "description": "One workflow to detail: its name, part of its name or executable, or its key."},
				"limit": {"type": "integer", "minimum": 1, "description": "Most recent finished jobs to analyse (default 50000)."},
				"everyone": {"type": "boolean", "description": "Everyone's jobs rather than the user's own, as the page's scope toggle does. Only administrators and project leads get more than their own."}
			}
		}`),
		exec: func(ctx context.Context, _ string, in json.RawMessage) (string, error) {
			var args chatUtilizationArgs
			if len(in) > 0 {
				if err := json.Unmarshal(in, &args); err != nil {
					return "", fmt.Errorf("invalid args: %w", err)
				}
			}
			r := chatRequestFrom(ctx)
			if r == nil || s.multi != nil {
				return "", errors.New("this tool is not available here")
			}
			// The page's own parameters, parsed and checked the page's way:
			// its "Mine" view unless asked for everyone's, which the scope
			// below grants only to whom the page grants it.
			q := url.Values{"owned_by_me": {strconv.FormatBool(!args.Everyone)}}
			if args.Days != 0 {
				q.Set("days", strconv.Itoa(args.Days))
			}
			if c := strings.TrimSpace(args.Constraint); c != "" {
				q.Set("constraint", c)
			}
			if args.Limit > 0 {
				q.Set("limit", strconv.Itoa(args.Limit))
			}
			uq, err := s.parseUtilizationValues(q)
			if err != nil {
				return "", err
			}
			scope, showOwner, _, err := s.utilizationScope(ctx, r, uq.ownedByMe)
			if err != nil {
				return "", err
			}
			mirror := s.mirrorAllowed(ctx, r) == nil
			c := &utilizationCaller{ctx: ctx, scope: scope, mirror: mirror, showOwner: showOwner, key: uq.key(scope, mirror)}
			res, err := s.utilizationAnalysis(c, uq)
			if err != nil {
				return "", fmt.Errorf("could not analyse finished jobs: %w", err)
			}
			// One workflow's full detail is kept compressed in the cached
			// answer and read only for the workflows the reply shows.
			detail := func(key string) (*utilization.Workflow, bool) {
				raw, ok, err := res.workflow(key)
				if !ok || err != nil {
					return nil, false
				}
				var w utilization.Workflow
				if json.Unmarshal(raw, &w) != nil {
					return nil, false
				}
				return &w, true
			}
			text, _ := mcpserver.RenderUtilization(res.summary, detail,
				mcpserver.UtilizationView{Workflow: strings.TrimSpace(args.Workflow)})
			return text, nil
		},
	}
}
