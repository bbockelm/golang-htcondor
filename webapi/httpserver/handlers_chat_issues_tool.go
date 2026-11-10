package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/chat"
	"github.com/bbockelm/golang-htcondor/webapi/issues"
)

// The in-page chat's analyze_issues: the Issues page's own answer, read
// through issuesAnswer -- the same owner scoping, the same administrator
// rule and the same one-minute cache as GET /api/v1/issues -- and cut down
// to what a model needs. Asking the chat about what is on screen costs
// nothing extra, because the page has already filled the cache.
//
// Tagged for the issues page only. Elsewhere the per-job tools answer
// "why is this job held"; this one reads the whole held backlog and every
// failed run attempt in the window, which is worth it only where the
// question is about the access point as a whole.

// Bounds on what crosses the wire to the model. Clusters come largest
// first, so the tail is the part nobody reads; a hold reason can be a
// paragraph.
const (
	chatIssuesMaxClusters   = 8
	chatIssuesMaxExamples   = 3
	chatIssuesMaxMessage    = 300
	chatIssuesMaxFacetTop   = 2
	chatIssuesMaxCodes      = 3
	chatIssuesMaxTopUsers   = 3
	chatIssuesMaxNoteLength = 400
	// Names: batch names, sites and resources.
	chatIssuesMaxName = 60
)

type chatIssuesArgs struct {
	WindowHours  float64  `json:"window_hours,omitempty"`
	Granularity  *float64 `json:"granularity,omitempty"`
	IncludeEnded *bool    `json:"include_ended,omitempty"`
	Constraint   string   `json:"constraint,omitempty"`
}

func (s *Handler) toolAnalyzeIssues() chat.Tool {
	return &chatTool{
		name:  "analyze_issues",
		pages: issuesPageTools,
		description: `What is going wrong: held jobs and run attempts that failed, grouped into problems by what ` +
			`their messages have in common, largest first -- the same answer the Issues page shows. Each problem has ` +
			`its job count, how many distinct users it affects, the hold codes, where it happened (site/resource) when ` +
			`that is concentrated, when it was last seen, and example jobs. Pass the window, detail and "include ended" ` +
			`settings the page context reports so the answer matches the screen; pass constraint to narrow to some jobs ` +
			`(e.g. RequestGPUs >= 1 for jobs that asked for a GPU). Covers the chat's scope: the user's own jobs, or ` +
			`every user's when the page shows everyone's and the user is an administrator.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"window_hours": {"type": "number", "minimum": 1, "maximum": 168, "description": "How far back to look, in hours (default 24; the page offers 1, 8, 24, 72 and 168)."},
				"granularity": {"type": "number", "minimum": 0, "maximum": 1, "description": "How finely to split problems, 0 (fewer, broader) to 1 (more, narrower). Default 0.5."},
				"include_ended": {"type": "boolean", "description": "Also count problems that have already ended (released holds, failed run attempts). Default true."},
				"constraint": {"type": "string", "description": "Optional ClassAd filter over job attributes, e.g. RequestGPUs >= 1 or JobBatchName == \"sweep\"."}
			}
		}`),
		exec: func(ctx context.Context, _ string, in json.RawMessage) (string, error) {
			var args chatIssuesArgs
			if len(in) > 0 {
				if err := json.Unmarshal(in, &args); err != nil {
					return "", fmt.Errorf("invalid args: %w", err)
				}
			}
			r := chatRequestFrom(ctx)
			if r == nil || s.multi != nil {
				return "", errors.New("this tool is not available here")
			}
			// The page's scope as the server resolved it. issuesAnswer
			// applies its own administrator rule on top, so this can only
			// ever narrow what GET /api/v1/issues would give this caller.
			scope := chat.ScopeFrom(ctx)
			q := issueQuery{
				ownedByMe:    scope.Effective != chat.ScopeEveryone,
				window:       defaultIssueWindow,
				granularity:  0.5,
				includeEnded: true,
				constraint:   args.Constraint,
			}
			if args.WindowHours > 0 {
				q.window = time.Duration(args.WindowHours * float64(time.Hour))
			}
			if args.Granularity != nil {
				q.granularity = *args.Granularity
			}
			if args.IncludeEnded != nil {
				q.includeEnded = *args.IncludeEnded
			}
			resp, err := s.issuesAnswer(ctx, r, q)
			if err != nil {
				var bad issueQueryError
				if errors.As(err, &bad) {
					return "", err
				}
				return "", fmt.Errorf("could not read what is going wrong: %w", err)
			}
			out, err := json.Marshal(chatIssuesSummary(resp, scope.Requested == chat.ScopeEveryone))
			if err != nil {
				return "", err
			}
			return string(out), nil
		},
	}
}

// chatIssueCluster is one problem as the model sees it.
type chatIssueCluster struct {
	Jobs  int `json:"jobs"`
	Users int `json:"users"`
	// TopUsers and Codes are "name (count)" strings: compact, and
	// what the page's tooltips show.
	TopUsers []string           `json:"top_users,omitempty"`
	Codes    []string           `json:"codes,omitempty"`
	Where    []string           `json:"where,omitempty"`
	LastSeen string             `json:"last_seen,omitempty"`
	Message  string             `json:"message"`
	Examples []chatIssueExample `json:"examples,omitempty"`
}

// chatIssueExample names a job with the problem. Its message is the
// cluster's (the lead example's), so it is not repeated per example.
type chatIssueExample struct {
	JobID string `json:"job_id"`
	Owner string `json:"owner,omitempty"`
	Batch string `json:"batch,omitempty"`
}

type chatIssueSection struct {
	Title    string             `json:"title"`
	Jobs     int                `json:"jobs"`
	Users    int                `json:"users"`
	Problems int                `json:"problems"`
	Shown    []chatIssueCluster `json:"shown"`
}

// chatIssuesSummary bounds an IssuesResponse for the model: at most
// chatIssuesMaxClusters problems per section, a few example jobs each,
// and every free-text field cut short.
func chatIssuesSummary(resp IssuesResponse, askedEveryone bool) map[string]any {
	scope := "your own jobs"
	if !resp.OwnedByMe {
		scope = "every user's jobs"
	} else if askedEveryone {
		scope = "your own jobs (the page asked for everyone's; only administrators can see them)"
	}
	sections := make([]chatIssueSection, 0, len(resp.Sections))
	for _, sec := range resp.Sections {
		cs := sec.Clusters
		if len(cs) > chatIssuesMaxClusters {
			cs = cs[:chatIssuesMaxClusters]
		}
		shown := make([]chatIssueCluster, 0, len(cs))
		for _, c := range cs {
			shown = append(shown, chatIssueClusterOf(c))
		}
		sections = append(sections, chatIssueSection{
			Title: sec.Title, Jobs: sec.Total, Users: sec.Users,
			Problems: len(sec.Clusters), Shown: shown,
		})
	}
	notes := make([]string, 0, len(resp.Notes))
	for _, n := range resp.Notes {
		notes = append(notes, chatClip(n, chatIssuesMaxNoteLength))
	}
	out := map[string]any{
		"scope":          scope,
		"window_hours":   resp.WindowSeconds / 3600,
		"granularity":    resp.Granularity,
		"include_ended":  resp.IncludeEnded,
		"sections":       sections,
		"computed_at":    time.Unix(resp.ComputedAt, 0).UTC().Format(time.RFC3339),
		"nothing_wrong":  len(sections) == 0,
		"counts_a_floor": resp.Truncated,
	}
	if resp.Constraint != "" {
		out["constraint"] = resp.Constraint
	}
	if len(notes) > 0 {
		out["notes"] = notes
	}
	return out
}

func chatIssueClusterOf(c issues.Cluster) chatIssueCluster {
	out := chatIssueCluster{Jobs: c.Count, Users: c.Users}
	for i, u := range c.TopUsers {
		if i >= chatIssuesMaxTopUsers {
			break
		}
		out.TopUsers = append(out.TopUsers, fmt.Sprintf("%s (%d)", chatClip(u.Owner, chatIssuesMaxName), u.Count))
	}
	for i, code := range c.Codes {
		if i >= chatIssuesMaxCodes {
			break
		}
		label := code.Label
		if label == "" {
			label = "code"
		}
		out.Codes = append(out.Codes, fmt.Sprintf("%s %d.%d (%d)", label, code.Code, code.SubCode, code.Count))
	}
	for _, f := range c.Facets {
		switch {
		case f.Distinct == 1 && len(f.Top) > 0:
			out.Where = append(out.Where, fmt.Sprintf("all at %s %s", f.Name, chatClip(f.Top[0].Value, chatIssuesMaxName)))
		case f.Distinct > 1:
			top := make([]string, 0, chatIssuesMaxFacetTop)
			for i, v := range f.Top {
				if i >= chatIssuesMaxFacetTop {
					break
				}
				top = append(top, fmt.Sprintf("%s (%d)", chatClip(v.Value, chatIssuesMaxName), v.Count))
			}
			out.Where = append(out.Where, fmt.Sprintf("%d %ss, most at %s", f.Distinct, f.Name, strings.Join(top, ", ")))
		}
	}
	if c.LastSeen > 0 {
		out.LastSeen = time.Unix(c.LastSeen, 0).UTC().Format(time.RFC3339)
	}
	// The page leads with the newest example's own words, falling back to
	// the masked template when it has none.
	out.Message = chatClip(c.Template, chatIssuesMaxMessage)
	if len(c.Examples) > 0 && strings.TrimSpace(c.Examples[0].Message) != "" {
		out.Message = chatClip(c.Examples[0].Message, chatIssuesMaxMessage)
	}
	for i, ex := range c.Examples {
		if i >= chatIssuesMaxExamples {
			break
		}
		e := chatIssueExample{
			JobID: fmt.Sprintf("%d.%d", ex.Cluster, ex.Proc),
			Owner: ex.Owner,
			Batch: chatClip(ex.Batch, chatIssuesMaxName),
		}
		out.Examples = append(out.Examples, e)
	}
	return out
}

// chatClip cuts s to at most n bytes on a rune boundary, flattening newlines.
func chatClip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
