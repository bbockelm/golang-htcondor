package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/issues"
)

// analyze_issues: what is going wrong on this access point, grouped.
//
// The same question the web UI's Issues page asks, through the same
// package, because an agent asked "why are my jobs failing" should get
// the answer a facilitator would be reading -- not a list of ads it then
// has to summarize, which is both expensive and a summary nobody
// reviewed.
//
// It is the counterpart to aggregate_jobs in the same way the page is
// the counterpart to the dashboard: aggregate_jobs counts by an
// attribute the caller names, and the whole finding here is that no
// attribute names a problem. HoldReasonCode is too coarse (thirteen
// codes cover ap40's entire held backlog) and HoldReason is too fine
// (one root cause, thousands of distinct strings).

const (
	issuesDefaultWindow = 24 * time.Hour
	issuesMinWindow     = time.Hour
	issuesMaxWindow     = 7 * 24 * time.Hour
	// A cap on what crosses the wire to a model. The clusters are
	// ordered by size, so the tail is the part nobody reads.
	issuesMaxClusters = 12
	issuesMaxExamples = 3
)

func analyzeIssuesTool() Tool {
	return Tool{
		Name: "analyze_issues",
		Description: "What is going wrong on this access point right now, grouped into problems rather than listed as ads. " +
			"Clusters hold reasons and run failures by their message, which is the grouping neither attribute gives you: " +
			"HoldReasonCode is too coarse (a dozen codes cover everything that can go wrong) and HoldReason is too fine " +
			"(one root cause appears as thousands of distinct strings, because the execute node, sandbox path and output " +
			"filename vary per occurrence). Each cluster reports how many jobs and how many DISTINCT USERS it spans -- " +
			"the difference between one person's broken submit file and a site problem -- with example jobs. " +
			"Prefer this over listing held jobs and reading the reasons yourself. Covers YOUR OWN jobs; MCP admins get every user's.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"window_hours": map[string]interface{}{
					"type":        "number",
					"description": "How far back to look, in hours (default 24, min 1, max 168). For holds this is when the job was held; for run failures, when the attempt started.",
				},
				"granularity": map[string]interface{}{
					"type":        "number",
					"description": "How finely to split problems, 0 to 1 (default 0.5). Lower folds related problems together (input- and output-transfer failures become one row about file transfer); higher keeps them apart.",
				},
				"include_ended": map[string]interface{}{
					"type":        "boolean",
					"description": "Also read per-run-attempt history (default true), which is the only way to see jobs that failed to start and holds that have since been released. Needs JOB_EPOCH_HISTORY; the answer says so when it is missing.",
				},
			},
		},
	}
}

// mcpIssueSource reads through the mirror when there is one and the
// schedd otherwise.
type mcpIssueSource struct{ s *Server }

func (m mcpIssueSource) JobAds(ctx context.Context, constraint string, projection []string, limit int) ([]*classad.ClassAd, string, error) {
	if ads, err := m.s.issueMirrorRows(ctx, "jobs", constraint, projection, limit); err == nil {
		return ads, "htcondordb mirror", nil
	}
	ads, _, err := m.s.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: projection,
		Limit:      limit,
	})
	if err != nil {
		return nil, "", err
	}
	return ads, "schedd", nil
}

func (m mcpIssueSource) EpochAds(ctx context.Context, constraint string, projection []string, limit int) ([]*classad.ClassAd, string, error) {
	if ads, err := m.s.issueMirrorRows(ctx, "epoch_history", constraint, projection, limit); err == nil {
		return ads, "htcondordb mirror", nil
	}
	ads, err := m.s.getSchedd().QueryHistoryWithOptions(ctx, constraint, &htcondor.HistoryQueryOptions{
		Source:     htcondor.HistorySourceJobEpoch,
		Projection: projection,
		Limit:      limit,
		ScanLimit:  200000,
		Backwards:  true,
	})
	if err != nil {
		return nil, "", err
	}
	return ads, "schedd", nil
}

func (s *Server) issueMirrorRows(ctx context.Context, table, constraint string, projection []string, limit int) ([]*classad.ClassAd, error) {
	dbc, closer, _, err := s.dbClient(ctx)
	if err != nil {
		return nil, err
	}
	defer closer()
	rows, err := dbc.QueryRawProject(ctx, table, constraint, projection, limit)
	if err != nil {
		return nil, err
	}
	out := make([]*classad.ClassAd, 0, len(rows))
	for _, raw := range rows {
		if ad, perr := classad.ParseOld(raw); perr == nil {
			out = append(out, ad)
		}
	}
	return out, nil
}

func (s *Server) toolAnalyzeIssues(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	scope, ok := s.ownerScope(ctx, tierRead)
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
	// The same owner confinement every read tool applies: a non-admin
	// caller's view of "what is going wrong" is their own jobs.
	constraint := "true"
	if !scope.AllUsers {
		constraint = fmt.Sprintf("Owner == %s", classadStringLit(scope.Owner))
	}

	window := issuesDefaultWindow
	if v, ok := args["window_hours"].(float64); ok && v > 0 {
		window = time.Duration(v * float64(time.Hour))
	}
	if window < issuesMinWindow {
		window = issuesMinWindow
	}
	if window > issuesMaxWindow {
		window = issuesMaxWindow
	}

	granularity := 0.5
	if v, ok := args["granularity"].(float64); ok {
		granularity = v
	}
	if granularity < 0 {
		granularity = 0
	}
	if granularity > 1 {
		granularity = 1
	}

	includeEnded := true
	if v, ok := args["include_ended"].(bool); ok {
		includeEnded = v
	}

	set, err := issues.Collect(ctx, mcpIssueSource{s}, issues.Options{
		Scope:        constraint,
		Window:       window,
		IncludeEnded: includeEnded,
	})
	if err != nil {
		return nil, fmt.Errorf("reading what is going wrong: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Problems in the last %s", humanWindow(window))
	if set.Truncated {
		b.WriteString(" (read was truncated, so the counts are a floor)")
	}
	b.WriteString(":\n")
	for _, note := range set.Notes {
		fmt.Fprintf(&b, "  note: %s\n", note)
	}

	sections := issueSections(set, granularity)
	if len(sections) == 0 {
		b.WriteString("  nothing held and no failed run attempts in this window.\n")
	}
	structured := make([]map[string]interface{}, 0, len(sections))
	for _, sec := range sections {
		fmt.Fprintf(&b, "\n%s -- %d job(s), %d user(s):\n", sec.title, sec.total, sec.users)
		clusters := sec.clusters
		if len(clusters) > issuesMaxClusters {
			clusters = clusters[:issuesMaxClusters]
		}
		for _, c := range clusters {
			fmt.Fprintf(&b, "  %d job(s), %d user(s)%s: %s\n", c.Count, c.Users, facetNote(c), c.Template)
			for i, ex := range c.Examples {
				if i >= issuesMaxExamples {
					break
				}
				fmt.Fprintf(&b, "      e.g. %d.%d (%s): %s\n", ex.Cluster, ex.Proc, ex.Owner, oneLine(ex.Message))
			}
		}
		structured = append(structured, map[string]interface{}{
			"kind": sec.kind, "title": sec.title,
			"total": sec.total, "users": sec.users,
			"clusters": trimExamples(clusters),
		})
	}
	b.WriteString("\n" + scope.Note())

	return structuredTextResult(b.String(), map[string]interface{}{
		"window_seconds": int64(window / time.Second),
		"granularity":    granularity,
		"include_ended":  includeEnded,
		"source":         set.Source,
		"truncated":      set.Truncated,
		// Never nil: a client that iterates this field should not have
		// to special-case null on the common "nothing wrong" answer.
		"notes":    append([]string{}, set.Notes...),
		"sections": structured,
	}), nil
}

type issueSectionView struct {
	kind, title  string
	total, users int
	clusters     []issues.Cluster
}

// issueSections clusters each kind separately: they are different
// questions, and a section's totals should not depend on what the other
// section contains.
func issueSections(set *issues.Set, granularity float64) []issueSectionView {
	var out []issueSectionView
	for _, section := range []struct{ kind, title string }{
		{issues.KindHold, "Holds"},
		{issues.KindRunFailure, "Jobs that could not keep running"},
	} {
		c := issues.NewClusterer()
		users := map[string]bool{}
		total := 0
		for _, rec := range set.Records {
			if rec.Kind != section.kind {
				continue
			}
			c.Add(rec)
			total++
			if rec.Owner != "" {
				users[rec.Owner] = true
			}
		}
		if total == 0 {
			continue
		}
		out = append(out, issueSectionView{
			kind: section.kind, title: section.title,
			total: total, users: len(users),
			clusters: c.Clusters(granularity, issues.HoldReasonLabel),
		})
	}
	return out
}

// trimExamples bounds what crosses the wire. A cluster carries up to 25
// examples for the web UI's "show more"; a model does not need them, and
// a hold reason is a paragraph.
func trimExamples(clusters []issues.Cluster) []issues.Cluster {
	out := make([]issues.Cluster, 0, len(clusters))
	for _, c := range clusters {
		if len(c.Examples) > issuesMaxExamples {
			c.Examples = c.Examples[:issuesMaxExamples]
		}
		out = append(out, c)
	}
	return out
}

// facetNote says where a problem is happening when that is the answer.
//
// A cluster confined to one resource is that resource's problem however
// many users it reaches, and a cluster spread over thirty is the pool's
// -- and neither is visible in a job count. Rendered inline because a
// model reading this is deciding whether to tell one user or raise a
// ticket with a site.
func facetNote(c issues.Cluster) string {
	var parts []string
	for _, f := range c.Facets {
		switch {
		case f.Distinct == 1 && len(f.Top) > 0:
			parts = append(parts, fmt.Sprintf("all at %s %s", f.Name, f.Top[0].Value))
		case f.Distinct > 1:
			parts = append(parts, fmt.Sprintf("%d %ss", f.Distinct, f.Name))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return ", " + strings.Join(parts, ", ")
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

func humanWindow(d time.Duration) string {
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		days := int(d / (24 * time.Hour))
		if days == 1 {
			return "24 hours"
		}
		return fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("%d hours", int(d/time.Hour))
}

// emptyIssuesResult is what the tool returns for an access point with
// nothing wrong. Named so the structured-output contract test can assert
// on the empty shape without a schedd.
func emptyIssuesResult() interface{} {
	return structuredTextResult("Problems in the last 24 hours:\n  nothing held and no failed run attempts in this window.\n",
		map[string]interface{}{
			"window_seconds": int64(86400),
			"granularity":    0.5,
			"include_ended":  true,
			"source":         "",
			"truncated":      false,
			"notes":          []string{},
			"sections":       []map[string]interface{}{},
		})
}
