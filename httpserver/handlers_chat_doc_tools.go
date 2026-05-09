package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bbockelm/golang-htcondor/condordocs"
	"github.com/bbockelm/golang-htcondor/httpserver/chat"
)

// docSearchArgs is the shared input shape for the documentation lookup
// tools. All fields are optional except Query.
type docSearchArgs struct {
	Query        string `json:"query"`
	ContextLines int    `json:"context_lines,omitempty"`
	MaxResults   int    `json:"max_results,omitempty"`
}

// toolDocJobAttributes is a job-attribute reference lookup. Restricted
// to PageJobAttributes — the LLM uses this when the user asks "what
// does NumShadowStarts mean" or "what's the difference between QDate
// and JobStartDate". Read-only and side-effect-free, so no
// confirmation is required.
func toolDocJobAttributes() chat.Tool {
	return &chatTool{
		name: "doc_job_attribute",
		description: `Look up an HTCondor job ClassAd attribute (e.g. ClusterId, ` +
			`JobStatus, RequestMemory, HoldReason, NumJobStarts, JobBatchName) in ` +
			`the embedded "Job ClassAd Attributes" reference. Returns raw snippet ` +
			`windows from the manual with file + line provenance — the docs are ` +
			`loosely-structured RST, so search for the attribute name first and ` +
			`re-call with a larger context_lines if the snippet is too narrow.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"query": {
					"type": "string",
					"description": "Case-insensitive substring; usually a job-attribute name."
				},
				"context_lines": {
					"type": "integer",
					"description": "Lines of surrounding text per hit. Default 5, max 100.",
					"minimum": 0,
					"maximum": 100
				},
				"max_results": {
					"type": "integer",
					"description": "Cap on hits returned. Default 30.",
					"minimum": 1,
					"maximum": 100
				}
			},
			"required": ["query"]
		}`),
		exec: func(_ context.Context, _ string, in json.RawMessage) (string, error) {
			return runDocSearch(in, []condordocs.Page{condordocs.PageJobAttributes})
		},
	}
}

// toolDocSearch is the generic full-text search across every embedded
// reference page. Read-only, no confirmation. Useful when the user
// asks about something that's not a pure job attribute — submit-file
// syntax, machine attributes, config macros — and the LLM doesn't
// know which page to start from.
func toolDocSearch() chat.Tool {
	return &chatTool{
		name: "doc_search",
		description: `Generic full-text search across every embedded HTCondor ` +
			`reference page (job attributes, machine/slot attributes, condor_submit ` +
			`syntax, configuration macros). Each hit is tagged with the page it came ` +
			`from. Use when the term isn't strictly a job ClassAd attribute (e.g. ` +
			`'transfer_input_files', 'request_cpus', 'JOB_TRANSFORM_*'). The docs are ` +
			`loosely-structured RST: re-call with a larger context_lines if needed.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"query": {
					"type": "string",
					"description": "Case-insensitive substring; an attribute, macro, or submit command name."
				},
				"context_lines": {
					"type": "integer",
					"description": "Lines of surrounding text per hit. Default 5, max 100.",
					"minimum": 0,
					"maximum": 100
				},
				"max_results": {
					"type": "integer",
					"description": "Cap on hits returned. Default 30.",
					"minimum": 1,
					"maximum": 100
				}
			},
			"required": ["query"]
		}`),
		exec: func(_ context.Context, _ string, in json.RawMessage) (string, error) {
			// Empty pages = search every page in condordocs.AllPages.
			return runDocSearch(in, nil)
		},
	}
}

// runDocSearch is the shared executor for both doc tools. Returns the
// rendered prose (with file + line headers) so Anthropic's tool_result
// arrives in a form the LLM can read directly — no JSON unwrapping
// step needed.
func runDocSearch(in json.RawMessage, pages []condordocs.Page) (string, error) {
	var args docSearchArgs
	if err := json.Unmarshal(in, &args); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}
	args.Query = strings.TrimSpace(args.Query)
	if args.Query == "" {
		return "", fmt.Errorf("query is required")
	}

	hits, err := condordocs.Search(condordocs.SearchOptions{
		Query:        args.Query,
		Pages:        pages,
		ContextLines: args.ContextLines,
		MaxResults:   args.MaxResults,
	})
	if err != nil {
		return "", err
	}

	if len(hits) == 0 {
		return fmt.Sprintf("No HTCondor doc matches for %q.", args.Query), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "HTCondor docs search for %q — %d match", args.Query, len(hits))
	if len(hits) != 1 {
		b.WriteString("es")
	}
	b.WriteString(":\n")
	for i, h := range hits {
		fmt.Fprintf(&b, "\n--- [%d] page=%s source=%s line=%d ---\n", i+1, h.Page, h.Source, h.Line)
		b.WriteString(h.Snippet)
		if len(h.Snippet) > 0 && h.Snippet[len(h.Snippet)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}
