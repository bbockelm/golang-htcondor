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
					"description": "Lines of surrounding text per hit. Default 5, max 40.",
					"minimum": 0,
					"maximum": 40
				},
				"max_results": {
					"type": "integer",
					"description": "Cap on hits returned. Default 15, max 30. The response is also byte-capped (~24 KiB).",
					"minimum": 1,
					"maximum": 30
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
					"description": "Lines of surrounding text per hit. Default 5, max 40.",
					"minimum": 0,
					"maximum": 40
				},
				"max_results": {
					"type": "integer",
					"description": "Cap on hits returned. Default 15, max 30. The response is also byte-capped (~24 KiB).",
					"minimum": 1,
					"maximum": 30
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

// docSearchDefaultMaxResults / docSearchMaxByteCap bound the LLM
// cost of a single doc search. Without these, a worst-case
// max_results=100 × context_lines=100 × wide-line could produce
// ~800 KB of output (~200k tokens). The defaults target ~3k tokens
// per call (15 results × 5 lines), with hard maxima carved to keep
// even the worst-permissible config under ~6k tokens.
const (
	docSearchDefaultMaxResults = 15
	docSearchDefaultContext    = 5
	docSearchMaxByteCap        = 24 * 1024
)

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
	// Pick the chat-flavored defaults — condordocs.Search's package
	// defaults are sized for the (uncapped) MCP path. The schema
	// upper bounds enforce the maxima.
	if args.MaxResults == 0 {
		args.MaxResults = docSearchDefaultMaxResults
	}
	if args.ContextLines == 0 {
		args.ContextLines = docSearchDefaultContext
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
	dropped := 0
	for i, h := range hits {
		header := fmt.Sprintf("\n--- [%d] page=%s source=%s line=%d ---\n", i+1, h.Page, h.Source, h.Line)
		// Belt-and-braces byte cap: even within the schema max,
		// a wide-line page could pile up. Stop emitting full hits
		// once we'd exceed the cap; record how many got dropped
		// so the LLM can see it was truncated and either narrow
		// the query or page.
		if b.Len()+len(header)+len(h.Snippet) > docSearchMaxByteCap {
			dropped = len(hits) - i
			break
		}
		b.WriteString(header)
		b.WriteString(h.Snippet)
		if len(h.Snippet) > 0 && h.Snippet[len(h.Snippet)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	if dropped > 0 {
		fmt.Fprintf(&b, "\n[truncated: %d more hit(s) elided to stay under the per-call byte cap; narrow the query or drop context_lines]\n", dropped)
	}
	return b.String(), nil
}
