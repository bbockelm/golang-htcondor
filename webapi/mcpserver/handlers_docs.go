package mcpserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/bbockelm/golang-htcondor/webapi/condordocs"
)

// isCondorDocTool reports whether name is one of the condor_doc_*
// reference tools. Used by handleCallTool's default arm so a new doc
// tool doesn't bump the dispatch switch's cyclomatic complexity.
func isCondorDocTool(name string) bool {
	switch name {
	case "condor_doc_job_attributes",
		"condor_doc_machine_attributes",
		"condor_doc_submit_syntax",
		"condor_doc_config_variables",
		"condor_doc_search":
		return true
	}
	return false
}

// condorDocTools returns the MCP tool definitions for the embedded
// HTCondor documentation. All five tools are read-only, deterministic,
// and side-effect-free — agents should auto-approve them.
//
// Each per-page tool wraps condordocs.Search restricted to that page.
// The generic search tool spans all pages. Both shapes are
// query/context_lines based: callers pass a phrase plus the desired
// surrounding-line window and get back snippet hits with file +
// line-number provenance.
//
// We deliberately do NOT try to parse the underlying RST. The MCP tool
// description tells the agent the content is loosely-structured prose
// and that the right call pattern is "search for the attribute or
// macro you care about with a small context window, then re-search
// with a larger window if you need more."
func condorDocTools() []Tool {
	docInputSchema := func(extraProps map[string]interface{}) map[string]interface{} {
		props := map[string]interface{}{
			"query": map[string]interface{}{
				"type":        "string",
				"description": "Case-insensitive substring to search for (typically an attribute, macro, or condor_submit command name like 'RequestMemory', 'COLLECTOR_HOST', or 'transfer_input_files').",
			},
			"context_lines": map[string]interface{}{
				"type":        "integer",
				"description": "Number of lines of surrounding text to include on each side of every matched line. Default: 5. Max: 100.",
			},
			"max_results": map[string]interface{}{
				"type":        "integer",
				"description": "Cap on the number of snippet hits returned. Default: 30. Increase for broad terms (e.g. 'memory'), decrease if responses are too long.",
			},
		}
		for k, v := range extraProps {
			props[k] = v
		}
		return map[string]interface{}{
			"type":       "object",
			"properties": props,
			"required":   []string{"query"},
		}
	}

	commonNote := " The HTCondor manual is loosely-structured RST source — the tool returns raw snippet windows with file + line provenance, not parsed records. Search for the attribute/macro/command name first; if the snippet is too narrow, re-call with a larger context_lines. The token cap recommended for the agent is 30 results."

	return []Tool{
		{
			Name:        "condor_doc_job_attributes",
			Description: "Look up a job ClassAd attribute (e.g. ClusterId, JobStatus, RequestMemory, HoldReason, NumJobStarts) in the HTCondor 'Job ClassAd Attributes' reference page. " + condordocs.PageDescription(condordocs.PageJobAttributes) + commonNote,
			InputSchema: docInputSchema(nil),
		},
		{
			Name:        "condor_doc_machine_attributes",
			Description: "Look up a machine/slot ClassAd attribute (e.g. Cpus, Memory, OpSys, Arch, START expression context) in the HTCondor 'Machine ClassAd Attributes' reference page. " + condordocs.PageDescription(condordocs.PageMachineAttributes) + commonNote,
			InputSchema: docInputSchema(nil),
		},
		{
			Name:        "condor_doc_submit_syntax",
			Description: "Look up a condor_submit submit-file command or CLI flag (e.g. executable, arguments, transfer_input_files, queue, +CustomAttr, request_cpus). " + condordocs.PageDescription(condordocs.PageSubmitSyntax) + commonNote,
			InputSchema: docInputSchema(nil),
		},
		{
			Name:        "condor_doc_config_variables",
			Description: "Look up an HTCondor configuration macro (e.g. CONDOR_HOST, COLLECTOR_HOST, START, MAX_JOBS_RUNNING, NEGOTIATOR_INTERVAL). " + condordocs.PageDescription(condordocs.PageConfigVariables) + commonNote,
			InputSchema: docInputSchema(nil),
		},
		{
			Name: "condor_doc_search",
			Description: "Generic full-text search across all four embedded HTCondor reference pages: job attributes, machine attributes, condor_submit syntax, and configuration macros. Use when you don't know which page a term lives in, or when you want hits from multiple pages at once. Each result is tagged with the page it came from so the agent can disambiguate. " +
				commonNote,
			InputSchema: docInputSchema(map[string]interface{}{
				"pages": map[string]interface{}{
					"type":        "array",
					"description": "Optional list of pages to restrict the search to. Defaults to all four pages. Allowed values: 'job_attributes', 'machine_attributes', 'submit_syntax', 'config_variables'.",
					"items": map[string]interface{}{
						"type": "string",
						"enum": []string{
							string(condordocs.PageJobAttributes),
							string(condordocs.PageMachineAttributes),
							string(condordocs.PageSubmitSyntax),
							string(condordocs.PageConfigVariables),
						},
					},
				},
			}),
		},
	}
}

// toolCondorDocSearch dispatches every condor_doc_* tool. Per-page
// tools pin the `pages` filter to a single Page; the generic search
// tool honors whatever subset (or all) the caller passed in.
func (s *Server) toolCondorDocSearch(_ context.Context, toolName string, args map[string]interface{}) (interface{}, error) {
	if !condordocs.IsEmbedded() {
		return nil, errors.New("HTCondor documentation is not embedded in this build")
	}
	query, _ := args["query"].(string)
	if query == "" {
		return nil, fmt.Errorf("query is required")
	}
	contextLines := intArg(args, "context_lines", 0)
	maxResults := intArg(args, "max_results", 0)

	var pages []condordocs.Page
	switch toolName {
	case "condor_doc_job_attributes":
		pages = []condordocs.Page{condordocs.PageJobAttributes}
	case "condor_doc_machine_attributes":
		pages = []condordocs.Page{condordocs.PageMachineAttributes}
	case "condor_doc_submit_syntax":
		pages = []condordocs.Page{condordocs.PageSubmitSyntax}
	case "condor_doc_config_variables":
		pages = []condordocs.Page{condordocs.PageConfigVariables}
	case "condor_doc_search":
		// Honor a caller-supplied subset; nil/empty = all pages.
		if raw, ok := args["pages"].([]interface{}); ok {
			for _, item := range raw {
				if name, ok := item.(string); ok && name != "" {
					pages = append(pages, condordocs.Page(name))
				}
			}
		}
	default:
		return nil, fmt.Errorf("unhandled doc tool %q", toolName)
	}

	hits, err := condordocs.Search(condordocs.SearchOptions{
		Query:        query,
		Pages:        pages,
		ContextLines: contextLines,
		MaxResults:   maxResults,
	})
	if err != nil {
		return nil, err
	}

	// Build a structured payload. The agent gets both a structured
	// `results` array (page/source/line/snippet) and a plain-text
	// `content` rendering — the latter is what most MCP clients
	// surface to the LLM by default, while the structured form lets
	// callers post-process if they want.
	if len(hits) == 0 {
		msg := fmt.Sprintf("No matches found for %q.", query)
		return map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": msg},
			},
			"results": []interface{}{},
		}, nil
	}

	text := renderDocHits(query, hits)
	results := make([]map[string]interface{}, 0, len(hits))
	for _, h := range hits {
		results = append(results, map[string]interface{}{
			"page":         string(h.Page),
			"source":       h.Source,
			"line":         h.Line,
			"matched_line": h.MatchedLine,
			"snippet":      h.Snippet,
		})
	}
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": text},
		},
		"results": results,
	}, nil
}

// renderDocHits formats a slice of snippet hits as plain text suitable
// for an MCP `content` block. We separate hits with a ruler so the LLM
// can tell where one entry ends and the next begins, and lead each one
// with a header that names the page + source file + line number.
func renderDocHits(query string, hits []condordocs.Snippet) string {
	out := fmt.Sprintf("HTCondor docs search for %q — %d match", query, len(hits))
	if len(hits) != 1 {
		out += "es"
	}
	out += ":\n"
	for i, h := range hits {
		out += "\n"
		out += fmt.Sprintf("--- [%d] page=%s source=%s line=%d ---\n", i+1, h.Page, h.Source, h.Line)
		out += h.Snippet
		if len(h.Snippet) > 0 && h.Snippet[len(h.Snippet)-1] != '\n' {
			out += "\n"
		}
	}
	return out
}

// intArg pulls an integer field out of an MCP tool's argument map.
// JSON unmarshals numbers as float64, so we accept either form;
// returns def for missing/blank/non-numeric values.
func intArg(args map[string]interface{}, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	}
	return def
}
