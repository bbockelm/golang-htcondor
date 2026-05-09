// Package condordocs embeds a curated subset of the upstream HTCondor
// RST documentation into the binary. Build with -tags embed_condor_docs
// after staging files into condordocs/dist/ (the Makefile and
// Dockerfile.release targets do this from reference/htcondor/docs/).
//
// The embedded content is loosely-structured RST source — exactly
// what a human reads in the HTCondor manual, minus the Sphinx
// rendering. We do not try to parse it; the MCP tools surface raw
// snippets with file + line provenance and let the LLM caller
// interpret the prose.
package condordocs

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// ErrNotEmbedded is returned by lookup/search calls when the binary was
// built without -tags embed_condor_docs and there is no documentation
// to consult. Callers (the MCP tool layer in particular) should surface
// this to the user as "docs unavailable" rather than as an internal
// error.
var ErrNotEmbedded = errors.New("htcondor docs are not embedded in this binary (rebuild with -tags embed_condor_docs)")

// Page identifies one of the four canonical doc sources. The string
// values are part of the MCP tool input contract for the search tool's
// `pages` filter, so don't rename them.
type Page string

// Page constants — exported because they show up in MCP tool input
// schemas (the `pages` enum on condor_doc_search) and in the JSON the
// search tool returns. The string values are the contract; don't
// rename without bumping the tool schema in lockstep.
const (
	PageJobAttributes     Page = "job_attributes"
	PageMachineAttributes Page = "machine_attributes"
	PageSubmitSyntax      Page = "submit_syntax"
	PageConfigVariables   Page = "config_variables"
)

// AllPages lists every page Search will visit by default.
var AllPages = []Page{
	PageJobAttributes,
	PageMachineAttributes,
	PageSubmitSyntax,
	PageConfigVariables,
}

// pageLayout maps each logical Page to the file or directory inside the
// embedded fs that holds its content. The config_variables page expands
// to a whole directory because the upstream "all configuration options"
// view is auto-generated from many smaller per-subsystem files; we ship
// the per-subsystem sources verbatim.
type pageLayout struct {
	// kind is "file" or "dir". Files are read once; dirs are walked and
	// every .rst leaf is treated as a sub-document of the page.
	kind string
	path string
}

func pageLayouts() map[Page]pageLayout {
	return map[Page]pageLayout{
		PageJobAttributes:     {kind: "file", path: "job-attributes.rst"},
		PageMachineAttributes: {kind: "file", path: "machine-attributes.rst"},
		PageSubmitSyntax:      {kind: "file", path: "condor-submit.rst"},
		PageConfigVariables:   {kind: "dir", path: "config"},
	}
}

// PageDescription returns a one-line, LLM-friendly explanation of a
// page's contents. The MCP tool definitions reuse these strings so the
// agent knows when to reach for which tool.
func PageDescription(p Page) string {
	switch p {
	case PageJobAttributes:
		return "ClassAd attributes that describe a submitted/running/completed job (e.g. ClusterId, JobStatus, RequestMemory, HoldReason)."
	case PageMachineAttributes:
		return "ClassAd attributes that describe an execute slot / machine (e.g. Cpus, Memory, OpSys, START expression context)."
	case PageSubmitSyntax:
		return "The condor_submit man page: submit-file commands and CLI flags (executable, arguments, transfer_input_files, queue, +Custom, etc.)."
	case PageConfigVariables:
		return "HTCondor daemon/system configuration macros (CONDOR_HOST, COLLECTOR_HOST, START, NEGOTIATOR_*, etc.). Many sub-files, one per subsystem."
	default:
		return ""
	}
}

// Snippet is a single search hit: a window of lines around a match,
// tagged with the page it came from and a 1-based line number that
// identifies where in the source file the match started.
type Snippet struct {
	// Page is the canonical Page value the snippet came from.
	Page Page `json:"page"`
	// Source is the file inside the embedded tree (e.g.
	// "config/global.rst"). For single-file pages this is the same as
	// the Page's file name; included so config_variables hits are
	// disambiguatable.
	Source string `json:"source"`
	// Line is the 1-based line number of the matched line.
	Line int `json:"line"`
	// Snippet is the raw text window: ContextLines lines before, the
	// matched line, ContextLines lines after, joined by '\n'. May be
	// shorter at file boundaries.
	Snippet string `json:"snippet"`
	// MatchedLine is the matched line itself, for callers that want to
	// render hits compactly without re-scanning the snippet.
	MatchedLine string `json:"matched_line"`
}

// SearchOptions controls a Search invocation.
type SearchOptions struct {
	// Query is matched case-insensitively against each line. Required.
	Query string
	// Pages limits the search to a subset; nil/empty searches all
	// pages in AllPages.
	Pages []Page
	// ContextLines is the number of lines on each side of a match to
	// include in the returned Snippet. Clamped to [0, 100]; defaults to
	// 5 when zero.
	ContextLines int
	// MaxResults caps the number of snippets returned; defaults to 30
	// when zero. Use this to keep tool responses small enough for the
	// LLM context window.
	MaxResults int
}

// Search scans every line of every requested page for case-insensitive
// substring matches of Query and returns a slice of Snippet windows.
// Hits are returned in (page, source-path, line) order so the result
// is deterministic across invocations.
func Search(opts SearchOptions) ([]Snippet, error) {
	if !IsEmbedded() {
		return nil, ErrNotEmbedded
	}
	if strings.TrimSpace(opts.Query) == "" {
		return nil, errors.New("query is required")
	}
	pages := opts.Pages
	if len(pages) == 0 {
		pages = AllPages
	}

	root, err := docsFS()
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, ErrNotEmbedded
	}
	return searchFS(root, pages, opts)
}

// searchFS is the dependency-injected core of Search; the public entry
// point wires in the embedded fs.FS and tests can pass a fstest.MapFS.
// Defaulting and clamping live here (not in Search) so tests that
// invoke this directly exercise the same behavior the LLM-facing tool
// will see.
func searchFS(root fs.FS, pages []Page, opts SearchOptions) ([]Snippet, error) {
	if opts.ContextLines == 0 {
		opts.ContextLines = 5
	}
	if opts.ContextLines < 0 {
		opts.ContextLines = 0
	}
	if opts.ContextLines > 100 {
		opts.ContextLines = 100
	}
	if opts.MaxResults == 0 {
		opts.MaxResults = 30
	}
	if opts.MaxResults < 0 {
		opts.MaxResults = 0
	}
	needle := strings.ToLower(opts.Query)
	var results []Snippet
	for _, page := range pages {
		hits, err := searchPage(root, page, needle, opts.ContextLines)
		if err != nil {
			return nil, fmt.Errorf("page %s: %w", page, err)
		}
		results = append(results, hits...)
		if opts.MaxResults > 0 && len(results) >= opts.MaxResults {
			results = results[:opts.MaxResults]
			break
		}
	}
	return results, nil
}

func searchPage(root fs.FS, page Page, needleLower string, contextLines int) ([]Snippet, error) {
	layout, ok := pageLayouts()[page]
	if !ok {
		return nil, fmt.Errorf("unknown page %q", page)
	}
	switch layout.kind {
	case "file":
		return searchFile(root, page, layout.path, needleLower, contextLines)
	case "dir":
		return searchDir(root, page, layout.path, needleLower, contextLines)
	default:
		return nil, fmt.Errorf("page %q has unknown layout kind %q", page, layout.kind)
	}
}

func searchDir(root fs.FS, page Page, dir, needleLower string, contextLines int) ([]Snippet, error) {
	var paths []string
	err := fs.WalkDir(root, dir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".rst") {
			return nil
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []Snippet
	for _, p := range paths {
		hits, err := searchFile(root, page, p, needleLower, contextLines)
		if err != nil {
			return nil, err
		}
		out = append(out, hits...)
	}
	return out, nil
}

func searchFile(root fs.FS, page Page, path, needleLower string, contextLines int) ([]Snippet, error) {
	data, err := fs.ReadFile(root, path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	var out []Snippet
	for i, line := range lines {
		if !strings.Contains(strings.ToLower(line), needleLower) {
			continue
		}
		out = append(out, Snippet{
			Page:        page,
			Source:      path,
			Line:        i + 1,
			Snippet:     extractWindow(lines, i, contextLines),
			MatchedLine: line,
		})
	}
	return out, nil
}

// extractWindow returns lines[max(0, idx-context) : min(len, idx+context+1)]
// joined by newlines.
func extractWindow(lines []string, idx, context int) string {
	start := idx - context
	if start < 0 {
		start = 0
	}
	end := idx + context + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

// Excerpt returns a single contiguous slice of lines from a Page,
// 1-based and inclusive on both ends. Use this when the caller has a
// known line number (e.g. from a previous Search hit) and wants to pull
// a wider window than the snippet provided.
//
// For multi-file pages (config_variables), source must be the path
// returned in Snippet.Source; for single-file pages it can be empty.
func Excerpt(page Page, source string, startLine, endLine int) (string, error) {
	if !IsEmbedded() {
		return "", ErrNotEmbedded
	}
	if startLine < 1 {
		startLine = 1
	}
	if endLine < startLine {
		return "", fmt.Errorf("end_line (%d) must be >= start_line (%d)", endLine, startLine)
	}
	root, err := docsFS()
	if err != nil {
		return "", err
	}
	if root == nil {
		return "", ErrNotEmbedded
	}
	layout, ok := pageLayouts()[page]
	if !ok {
		return "", fmt.Errorf("unknown page %q", page)
	}
	path := source
	if path == "" {
		if layout.kind != "file" {
			return "", fmt.Errorf("source is required for page %q", page)
		}
		path = layout.path
	} else if layout.kind == "dir" && !strings.HasPrefix(path, layout.path+"/") && path != layout.path {
		return "", fmt.Errorf("source %q is not within page %q", source, page)
	}
	data, err := fs.ReadFile(root, path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	if startLine > len(lines) {
		return "", fmt.Errorf("start_line %d exceeds file length %d", startLine, len(lines))
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}
	return strings.Join(lines[startLine-1:endLine], "\n"), nil
}

// ListSources returns the file paths inside a multi-file page. For
// single-file pages it returns a one-element slice with the page's
// canonical filename. Useful for the MCP "config_variables" tool: an
// agent can ask "what files exist?" before drilling into a specific
// subsystem.
func ListSources(page Page) ([]string, error) {
	if !IsEmbedded() {
		return nil, ErrNotEmbedded
	}
	root, err := docsFS()
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, ErrNotEmbedded
	}
	layout, ok := pageLayouts()[page]
	if !ok {
		return nil, fmt.Errorf("unknown page %q", page)
	}
	if layout.kind == "file" {
		return []string{layout.path}, nil
	}
	var paths []string
	err = fs.WalkDir(root, layout.path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".rst") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}
