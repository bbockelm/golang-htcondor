package httpserver

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/chat"
)

// chatToolsOnPage is what the engine advertises on page: the tools tagged
// for it plus the untagged (universal) ones.
func chatToolsOnPage(tools []chat.Tool, page string) map[string]chat.Tool {
	out := map[string]chat.Tool{}
	for _, t := range tools {
		if pages := t.AvailablePages(); len(pages) == 0 || slices.Contains(pages, page) {
			out[t.Name()] = t
		}
	}
	return out
}

// Every page a tool is tagged for has instructions, so a typo in a tag
// ("pools") cannot make a tool silently invisible, and a page cannot be
// given tools without being described.
func TestChatToolPagesHaveInstructions(t *testing.T) {
	instructions := chatPageInstructions()
	for _, tool := range (&Handler{}).buildChatTools() {
		for _, p := range tool.AvailablePages() {
			if instructions[p] == "" {
				t.Errorf("tool %s is tagged for page %q, which has no instructions", tool.Name(), p)
			}
		}
	}
}

// chatPanelPage finds the page key each <ChatPanel> in the SPA sends.
var chatPanelPage = regexp.MustCompile(`(?s)<ChatPanel\b[^>]*?\bpage="([^"]+)"`)

// Every page key the SPA sends has instructions here: the two sides are
// kept in sync by hand (see the KEEP IN SYNC comments), and a page whose
// key the server does not know gets a generic assistant that knows
// nothing about what is on screen.
func TestChatPanelPagesHaveInstructions(t *testing.T) {
	instructions := chatPageInstructions()
	seen := map[string]bool{}
	root := filepath.Join("..", "frontend", "src", "app")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".tsx") || strings.HasSuffix(path, ".test.tsx") {
			return err
		}
		src, err := os.ReadFile(path) //nolint:gosec // a path under the repo's own frontend tree
		if err != nil {
			return err
		}
		for _, m := range chatPanelPage.FindAllStringSubmatch(string(src), -1) {
			seen[m[1]] = true
			if instructions[m[1]] == "" {
				t.Errorf("%s mounts the chat with page %q, which has no instructions", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading the SPA's pages: %v", err)
	}
	for _, want := range []string{"jobs", "submit", "job-detail", "archive", "archive-detail", "issues", "utilization", "pool"} {
		if !seen[want] {
			t.Errorf("no page mounts the chat with page %q", want)
		}
	}
}

// What the assistant can do on the Issues, Utilization and Pool pages and
// an archived job's page: read, and move the page's own filter. Nothing
// there changes a job or a machine, so nothing there asks for
// confirmation.
func TestChatToolsOnReadOnlyPages(t *testing.T) {
	tools := (&Handler{}).buildChatTools()
	// Server-side tools allowed on these pages; all read-only.
	readOnly := map[string]bool{
		"analyze_issues": true, "analyze_utilization": true, "query_slots": true,
		"doc_job_attributes": true, "doc_search": true, "query_jobs_archive": true,
		// Reads one of the site's own Markdown documents. Untagged for
		// the same reason the doc lookups are: a site skill about the
		// local GPU partition is as relevant here as anywhere.
		"get_site_skill": true,
	}
	for page, want := range map[string][]string{
		"issues":      {"analyze_issues", "set_constraint", "query_slots", "analyze_utilization"},
		"utilization": {"analyze_utilization", "set_constraint", "set_filter", "query_slots"},
		"pool":        {"query_slots", "set_constraint", "set_filter", "expand_machine"},
		// A finished job: its record, match analysis, and history. Not
		// the event log or stdout/stderr, which are read from the live
		// queue and so are not found for a job only in history.
		"archive-detail": {"get_job_attributes", "get_match_analysis", "query_jobs_archive"},
	} {
		on := chatToolsOnPage(tools, page)
		for _, name := range want {
			if on[name] == nil {
				t.Errorf("page %s does not offer %s", page, name)
			}
		}
		for name, tool := range on {
			if tool.RequiresConfirmation() {
				t.Errorf("page %s offers %s, which needs confirmation", page, name)
			}
			if !tool.ClientSide() && !readOnly[name] {
				t.Errorf("page %s offers server-side tool %s, which is not a known read", page, name)
			}
		}
	}
	if on := chatToolsOnPage(tools, "archive-detail"); on["get_job_log"] != nil || on["read_job_output"] != nil {
		t.Error("the archived-job page offers a tool that reads the live queue")
	}
	// Tagged where they mean something and nowhere else.
	if on := chatToolsOnPage(tools, "jobs"); on["analyze_issues"] != nil || on["expand_machine"] != nil {
		t.Error("the jobs page offers an issues- or pool-page tool")
	}
	if on := chatToolsOnPage(tools, "issues"); on["set_filter"] != nil {
		t.Error("the issues page has no text filter, but set_filter is offered there")
	}
	// The archive page's instructions describe set_filter; it has to be
	// offered there for that to be true.
	if on := chatToolsOnPage(tools, "archive"); on["set_filter"] == nil || on["set_constraint"] == nil {
		t.Error("the archive page does not offer set_filter and set_constraint")
	}
}
