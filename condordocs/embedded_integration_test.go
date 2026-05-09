//go:build embed_condor_docs

package condordocs

import (
	"strings"
	"testing"
)

// These tests run only when the docs are embedded. They use known
// well-defined attribute / macro / command names from the upstream
// HTCondor manual; if any of these vanish from the source, the
// upstream changed something we should investigate (rather than
// silently shipping a tool that returns "no matches").

func TestEmbedded_JobAttributesHasClusterId(t *testing.T) {
	hits, err := Search(SearchOptions{Query: "ClusterId", Pages: []Page{PageJobAttributes}, ContextLines: 2, MaxResults: 5})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected ClusterId to appear in job attributes page")
	}
}

func TestEmbedded_MachineAttributesHasMemory(t *testing.T) {
	hits, err := Search(SearchOptions{Query: "Memory", Pages: []Page{PageMachineAttributes}, ContextLines: 0, MaxResults: 1})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected Memory to appear in machine attributes page")
	}
}

func TestEmbedded_SubmitSyntaxHasTransferInputFiles(t *testing.T) {
	hits, err := Search(SearchOptions{Query: "transfer_input_files", Pages: []Page{PageSubmitSyntax}, ContextLines: 1, MaxResults: 1})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected transfer_input_files in condor_submit doc")
	}
	if !strings.Contains(strings.ToLower(hits[0].MatchedLine), "transfer_input_files") {
		t.Errorf("matched line wrong: %q", hits[0].MatchedLine)
	}
}

func TestEmbedded_ConfigVariablesHasCollectorHost(t *testing.T) {
	hits, err := Search(SearchOptions{Query: "COLLECTOR_HOST", Pages: []Page{PageConfigVariables}, ContextLines: 0, MaxResults: 5})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected COLLECTOR_HOST in config_variables page")
	}
	// The config_variables page is multi-file; verify Source is set.
	for _, h := range hits {
		if h.Source == "" {
			t.Errorf("expected Source to be set on multi-file page hit: %+v", h)
		}
	}
}

func TestEmbedded_GenericSearch_FindsAcrossPages(t *testing.T) {
	// "memory" appears in both job attributes (RequestMemory) and
	// machine attributes (Memory). A generic search should pull from
	// at least two pages.
	hits, err := Search(SearchOptions{Query: "memory", ContextLines: 0, MaxResults: 100})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	pages := map[Page]int{}
	for _, h := range hits {
		pages[h.Page]++
	}
	if len(pages) < 2 {
		t.Errorf("expected hits on ≥2 pages for 'memory', got %v", pages)
	}
}

func TestEmbedded_ListSources_ConfigPage(t *testing.T) {
	srcs, err := ListSources(PageConfigVariables)
	if err != nil {
		t.Fatalf("ListSources: %v", err)
	}
	if len(srcs) == 0 {
		t.Fatal("expected at least one source file under config_variables")
	}
}
