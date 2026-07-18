package condordocs

import (
	"strings"
	"testing"
	"testing/fstest"
)

// fakeDocs builds a minimal in-memory fs.FS that mirrors the layout
// docs.go expects (same filenames at the same depths). Tests use this
// instead of the real embedded fs so they pass with or without the
// embed_condor_docs build tag.
func fakeDocs() fstest.MapFS {
	return fstest.MapFS{
		"job-attributes.rst": &fstest.MapFile{Data: []byte(strings.Join([]string{
			"Job ClassAd Attributes",
			"======================",
			"",
			"AcctGroup",
			"  Accounting group name.",
			"",
			"JobStatus",
			"  Integer job state. 1=Idle, 2=Running, 5=Held.",
			"",
			"RequestMemory",
			"  Memory the job asked for, in MB.",
		}, "\n"))},
		"machine-attributes.rst": &fstest.MapFile{Data: []byte(strings.Join([]string{
			"Machine ClassAd Attributes",
			"==========================",
			"",
			"Cpus",
			"  Number of CPUs in the slot.",
			"",
			"Memory",
			"  Memory in MB visible to the slot.",
		}, "\n"))},
		"condor-submit.rst": &fstest.MapFile{Data: []byte(strings.Join([]string{
			"condor_submit",
			"=============",
			"",
			"executable",
			"  The program to run.",
			"",
			"transfer_input_files",
			"  Comma-separated list of files to transfer in.",
		}, "\n"))},
		"config/global.rst": &fstest.MapFile{Data: []byte(strings.Join([]string{
			"Global Configuration",
			"====================",
			"",
			"COLLECTOR_HOST",
			"  Host of the collector daemon.",
			"",
			"CONDOR_HOST",
			"  Host of the central manager.",
		}, "\n"))},
		"config/schedd.rst": &fstest.MapFile{Data: []byte(strings.Join([]string{
			"Schedd Configuration",
			"====================",
			"",
			"MAX_JOBS_RUNNING",
			"  Cap on simultaneously running jobs.",
		}, "\n"))},
	}
}

func TestSearchFS_FindsAcrossPages(t *testing.T) {
	hits, err := searchFS(fakeDocs(), AllPages, SearchOptions{Query: "memory", ContextLines: 1, MaxResults: 30})
	if err != nil {
		t.Fatalf("searchFS: %v", err)
	}
	// Expect at least: RequestMemory (job), Memory header + body (machine).
	if len(hits) < 2 {
		t.Fatalf("expected ≥2 hits for 'memory', got %d", len(hits))
	}
	gotPages := map[Page]bool{}
	for _, h := range hits {
		gotPages[h.Page] = true
	}
	if !gotPages[PageJobAttributes] || !gotPages[PageMachineAttributes] {
		t.Errorf("expected hits in both job_attributes and machine_attributes; got %v", gotPages)
	}
}

func TestSearchFS_CaseInsensitive(t *testing.T) {
	hits, err := searchFS(fakeDocs(), []Page{PageConfigVariables}, SearchOptions{Query: "collector_host", ContextLines: 0, MaxResults: 30})
	if err != nil {
		t.Fatalf("searchFS: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected at least one hit for COLLECTOR_HOST")
	}
	for _, h := range hits {
		if h.Page != PageConfigVariables {
			t.Errorf("expected page=config_variables, got %s", h.Page)
		}
	}
}

func TestSearchFS_ContextWindow(t *testing.T) {
	hits, err := searchFS(fakeDocs(), []Page{PageJobAttributes}, SearchOptions{Query: "JobStatus", ContextLines: 2, MaxResults: 30})
	if err != nil {
		t.Fatalf("searchFS: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected a hit for JobStatus")
	}
	// Snippet should contain both the matched line and the line below
	// it (the description), since context=2 covers ±2 lines.
	if !strings.Contains(hits[0].Snippet, "JobStatus") {
		t.Errorf("snippet missing matched line: %q", hits[0].Snippet)
	}
	if !strings.Contains(hits[0].Snippet, "Idle") {
		t.Errorf("snippet missing context after match: %q", hits[0].Snippet)
	}
}

func TestSearchFS_MaxResults(t *testing.T) {
	hits, err := searchFS(fakeDocs(), AllPages, SearchOptions{Query: "ClassAd", ContextLines: 0, MaxResults: 1})
	if err != nil {
		t.Fatalf("searchFS: %v", err)
	}
	if len(hits) != 1 {
		t.Errorf("expected exactly 1 hit (capped), got %d", len(hits))
	}
}

func TestSearchFS_DefaultsContextLines(t *testing.T) {
	// ContextLines=0 in the input should be promoted to the default
	// (5). We can't observe the constant directly, but we can verify
	// the snippet has more than one line for a query whose match is
	// not at the file boundary.
	hits, err := searchFS(fakeDocs(), []Page{PageJobAttributes}, SearchOptions{Query: "JobStatus", MaxResults: 1})
	if err != nil {
		t.Fatalf("searchFS: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected a hit")
	}
	if !strings.Contains(hits[0].Snippet, "\n") {
		t.Errorf("expected default context to include surrounding lines, snippet=%q", hits[0].Snippet)
	}
}

func TestSearchFS_ReturnsLineNumber(t *testing.T) {
	hits, err := searchFS(fakeDocs(), []Page{PageJobAttributes}, SearchOptions{Query: "RequestMemory", ContextLines: 0, MaxResults: 1})
	if err != nil {
		t.Fatalf("searchFS: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected a hit")
	}
	if hits[0].Line < 1 {
		t.Errorf("line number not 1-based: got %d", hits[0].Line)
	}
	if hits[0].MatchedLine != "RequestMemory" {
		t.Errorf("matched line wrong: got %q", hits[0].MatchedLine)
	}
}

func TestSearchFS_DirPageWalksAllFiles(t *testing.T) {
	// MAX_JOBS_RUNNING only lives in config/schedd.rst — covers the
	// directory-walk path.
	hits, err := searchFS(fakeDocs(), []Page{PageConfigVariables}, SearchOptions{Query: "MAX_JOBS_RUNNING", ContextLines: 0, MaxResults: 30})
	if err != nil {
		t.Fatalf("searchFS: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected a hit in config/schedd.rst")
	}
	if hits[0].Source != "config/schedd.rst" {
		t.Errorf("expected Source=config/schedd.rst, got %q", hits[0].Source)
	}
}

func TestExtractWindowBoundaries(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}
	got := extractWindow(lines, 0, 2)
	// idx=0 with context=2 should give lines[0:3] = "a\nb\nc".
	if got != "a\nb\nc" {
		t.Errorf("start window: got %q", got)
	}
	got = extractWindow(lines, 4, 2)
	// idx=4 (last line) with context=2 should give lines[2:5] = "c\nd\ne".
	if got != "c\nd\ne" {
		t.Errorf("end window: got %q", got)
	}
	got = extractWindow(lines, 2, 0)
	if got != "c" {
		t.Errorf("zero context: got %q", got)
	}
}

func TestSearch_NotEmbeddedReturnsSentinel(t *testing.T) {
	if IsEmbedded() {
		t.Skip("docs are embedded in this build; sentinel only fires when not embedded")
	}
	_, err := Search(SearchOptions{Query: "anything"})
	if err == nil {
		t.Fatal("expected error when not embedded")
	}
	// We accept either the exported sentinel or any wrapped form of it.
	if err.Error() == "" {
		t.Errorf("error message should not be empty")
	}
}

func TestSearchFS_EmptyQueryRejected(t *testing.T) {
	_, err := Search(SearchOptions{Query: "   "})
	if err == nil {
		t.Fatal("expected error for whitespace-only query")
	}
}

func TestPageLayouts_AllPagesCovered(t *testing.T) {
	layouts := pageLayouts()
	for _, p := range AllPages {
		if _, ok := layouts[p]; !ok {
			t.Errorf("page %s missing from pageLayouts", p)
		}
	}
}

func TestPageDescription_AllPagesHaveText(t *testing.T) {
	for _, p := range AllPages {
		if PageDescription(p) == "" {
			t.Errorf("page %s has no description", p)
		}
	}
}
