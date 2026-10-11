package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
)

// archiveCall runs query_job_archive and returns its text and structured
// content.
func archiveCall(ctx context.Context, t *testing.T, s *Server, args map[string]interface{}) (string, map[string]interface{}) {
	t.Helper()
	params, err := json.Marshal(map[string]interface{}{"name": "query_job_archive", "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp := s.HandleMessage(ctx, &MCPMessage{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params})
	if resp.Error != nil {
		t.Fatalf("protocol error %v", resp.Error)
	}
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Structured map[string]interface{} `json:"structuredContent"`
		IsError    bool                   `json:"isError"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	if parsed.IsError {
		t.Fatalf("tool failed: %s", raw)
	}
	var text strings.Builder
	for _, c := range parsed.Content {
		text.WriteString(c.Text)
	}
	return text.String(), parsed.Structured
}

// The reported bug, schedd side: a busy access point's history holds more
// completions since the window a caller asks about than the schedd's default
// scan limit, so the schedd stops before reaching it and returns nothing. The
// answer must say the search was cut off, not look like "no such jobs".
func TestQueryJobArchiveReportsScanLimitCutoff(t *testing.T) {
	f := newActionScopeFixture(t)
	// alice's old jobs, then more than a default scan's worth of newer ones.
	total := htcondor.DefaultHistoryScanLimit + 50
	ads := make([]*classad.ClassAd, 0, total)
	for i := 0; i < total; i++ {
		ad := fakeschedd.JobAd(1000+i, 0, "alice", 4)
		ad.InsertAttr("CompletionDate", int64(1_000_000+i))
		ads = append(ads, ad)
	}
	f.schedd.AddHistory(ads...)
	alice := f.as(t, "alice", "mcp:read")

	text, sc := archiveCall(alice, t, f.server, map[string]interface{}{
		"constraint": "CompletionDate < 1000010",
		"limit":      float64(3),
	})
	if !strings.Contains(text, "Found 0 job history record(s)") {
		t.Fatalf("expected an empty answer from the cut-off scan: %q", text)
	}
	want := fmt.Sprintf("the schedd examined only the %d most recent history records", htcondor.DefaultHistoryScanLimit)
	if !strings.Contains(text, want) || !strings.Contains(text, "older records were not searched") {
		t.Errorf("text does not say the scan was cut off: %q", text)
	}
	if sc["scan_limit_reached"] != true {
		t.Errorf("scan_limit_reached = %v, want true", sc["scan_limit_reached"])
	}
	if sc["records_scanned"] != float64(htcondor.DefaultHistoryScanLimit) {
		t.Errorf("records_scanned = %v, want %d", sc["records_scanned"], htcondor.DefaultHistoryScanLimit)
	}

	// A query whose matches fill the limit within the scanned range is
	// complete as far as the caller is concerned: no cut-off note.
	text, sc = archiveCall(alice, t, f.server, map[string]interface{}{
		"constraint": fmt.Sprintf("CompletionDate >= %d", 1_000_000+total-2),
		"limit":      float64(2),
	})
	if !strings.Contains(text, "Found 2 job history record(s)") {
		t.Fatalf("expected the two newest records: %q", text)
	}
	if strings.Contains(text, "not searched") || sc["scan_limit_reached"] != false {
		t.Errorf("a complete answer must not report a cut-off: scan_limit_reached=%v text=%q", sc["scan_limit_reached"], text)
	}
}
