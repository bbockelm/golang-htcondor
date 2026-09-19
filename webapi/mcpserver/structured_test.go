package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestEveryServedToolHasOutputSchema is the drift guard: a tool added to the
// catalogue without an entry in outputSchemas would be served with no
// machine-readable result contract. The base catalogue a bare *Server
// serves is checked here; conditional families (credd, htcondordb, docs,
// skills, watches) are covered by TestOutputSchemaPolicyCoversConditionalTools.
func TestEveryServedToolHasOutputSchema(t *testing.T) {
	server := &Server{}
	tools := servedTools(t, server)
	if len(tools) == 0 {
		t.Fatal("bare server served no tools")
	}
	for _, tool := range tools {
		if tool.OutputSchema == nil {
			t.Errorf("tool %q is served without an output schema; add it to outputSchemas in structured.go", tool.Name)
		}
	}
}

// TestOutputSchemaPolicyCoversConditionalTools asserts the tools a bare
// server does not enable still have a published schema, so a new one cannot
// ship unschematised behind a feature flag.
func TestOutputSchemaPolicyCoversConditionalTools(t *testing.T) {
	conditional := []string{
		"condor_doc_job_attributes", "condor_doc_machine_attributes",
		"condor_doc_submit_syntax", "condor_doc_config_variables", "condor_doc_search",
		"skills_list", "skills_get",
		"list_service_credentials", "get_credential_status",
		"store_service_credential", "delete_service_credential",
		"query_history_db", "query_jobs_as_of", "aggregate_jobs",
		"watch_jobs", "check_watches", "cancel_watch",
	}
	for _, name := range conditional {
		if outputSchemaFor(name) == nil {
			t.Errorf("conditional tool %q has no output schema", name)
		}
	}
}

// TestOutputSchemaAppearsInWireJSON confirms the schema reaches the client
// on the tools/list response, keyed as "outputSchema".
func TestOutputSchemaAppearsInWireJSON(t *testing.T) {
	raw, _ := json.Marshal((&Server{}).handleListTools(context.Background(), nil))
	if !strings.Contains(string(raw), `"outputSchema"`) {
		t.Error("tools/list wire JSON carries no outputSchema")
	}
}

// TestHistoryResultCarriesStructuredContent pins that a history result ships
// the records as structuredContent, not only embedded in the text blob.
func TestHistoryResultCarriesStructuredContent(t *testing.T) {
	ad := classad.New()
	ad.InsertAttr("ClusterId", 5)
	res := historyResult([]*classad.ClassAd{ad}, "job history", "true", "JOB_HISTORY", "")
	m := res.(map[string]interface{})
	sc, ok := m["structuredContent"].(map[string]interface{})
	if !ok {
		t.Fatalf("no structuredContent on history result: %T", m["structuredContent"])
	}
	if sc["count"] != 1 || sc["type"] != "job history" || sc["source"] != "JOB_HISTORY" {
		t.Errorf("structuredContent fields wrong: %+v", sc)
	}
	recs, ok := sc["records"].([]*classad.ClassAd)
	if !ok || len(recs) != 1 {
		t.Errorf("structuredContent.records should carry the ads: %+v", sc["records"])
	}
}

// TestWithStructuredKeepsText confirms the helper adds structuredContent
// without disturbing the human-readable content block.
func TestWithStructuredKeepsText(t *testing.T) {
	base := map[string]interface{}{
		"content": []map[string]interface{}{{"type": "text", "text": "hi"}},
	}
	got := withStructured(base, map[string]interface{}{"x": 1})
	if got["structuredContent"].(map[string]interface{})["x"] != 1 {
		t.Error("structuredContent not attached")
	}
	if got["content"] == nil {
		t.Error("text content was dropped")
	}
}
