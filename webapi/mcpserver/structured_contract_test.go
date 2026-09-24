package mcpserver

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/google/jsonschema-go/jsonschema"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// These tests exist because the published outputSchema is enforced by the
// CLIENT, not by this server: a mismatch is invisible here and surfaces
// over there as the whole tool call failing. Every assertion below
// therefore runs the payload through the same JSON Schema validation a
// client does, against the schema this server actually publishes.
//
// The empty case is what they pin. A handler that appends into a nil slice
// is correct for every result with something in it, which is every result a
// test that submits a job and then queries for it will ever see.

// validateStructured checks a tool's structuredContent against the schema
// the server publishes for that tool, the way a client does: marshal, then
// validate the JSON value.
func validateStructured(t *testing.T, tool string, structured interface{}) {
	t.Helper()
	schema := outputSchemaFor(tool)
	if schema == nil {
		t.Fatalf("tool %q publishes no output schema", tool)
	}
	resolved := resolveSchema(t, schema)

	raw, err := json.Marshal(structured)
	if err != nil {
		t.Fatalf("%s: marshalling structuredContent: %v", tool, err)
	}
	var instance interface{}
	if err := json.Unmarshal(raw, &instance); err != nil {
		t.Fatalf("%s: unmarshalling structuredContent: %v", tool, err)
	}
	if err := resolved.Validate(instance); err != nil {
		t.Errorf("%s: structuredContent does not satisfy its published output schema: %v\npayload: %s",
			tool, err, raw)
	}
}

func resolveSchema(t *testing.T, schema map[string]interface{}) *jsonschema.Resolved {
	t.Helper()
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshalling the schema: %v", err)
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("the published schema is not a JSON Schema: %v", err)
	}
	resolved, err := s.Resolve(nil)
	if err != nil {
		t.Fatalf("resolving the published schema: %v", err)
	}
	return resolved
}

// finalized runs a result through the dispatcher's contract step and hands
// back its structuredContent, so a test asserts on what the wire carries
// rather than on what the handler happened to build.
func finalized(t *testing.T, s *Server, tool string, result interface{}) interface{} {
	t.Helper()
	out, ok := s.finalizeToolResult(tool, result).(map[string]interface{})
	if !ok {
		t.Fatalf("%s: result is %T, want a map", tool, result)
	}
	sc, ok := out["structuredContent"]
	if !ok {
		t.Fatalf("%s: the result carries no structuredContent, so a client rejects it wholesale", tool)
	}
	return sc
}

func contractServer(t *testing.T) *Server {
	t.Helper()
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return &Server{logger: lg}
}

// --- the three defects seen on a live access point -----------------------

// TestQueryJobsWithNoMatchesIsAnEmptyArray is the first, reported as
// "Structured content does not match the tool's output schema: data/jobs
// must be array".
//
// The constraint matched nothing, so the handler's `var jobAds
// []*classad.ClassAd` was still nil, and nil marshals to null. "No jobs
// matched" is an ordinary answer and it was the only one the tool could not
// return.
func TestQueryJobsWithNoMatchesIsAnEmptyArray(t *testing.T) {
	s := contractServer(t)

	// Exactly what toolQueryJobs builds when the stream yielded no ads.
	_, metadata, structured := renderJobsBase(nil, `Owner == "nobody"`, "schedd", "")
	result := withStructured(map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": ""}},
		"metadata": metadata,
	}, structured)

	sc := finalized(t, s, "query_jobs", result)

	raw, err := json.Marshal(sc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), `"jobs":null`) {
		t.Errorf("a query matching nothing emitted jobs:null, which fails the client's schema check: %s", raw)
	}
	if !strings.Contains(string(raw), `"jobs":[]`) {
		t.Errorf("an empty job list should be [], got: %s", raw)
	}
	validateStructured(t, "query_jobs", sc)
}

// TestWhoamiCarriesStructuredContent is the second, reported as "Tool
// whoami has an output schema but did not return structured content".
//
// The handler marshalled its report into the TEXT block and returned no
// structuredContent at all, so the tool failed on every call from the day
// it shipped; nothing about a particular deployment made the difference.
func TestWhoamiCarriesStructuredContent(t *testing.T) {
	s := whoamiServer(t, "bbockelm@ap2001.chtc.wisc.edu")
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "bbockelm@ap2001.chtc.wisc.edu")

	res, err := s.toolWhoami(ctx, nil)
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	// Read the handler's own result, not the repaired one: the contract
	// step has no metadata to fall back on here, but asserting on the
	// handler keeps this test about the handler.
	m0, _ := res.(map[string]interface{})
	sc, ok := m0["structuredContent"]
	if !ok {
		t.Fatal("whoami returned no structuredContent; the report was only in the text block")
	}
	validateStructured(t, "whoami", sc)

	raw, _ := json.Marshal(sc)
	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("whoami structuredContent is not an object: %v", err)
	}
	if got["admin"] != true {
		t.Errorf("structuredContent.admin should report the read tier, got %v", got["admin"])
	}
	if got["authenticated_user"] != "bbockelm@ap2001.chtc.wisc.edu" {
		t.Errorf("structuredContent.authenticated_user = %v", got["authenticated_user"])
	}
}

// TestWhoamiScopesAreAnArray: the published schema typed oauth_scopes as an
// object while the report has always carried a list of scope strings. The
// disagreement was unreachable only because no structured content was sent;
// fixing the missing payload without this would have traded one client
// rejection for another, on any caller whose token carries scopes.
func TestWhoamiScopesAreAnArray(t *testing.T) {
	s := whoamiServer(t)
	ctx := WithGrantedScopes(
		htcondor.WithAuthenticatedUser(context.Background(), "carol@uid.domain"),
		[]string{"openid", "mcp:read"})

	res, err := s.toolWhoami(ctx, nil)
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	sc := res.(map[string]interface{})["structuredContent"]
	validateStructured(t, "whoami", sc)

	raw, _ := json.Marshal(sc)
	if !strings.Contains(string(raw), `"oauth_scopes":["mcp:read","openid"]`) {
		t.Errorf("oauth_scopes should be the sorted scope list, got: %s", raw)
	}
}

// TestBuildContainerCarriesStructuredContent is the third, and the one that
// cost something: the build job was submitted and its inputs spooled, and
// only the response failed the contract. The caller was told the build had
// failed, and a retry submits a second one.
func TestBuildContainerCarriesStructuredContent(t *testing.T) {
	res := buildContainerResult(15690296, "alpine-py.sif",
		"osdf:///ospool/ap40/data/brian.bockelman.1/alpine-py.sif",
		"python3 -c 'print(1)'", 2, 4096, 8192)

	// Read straight off the handler's own result, not through
	// finalizeToolResult: the contract step would promote this tool's
	// metadata and hide the omission, and the handler is what is fixed.
	sc, ok := res["structuredContent"]
	if !ok {
		t.Fatal("build_container returned only the content envelope and metadata, " +
			"so a client rejects a build that was already submitted")
	}
	validateStructured(t, "build_container", sc)

	m, _ := sc.(map[string]interface{})
	if m["cluster_id"] != 15690296 || m["job_id"] != "15690296.0" {
		t.Errorf("structuredContent must identify the submitted job, got %+v", m)
	}
	// The text block still has to be there: it is what the model reads.
	if c, _ := res["content"].([]map[string]interface{}); len(c) == 0 ||
		!strings.Contains(c[0]["text"].(string), "15690296.0") {
		t.Errorf("the human-readable block was lost: %+v", res["content"])
	}
}

// TestDispatchDeliversAValidStructuredResult walks the path a real call
// takes -- handleCallTool, the handler, the contract step -- for the one
// schematised tool a server with no schedd, credd or collector can run to
// completion. It is the end-to-end check that nothing between the handler
// and the transport drops structuredContent.
func TestDispatchDeliversAValidStructuredResult(t *testing.T) {
	s := whoamiServer(t, "bbockelm@ap2001.chtc.wisc.edu")
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "bbockelm@ap2001.chtc.wisc.edu")

	res, err := s.handleCallTool(ctx, json.RawMessage(`{"name":"whoami","arguments":{}}`))
	if err != nil {
		t.Fatalf("whoami through the dispatcher: %v", err)
	}
	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("dispatcher returned %T", res)
	}
	sc, ok := m["structuredContent"]
	if !ok {
		t.Fatal("the dispatched result carries no structuredContent")
	}
	validateStructured(t, "whoami", sc)
	if c, _ := m["content"].([]map[string]interface{}); len(c) == 0 {
		t.Error("the dispatched result lost its text block")
	}
}

// --- what the audit turned up --------------------------------------------

// TestHistoryWithNoRecordsIsAnEmptyArray: historyResult is the shared
// constructor behind query_job_archive, query_job_epochs and
// query_transfer_history, and it has the same nil-slice shape query_jobs
// had. Unreported only because a history query rarely matches nothing.
func TestHistoryWithNoRecordsIsAnEmptyArray(t *testing.T) {
	s := contractServer(t)
	for _, tool := range []string{"query_job_archive", "query_job_epochs", "query_transfer_history"} {
		t.Run(tool, func(t *testing.T) {
			sc := finalized(t, s, tool, historyResult(nil, "job history", "true", "JOB_HISTORY", ""))
			raw, _ := json.Marshal(sc)
			if strings.Contains(string(raw), `"records":null`) {
				t.Errorf("an empty history emitted records:null: %s", raw)
			}
			validateStructured(t, tool, sc)
		})
	}
}

// TestAggregateWithoutGroupByIsAnEmptyArray: aggregate_jobs takes group_by
// straight from the caller's arguments, so omitting it leaves a nil slice,
// and the single ungrouped row's key is nil for the same call -- a null
// nested one level inside the declared array of objects.
func TestAggregateWithoutGroupByIsAnEmptyArray(t *testing.T) {
	s := contractServer(t)

	groups := []map[string]interface{}{{"key": []string(nil), "count": "42"}}
	structured := aggregateStructured(groups, nil, "jobs", "schedd", false)
	sc := finalized(t, s, "aggregate_jobs", structuredTextResult("", structured))

	raw, _ := json.Marshal(sc)
	if strings.Contains(string(raw), `"group_by":null`) {
		t.Errorf("an ungrouped aggregate emitted group_by:null: %s", raw)
	}
	if strings.Contains(string(raw), `"key":null`) {
		t.Errorf("the ungrouped row emitted key:null: %s", raw)
	}
	validateStructured(t, "aggregate_jobs", sc)
}

// --- the chokepoint itself -----------------------------------------------

// TestFinalizePromotesMetadataWhenStructuredContentIsMissing is the net
// under the next handler to make build_container's mistake. Throughout this
// server metadata and structuredContent carry the same map; a handler that
// filled in only the first has published the payload under the older name.
func TestFinalizePromotesMetadataWhenStructuredContentIsMissing(t *testing.T) {
	s := contractServer(t)

	res := s.finalizeToolResult("remove_job", map[string]interface{}{
		"content":  []map[string]interface{}{{"type": "text", "text": "done"}},
		"metadata": map[string]interface{}{"job_id": "1.0", "action": "remove", "success": true},
	})
	m := res.(map[string]interface{})
	sc, ok := m["structuredContent"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata was not promoted: %+v", m)
	}
	if sc["job_id"] != "1.0" {
		t.Errorf("the promoted payload is wrong: %+v", sc)
	}
	validateStructured(t, "remove_job", sc)
}

// A tool with no published schema promises nothing, so nothing is repaired:
// promoting metadata there would invent a contract the catalogue never
// stated.
func TestFinalizeLeavesUnschematisedToolsAlone(t *testing.T) {
	s := contractServer(t)
	res := s.finalizeToolResult("no_such_tool", map[string]interface{}{
		"metadata": map[string]interface{}{"x": 1},
	})
	if _, has := res.(map[string]interface{})["structuredContent"]; has {
		t.Error("a tool with no output schema was given structuredContent")
	}
}

// A handler that already said what it meant must not be second-guessed.
func TestFinalizeDoesNotOverwriteStructuredContent(t *testing.T) {
	s := contractServer(t)
	res := s.finalizeToolResult("remove_job", map[string]interface{}{
		"structuredContent": map[string]interface{}{"job_id": "2.0", "action": "remove", "success": true},
		"metadata":          map[string]interface{}{"job_id": "wrong"},
	})
	sc := res.(map[string]interface{})["structuredContent"].(map[string]interface{})
	if sc["job_id"] != "2.0" {
		t.Errorf("metadata overwrote the handler's own payload: %+v", sc)
	}
}

// TestEmptyNotNullDoesNotWriteWhenNothingChanges: a payload can share a map
// with state the server keeps (the match analyzer's slot-cache status), so
// an unconditional write-back would be a write to shared state on every
// call.
func TestEmptyNotNullDoesNotWriteWhenNothingChanges(t *testing.T) {
	shared := map[string]interface{}{"hits": 3, "names": []string{"a"}}
	before := reflect.ValueOf(shared).Pointer()

	got, changed := emptyNotNull(shared)
	if changed {
		t.Error("a payload with nothing nil in it reported a change")
	}
	if reflect.ValueOf(got).Pointer() != before {
		t.Error("the map was copied rather than left alone")
	}

	// That it is not WRITTEN is something Go cannot observe directly --
	// only the race detector can, by reading the map from another
	// goroutine at the same time. Under -race an unconditional write-back
	// fails here; without -race this is just a second call.
	t.Run("concurrent reader", func(_ *testing.T) {
		clean := map[string]interface{}{"hits": 3, "names": []string{"a"}}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; i < 500; i++ {
				_ = clean["hits"]
			}
		}()
		for i := 0; i < 500; i++ {
			emptyNotNull(clean)
		}
		<-done
	})
}

func TestEmptyNotNullReplacesNilCollections(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   interface{}
		want string
	}{
		{"nil typed slice", []string(nil), `[]`},
		{"nil ad slice", []*classad.ClassAd(nil), `[]`},
		{"nil map", map[string]string(nil), `{}`},
		{"nested in a map", map[string]interface{}{"xs": []int(nil)}, `{"xs":[]}`},
		{"nested in a slice of maps",
			[]map[string]interface{}{{"xs": []string(nil)}}, `[{"xs":[]}]`},
		{"nested in a slice of any",
			[]interface{}{map[string]interface{}{"xs": []string(nil)}}, `[{"xs":[]}]`},
		// The element is itself the nil one, so repairing it means
		// writing back into the slice rather than mutating in place.
		{"a nil slice inside a slice", []interface{}{[]string(nil)}, `[[]]`},
		{"non-empty is untouched", []string{"a"}, `["a"]`},
		{"bytes are left alone", []byte("hi"), `"aGk="`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := emptyNotNull(tc.in)
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(raw) != tc.want {
				t.Errorf("emptyNotNull(%#v) marshalled to %s, want %s", tc.in, raw, tc.want)
			}
		})
	}
}

// --- the whole surface ----------------------------------------------------

// TestOutputSchemasAreValidJSONSchema: a schema that does not compile
// cannot be enforced, and the client's failure would name the payload
// rather than the schema.
func TestOutputSchemasAreValidJSONSchema(t *testing.T) {
	for name, schema := range outputSchemas {
		t.Run(name, func(t *testing.T) { resolveSchema(t, schema) })
	}
}

// emptyCase is one tool's answer when the answer is nothing: the payload a
// handler builds with no rows, no files, no matches -- collections left as
// the Go code leaves them, which for an accumulate-with-append handler is
// nil.
type emptyCase struct {
	tool    string
	payload interface{}
}

// emptyCases is the empty answer for every tool that publishes an output
// schema. Where a shared constructor exists the payload comes from it, so
// the case tracks the product code; the rest mirror what the handler
// builds, with each collection-valued field nil, which is the shape that
// broke query_jobs on a live access point.
//
// TestEveryOutputSchemaHasAnEmptyCase keeps the list exhaustive: a new
// schematised tool reddens the suite until its empty answer is written down
// here and shown to validate.
func emptyCases(t *testing.T) []emptyCase {
	t.Helper()
	structuredOf := func(result interface{}) interface{} {
		m, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("result is %T, want a map", result)
		}
		return m["structuredContent"]
	}
	_, _, jobs := renderJobsBase(nil, "true", "schedd", "")

	return []emptyCase{
		{"query_jobs", jobs},
		{"query_job_archive", structuredOf(historyResult(nil, "job history", "true", "JOB_HISTORY", ""))},
		{"query_job_epochs", structuredOf(historyResult(nil, "epoch", "true", "JOB_EPOCH_HISTORY", ""))},
		{"query_transfer_history", structuredOf(historyResult(nil, "transfer", "true", "JOB_EPOCH_HISTORY", ""))},
		{"query_history_db", structuredOf(dbTextResult("records", nil, 50, nil, OwnerScope{}))},
		{"query_jobs_as_of", structuredOf(dbTextResult("records", nil, 50, nil, OwnerScope{}))},
		{"aggregate_jobs", aggregateStructured(nil, nil, "jobs", "schedd", false)},
		// An access point with nothing wrong is the normal case, and the
		// one where a client's schema check would otherwise first run on
		// a live call: sections is an empty array, never null.
		{"analyze_issues", structuredOf(emptyIssuesResult())},
		// The dag object is absent here on purpose: it is present only
		// for a DAGMan manager job, and the emptiest get_job result is
		// an ordinary job's. The shape it takes when it IS present --
		// a manager job before DAGMan has published anything, so only
		// the manager's own status is known -- is checked separately in
		// TestGetJobDagSectionValidatesAgainstTheSchema.
		{"get_job", map[string]interface{}{"job_id": "1.0", "job": map[string]interface{}{}}},
		{"analyze_job_match", map[string]interface{}{
			"job_id": "1.0", "requirements": "", "result": nil, "slot_cache": nil}},

		{"submit_job", map[string]interface{}{
			"cluster_id": 0, "job_ids": []string(nil), "proc_count": 0,
			"needs_upload": false, "warnings": []string(nil)}},
		// submit_dag: a workflow with nothing referenced and nothing
		// outstanding. Slices are nil rather than empty because that is
		// what the analysis returns when it found nothing.
		{"submit_dag", map[string]interface{}{
			"cluster_id": 0, "job_id": "0.0", "dag_name": "workflow.dag",
			"input_files": []string(nil), "notes": []string(nil), "deferred": []string(nil)}},
		{"build_container", structuredOf(buildContainerResult(0, "", "", "", 0, 0, 0))},
		{"remove_job", map[string]interface{}{"job_id": "1.0", "action": "remove", "success": true}},
		{"hold_job", map[string]interface{}{"job_id": "1.0", "action": "hold", "success": true}},
		{"release_job", map[string]interface{}{"job_id": "1.0", "action": "release", "success": true}},
		{"remove_jobs", map[string]interface{}{
			"action": "remove", "constraint": "", "total": 0,
			"success": 0, "permission_denied": 0, "not_found": 0}},
		{"edit_job", map[string]interface{}{
			"job_id": "1.0", "attributes": map[string]interface{}(nil), "notes": []string(nil)}},
		{"advertise_to_collector", map[string]interface{}{
			"advertised": true, "ad_name": "", "ad_type": "", "with_ack": false}},

		{"get_job_stdout", map[string]interface{}{
			"job_id": "1.0", "output_type": "stdout", "filename": "", "size": 0,
			"empty": true, "content": ""}},
		{"get_job_stderr", map[string]interface{}{
			"job_id": "1.0", "output_type": "stderr", "filename": "", "size": 0,
			"empty": true, "content": ""}},
		{"get_job_output", map[string]interface{}{
			"job_id": "1.0", "file_count": 0, "files": []OutputFile(nil)}},
		{"upload_job_input", map[string]interface{}{
			"job_id": "1.0", "files": []string(nil), "file_count": 0,
			"total_size": 0, "released": true}},
		// A watch URL always names a watch; the "empty" case is the one
		// where the watch carries no optional detail yet.
		{"create_watch_url", map[string]interface{}{
			"url": "", "watch_id": "", "owner": "", "event": "", "label": "",
			"expires_at": "", "ttl_seconds": 0,
			"max_wait_seconds": 0, "default_wait_seconds": 0}},

		{"create_input_upload_url", map[string]interface{}{
			"cluster_id": 0, "owner": "", "expires_at": "", "ttl_seconds": 0,
			"count": 0, "uploads": []map[string]interface{}(nil)}},

		{"list_service_credentials", map[string]interface{}{
			"credentials": []map[string]interface{}(nil), "count": 0}},
		{"get_credential_status", map[string]interface{}{
			"service": "s", "handle": "", "exists": false}},
		{"store_service_credential", map[string]interface{}{
			"service": "s", "handle": "", "stored": true}},
		{"delete_service_credential", map[string]interface{}{
			"service": "s", "handle": "", "deleted": true}},

		{"condor_doc_search", docEmpty()},
		{"condor_doc_job_attributes", docEmpty()},
		{"condor_doc_machine_attributes", docEmpty()},
		{"condor_doc_submit_syntax", docEmpty()},
		{"condor_doc_config_variables", docEmpty()},
		{"skills_list", map[string]interface{}{"skills": []interface{}(nil), "count": 0}},
		{"skills_get", map[string]interface{}{"name": "n", "description": "", "content": ""}},

		{"watch_jobs", map[string]interface{}{
			"watch_id": "w1", "event": "done", "constraint": "", "fired": false}},
		{"check_watches", map[string]interface{}{
			"watches": []map[string]interface{}(nil), "count": 0,
			"new_count": 0, "waiting_count": 0}},
		{"cancel_watch", map[string]interface{}{"watch_id": "w1", "cancelled": true}},

		{"interactive_session_start", map[string]interface{}{
			"session": "s", "job_id": "1.0", "job_status": 1, "status": "queued"}},
		{"interactive_session_exec", map[string]interface{}{
			"job_id": "1.0", "stdout": "", "stderr": "", "exit_code": 0}},
		{"interactive_session_list", map[string]interface{}{
			"sessions": []map[string]interface{}(nil), "count": 0}},
		{"interactive_session_stop", map[string]interface{}{
			"session": "s", "job_id": "1.0", "stopped": true}},
		{"exec_in_job", map[string]interface{}{
			"job_id": "1.0", "stdout": "", "stderr": "", "exit_code": 0}},
		{"tail_job_output", map[string]interface{}{
			"job_id": "1.0", "stdout": "", "stderr": "",
			"stdout_offset": 0, "stderr_offset": 0}},

		{"get_version", map[string]interface{}{"Module": "", "Revision": "", "Dirty": false}},
		{"whoami", whoamiReport{}},
	}
}

// docEmpty is the no-hits payload every condor_doc_* tool shares.
func docEmpty() map[string]interface{} {
	return map[string]interface{}{"query": "x", "results": []interface{}{}, "count": 0}
}

// TestEveryEmptyResultValidatesAgainstItsSchema is the class-wide guard: for
// every tool that publishes a schema, the answer "nothing" has to be a legal
// answer. Each payload goes through the dispatcher's contract step first,
// because that is what the wire carries.
func TestEveryEmptyResultValidatesAgainstItsSchema(t *testing.T) {
	s := contractServer(t)
	for _, tc := range emptyCases(t) {
		t.Run(tc.tool, func(t *testing.T) {
			sc := finalized(t, s, tc.tool, structuredTextResult("", tc.payload))
			validateStructured(t, tc.tool, sc)

			raw, _ := json.Marshal(sc)
			if strings.Contains(string(raw), `:null`) {
				// Not a failure on its own -- a permissive schema allows
				// null -- but worth reading when one of these does break.
				t.Logf("%s empty payload contains a null: %s", tc.tool, raw)
			}
		})
	}
}

// TestEveryOutputSchemaHasAnEmptyCase keeps the table above exhaustive.
// Without it the guard silently stops covering whatever was added last,
// which is the tool most likely to have the defect.
func TestEveryOutputSchemaHasAnEmptyCase(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range emptyCases(t) {
		if covered[tc.tool] {
			t.Errorf("duplicate empty case for %q", tc.tool)
		}
		covered[tc.tool] = true
	}
	var missing []string
	for name := range outputSchemas {
		if !covered[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these tools publish an output schema with no empty case in emptyCases(): %s\n"+
			"add what the tool returns when it finds nothing, so the client's schema check is exercised here "+
			"rather than on a live call that happens to match no rows", strings.Join(missing, ", "))
	}
	for name := range covered {
		if outputSchemaFor(name) == nil {
			t.Errorf("emptyCases() lists %q, which publishes no output schema", name)
		}
	}
}

// TestGetJobDagSectionValidatesAgainstTheSchema. The dag object is
// optional, so the empty-result guard above cannot cover it: the
// emptiest get_job result is an ordinary job's, which has none. This is
// the first answer a caller gets after submit_dag -- the manager job
// held for spooling, DAGMan not yet started -- and the fullest one.
func TestGetJobDagSectionValidatesAgainstTheSchema(t *testing.T) {
	s := contractServer(t)
	for _, tc := range []struct {
		name string
		dag  map[string]interface{}
	}{
		{"nothing published yet", map[string]interface{}{"job_status": 5, "hold_reason_code": 16}},
		{"running workflow", dagStructuredFields(dagAd(t, map[string]interface{}{
			"JobStatus": 2, "DAG_Status": 0, "DAG_NodesTotal": 3, "DAG_NodesDone": 1,
			"DAG_NodesQueued": 1, "DAG_NodesUnready": 1, "DAG_JobsRunning": 1,
			"Arguments": "-f -l . -Dag diamond.dag",
		}))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]interface{}{
				"job_id": "1.0", "job": map[string]interface{}{}, "dag": tc.dag,
			}
			sc := finalized(t, s, "get_job", structuredTextResult("", payload))
			validateStructured(t, "get_job", sc)
		})
	}
}
