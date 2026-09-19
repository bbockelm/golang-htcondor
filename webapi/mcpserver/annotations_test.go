package mcpserver

import (
	"context"
	"testing"
)

// TestEveryServedToolIsAnnotated is the drift guard: a tool added to the
// catalogue without a matching entry in toolAnnotations would be served
// with no behavioural hints, silently defaulting (per the spec) to the
// most permissive interpretation -- not read-only, not destructive. The
// base catalogue a bare *Server serves is enumerated here; the
// conditional families (credd, htcondordb, docs, skills) are covered by
// TestToolAnnotationPolicyCoversConditionalTools below.
func TestEveryServedToolIsAnnotated(t *testing.T) {
	server := &Server{}
	tools := servedTools(t, server)
	if len(tools) == 0 {
		t.Fatal("bare server served no tools")
	}
	for _, tool := range tools {
		if tool.Annotations == nil {
			t.Errorf("tool %q is served without annotations; add it to toolAnnotations in annotations.go", tool.Name)
		}
	}
}

// TestToolAnnotationPolicyCoversConditionalTools asserts every tool name
// this package can declare has a policy entry, including the families a
// bare *Server does not enable. If a new tool is added, listing it here
// makes the omission a compile-time-visible test failure rather than a
// silent unannotated tool in production.
func TestToolAnnotationPolicyCoversConditionalTools(t *testing.T) {
	conditional := []string{
		// docs
		"condor_doc_job_attributes", "condor_doc_machine_attributes",
		"condor_doc_submit_syntax", "condor_doc_config_variables", "condor_doc_search",
		// skills
		"skills_list", "skills_get",
		// credd
		"list_service_credentials", "get_credential_status",
		"store_service_credential", "delete_service_credential",
		// htcondordb
		"query_history_db", "query_jobs_as_of", "aggregate_jobs",
		// watches
		"watch_jobs", "check_watches", "cancel_watch",
		// interactive sessions + live-job reach
		"interactive_session_start", "interactive_session_exec",
		"interactive_session_list", "interactive_session_stop",
		"tail_job_output", "exec_in_job",
	}
	for _, name := range conditional {
		if annotationsFor(name) == nil {
			t.Errorf("conditional tool %q has no annotation policy entry", name)
		}
	}
}

// TestDestructiveSurfaceAnnotations pins the seven-tool destructive
// job-control surface called out in issue #391: each must declare itself
// writable and destructive so the broker's confirmation policy can key on
// it. A regression that flips one of these to read-only would let a
// destructive call through an auto-approve path.
func TestDestructiveSurfaceAnnotations(t *testing.T) {
	destructive := []string{
		"submit_job", "hold_job", "release_job",
		"remove_job", "remove_jobs", "edit_job", "advertise_to_collector",
	}
	for _, name := range destructive {
		ann := annotationsFor(name)
		if ann == nil {
			t.Errorf("%s: no annotations", name)
			continue
		}
		if ann.ReadOnlyHint {
			t.Errorf("%s: readOnlyHint is true, want false", name)
		}
		if ann.DestructiveHint == nil || !*ann.DestructiveHint {
			t.Errorf("%s: destructiveHint is not true", name)
		}
	}
}

// TestReadOnlyQueryAnnotations pins the query/read surface as read-only so
// a regression cannot silently make a client treat a read as a write (or
// vice versa).
func TestReadOnlyQueryAnnotations(t *testing.T) {
	readOnly := []string{
		"query_jobs", "get_job", "analyze_job_match",
		"get_job_stdout", "get_job_stderr", "get_job_output",
		"query_job_archive", "query_job_epochs", "query_transfer_history",
		"query_history_db", "query_jobs_as_of", "aggregate_jobs",
		"condor_doc_search", "get_version",
	}
	for _, name := range readOnly {
		ann := annotationsFor(name)
		if ann == nil {
			t.Errorf("%s: no annotations", name)
			continue
		}
		if !ann.ReadOnlyHint {
			t.Errorf("%s: readOnlyHint is false, want true", name)
		}
		// Per the spec, destructiveHint is meaningful only when the tool is
		// not read-only; leave it unset on read-only tools.
		if ann.DestructiveHint != nil {
			t.Errorf("%s: destructiveHint set on a read-only tool", name)
		}
	}
}

// servedTools calls the real tools/list path and returns the catalogue.
func servedTools(t *testing.T, s *Server) []Tool {
	t.Helper()
	result := s.handleListTools(context.Background(), nil)
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("handleListTools returned %T, want map", result)
	}
	tools, ok := m["tools"].([]Tool)
	if !ok {
		t.Fatalf("tools field is %T, want []Tool", m["tools"])
	}
	return tools
}
