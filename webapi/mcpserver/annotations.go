package mcpserver

import "github.com/modelcontextprotocol/go-sdk/mcp"

// Tool behavioural hints (MCP spec revision 2026-07-28, ToolAnnotations).
//
// These let a client -- or the broker fronting this fleet -- reason about
// which calls are safe to retry, cache, or gate behind a confirmation
// prompt, without an out-of-band list of which condor tools write versus
// read. Until now that knowledge lived only in the broker; the spec wants
// it self-described on the tool declarations, which is what this file adds.
//
// We reuse the SDK's mcp.ToolAnnotations type rather than defining a
// parallel one so the hand-rolled JSON-RPC transport and the SDK transport
// emit byte-identical annotations and there is a single field set to track
// as the spec moves. In that type ReadOnlyHint and IdempotentHint are plain
// bools (always serialised); DestructiveHint and OpenWorldHint are *bool
// (omitted when nil).
//
// These are hints, not a trust boundary. The spec is explicit that a client
// must not use annotations from an untrusted server to make unilateral
// trust decisions, and the broker lints them against its own policy rather
// than trusting them blindly. They remain the only self-describing read/
// write signal a standalone Go MCP server has, so we declare them
// accurately regardless.

func boolPtr(v bool) *bool { return &v }

// readOnlyAnn describes a tool that changes no state. openWorld reports
// whether it reaches out to the pool/schedd/collector/credd (true) or
// answers from static knowledge embedded in this binary or this server's
// own bookkeeping (false). DestructiveHint and IdempotentHint are left at
// their zero values: the spec says both are meaningful only when
// ReadOnlyHint is false.
func readOnlyAnn(openWorld bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(openWorld)}
}

// writeAnn describes a state-changing tool. destructive means the call may
// overwrite or tear down existing state rather than only add to it;
// idempotent means repeating the call with the same arguments lands the
// environment in the same place (so a client may safely retry it).
//
// Every state-changing tool this server exposes acts on the pool/schedd/
// collector/credd, so openWorldHint is always true for a write and is not a
// parameter here.
func writeAnn(destructive, idempotent bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		DestructiveHint: boolPtr(destructive),
		IdempotentHint:  idempotent,
		OpenWorldHint:   boolPtr(true),
	}
}

// toolAnnotations is the behavioural-hint policy for every MCP tool this
// server can serve, conditional tools (credd, htcondordb, docs, skills,
// interactive sessions) included. toolsFor stamps these onto the catalogue
// it returns, so both transports serve them and the two never drift.
//
// The seven-tool destructive job-control surface follows the grouping in
// issue #391 verbatim -- submit_job included -- so the broker's
// confirmation policy sees the whole mutating surface as one class.
var toolAnnotations = map[string]*mcp.ToolAnnotations{
	// --- read-only, reaching into the pool/schedd/collector/credd ---
	"query_jobs":               readOnlyAnn(true),
	"get_job":                  readOnlyAnn(true),
	"analyze_job_match":        readOnlyAnn(true),
	"get_job_stdout":           readOnlyAnn(true),
	"get_job_stderr":           readOnlyAnn(true),
	"get_job_output":           readOnlyAnn(true),
	"query_job_archive":        readOnlyAnn(true),
	"query_job_epochs":         readOnlyAnn(true),
	"query_transfer_history":   readOnlyAnn(true),
	"query_history_db":         readOnlyAnn(true),
	"query_jobs_as_of":         readOnlyAnn(true),
	"aggregate_jobs":           readOnlyAnn(true),
	"list_service_credentials": readOnlyAnn(true),
	"get_credential_status":    readOnlyAnn(true),
	"tail_job_output":          readOnlyAnn(true),
	"interactive_session_list": readOnlyAnn(true),
	// watch_jobs observes the pool for a condition; it registers a watch in
	// this server's bookkeeping but touches no job, which is why the scope
	// model already treats it (and its two companions) as read-only.
	"watch_jobs": readOnlyAnn(true),

	// --- read-only, closed world: static docs, skills, and this server's
	// own version and watch bookkeeping ---
	"condor_doc_job_attributes":     readOnlyAnn(false),
	"condor_doc_machine_attributes": readOnlyAnn(false),
	"condor_doc_submit_syntax":      readOnlyAnn(false),
	"condor_doc_config_variables":   readOnlyAnn(false),
	"condor_doc_search":             readOnlyAnn(false),
	"skills_list":                   readOnlyAnn(false),
	"skills_get":                    readOnlyAnn(false),
	"get_version":                   readOnlyAnn(false),
	"whoami":                        readOnlyAnn(false),
	"check_watches":                 readOnlyAnn(false),
	"dag_status":                    readOnlyAnn(false),
	"cancel_watch":                  readOnlyAnn(false),

	// --- destructive job-control surface (issue #391) ---
	// submit_job is grouped here per the issue even though it only creates;
	// each call makes a new job, so it is not idempotent.
	"submit_job": writeAnn(true, false),
	// submit_dag creates a new workflow on every call, like submit_job.
	"submit_dag": writeAnn(true, false),
	// build_container submits a job like submit_job does. Not
	// idempotent: calling it again runs another build and overwrites
	// whatever is at the destination. Open-world because the image
	// lands in object storage outside the pool.
	"build_container": writeAnn(true, false),
	"hold_job":        writeAnn(true, true),
	"release_job":     writeAnn(true, true),
	"remove_job":      writeAnn(true, true),
	"remove_jobs":     writeAnn(true, true),
	"edit_job":        writeAnn(true, true),
	// advertise_to_collector re-publishes an ad; sending the same ad again
	// refreshes it to the same state, so it is idempotent.
	"advertise_to_collector": writeAnn(true, true),

	// --- other state-changing tools ---
	// upload_job_input only adds files to a job's spool (additive); the same
	// upload lands the spool in the same state.
	"upload_job_input": writeAnn(false, true),
	// create_input_upload_url does not touch the job -- it hands back a
	// capability. Minting a second URL for the same job neither replaces
	// the first nor changes anything, so: additive, and idempotent in the
	// only sense that matters (calling twice leaves the same state).
	"create_input_upload_url": writeAnn(false, true),
	// create_watch_url does not touch the watch -- it hands back a
	// read-only capability naming it. Minting a second URL for the same
	// watch neither replaces the first nor changes anything.
	"create_watch_url": writeAnn(false, true),
	// storing a credential overwrites any prior one for the service/handle;
	// deleting one removes it. Both are idempotent on a repeat.
	"store_service_credential":  writeAnn(true, true),
	"delete_service_credential": writeAnn(true, true),
	// interactive sessions: starting makes a new session (additive, not
	// idempotent); exec runs an arbitrary command in one (may destroy, not
	// idempotent); stopping tears one down (destructive, idempotent).
	"interactive_session_start": writeAnn(false, false),
	"interactive_session_exec":  writeAnn(true, false),
	"interactive_session_stop":  writeAnn(true, true),
	// exec_in_job runs an arbitrary command inside a live job.
	"exec_in_job": writeAnn(true, false),
}

// annotationsFor returns the behavioural hints for a tool, or nil if the
// tool has no policy entry. The returned pointer is shared and must not be
// mutated.
func annotationsFor(name string) *mcp.ToolAnnotations {
	return toolAnnotations[name]
}
