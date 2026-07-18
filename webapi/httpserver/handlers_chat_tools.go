package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/condordocs"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/chat"
)

// chatToolDeps is the interface a tool implementation needs satisfied
// from the surrounding Handler. Pulled to a small interface so the
// tool tests can inject fakes (schedd, collector) without spinning
// up the whole HTTP server. Add new dependencies (e.g. credd, a
// metrics handle) here when a tool needs them so the tests get the
// same injection surface for free.
type chatToolDeps interface {
	getSchedd() *htcondor.Schedd
	getCollector() *htcondor.Collector
}

// chatTool is a small concrete struct that satisfies chat.Tool with
// fields instead of methods on a per-tool type. Cuts boilerplate —
// every tool below is a `chatTool{...}` literal plus an Execute
// closure.
type chatTool struct {
	name        string
	description string
	schema      json.RawMessage
	clientSide  bool
	confirm     bool
	// pages restricts the tool to specific SPA pages. Empty means
	// the tool is universally available — the convention for tools
	// whose effect makes sense everywhere (doc lookups, slot status).
	// Use snake_case page identifiers matching what the SPA sends in
	// Request.Page (e.g. "jobs", "submit").
	pages []string
	exec  func(ctx context.Context, actor string, input json.RawMessage) (string, error)
}

func (t *chatTool) Name() string                 { return t.name }
func (t *chatTool) Description() string          { return t.description }
func (t *chatTool) InputSchema() json.RawMessage { return t.schema }
func (t *chatTool) ClientSide() bool             { return t.clientSide }
func (t *chatTool) RequiresConfirmation() bool   { return t.confirm }
func (t *chatTool) AvailablePages() []string     { return t.pages }
func (t *chatTool) Execute(ctx context.Context, actor string, in json.RawMessage) (string, error) {
	if t.exec == nil {
		// Client-side tool: the engine never calls Execute on a
		// client-side tool, but a misconfigured registry shouldn't
		// silently pass.
		return "", errors.New("chat: tool has no server-side executor")
	}
	return t.exec(ctx, actor, in)
}

// jobsPageTools and submitPageTools are the canonical page tags used
// throughout the chat tool registry. Concentrating the strings here
// keeps the tool definitions below uniform and prevents typos like
// "job" vs "jobs" silently making a tool invisible.
var (
	jobsPageTools      = []string{"jobs"}
	submitPageTools    = []string{"submit"}
	jobDetailPageTools = []string{"job-detail"}
	archivePageTools   = []string{"archive"}
)

// jobsPageInstructions is appended to the chat system prompt when the
// SPA reports `page=jobs`.
//
// === KEEP IN SYNC WITH frontend/src/app/jobs/page.tsx ===
// If you remove a column from the jobs table, change what set_filter
// matches against, or alter how expanded rows render, update the
// matching language here so the LLM doesn't hallucinate UI affordances.
const jobsPageInstructions = `The user is on the jobs page. They see a single table grouped
by batch (one row per cluster) with running/idle/held/etc. status counts. They can expand
a batch row to see individual jobs. You have tools to:
  - filter the table to a substring (set_filter)
  - expand a batch row (expand_batch)
  - flash a job row to draw attention (highlight_job)
  - read the user's job state (query_jobs)
  - hold/release/remove a single job (those require user confirmation)
  - bulk-remove jobs (remove_jobs — takes a cluster_id OR a ClassAd constraint and
    removes every match, capped at 1000 per call. Confirmation required.)
  - edit attributes on every job matching a constraint (edit_jobs_by_constraint).
    The user does NOT have a UI for bulk edit — this tool exists specifically so
    you can do "raise JobPrio to 10 on all my held jobs in this batch" or "clear
    PeriodicHold on every idle job in cluster 42" in one round trip. The
    'attributes' values must be ClassAd-encoded: strings need quotes ("ok"),
    integers / reals are bare digits, booleans are true/false. Requires user
    confirmation.
Use the UI tools to direct the user's eye after answering — e.g. if they ask "why is my
training run held", filter to that batch and expand it.

BULK REMOVE WORKFLOW (remove_jobs):
  1. Run query_jobs FIRST with the same constraint so you can tell the user the count
     before they see the approval card. "This will remove 47 jobs from batch 42 —
     proceed?" is much better UX than the user squinting at the raw constraint string.
  2. Call remove_jobs with cluster_id (when the user said "the whole batch N") OR
     constraint (status / batch-name / age filters, etc.). The two are mutually
     exclusive — passing both is rejected.
  3. Server caps each call at 1000 affected jobs. If query_jobs reports more than that,
     narrow the filter (e.g. add a JobStatus or QDate clause) and run multiple calls.
     Don't loop quietly to bypass the cap — ask the user.
  4. Owner-scoping is enforced server-side regardless of what you put in 'constraint';
     you cannot match other users' jobs.`

// submitPageInstructions is appended to the chat system prompt when the
// SPA reports `page=submit`.
//
// === KEEP IN SYNC WITH frontend/src/app/submit/page.tsx ===
// If you remove a section, rename a state field a tool writes to, or
// change the submit flow, update the matching language here so the LLM
// doesn't hallucinate UI affordances.
const submitPageInstructions = `The user is on the job-submission page. They are assembling
one or more HTCondor jobs but have NOT submitted yet. The page has four sections:
  1. Template — pick from a library or write a custom submit-file body
  2. Table — one row per job, columns named by template variables
  3. Inputs — shared input files (template defaults plus user-dropped)
  4. Resources — optional CPU/memory/disk override

THE WORKFLOW:
  step 1. Pick (or scaffold) a template that defines the per-job submit-file body
          and which columns the table will use.
  step 2. Provide per-job parameters. Three options:
            - set_table_rows — one row per job, cells fill column variables. The
              page synthesizes "queue <cols> from ((...))" automatically.
            - set_table_count — N identical jobs (HTCondor "queue N"). Use when
              the body needs only $(ProcId)-based variation, or for a one-off
              "just run it once" job. Default count is 1.
            - the user picks a directory / tarball in the table UI; one job per
              file. You don't have a tool for this; suggest it manually.
          For zero-column templates, set_table_count is the natural choice.
  step 3. Optionally attach shared input files or override resources.
  step 4. The HUMAN clicks Submit. You CANNOT submit on their behalf — there is no
          submit tool, by design. If the user asks you to submit, decline politely
          and remind them to click Submit themselves.

CONTINUATION RULE (very important): you operate in a multi-step workflow with
many tools. After a tool returns successfully, IMMEDIATELY continue with the
next step on the same turn — do not pause to ask the user for confirmation.
Examples of when to keep going on your own:
  - You called list_submit_templates; now activate the right one.
  - You called select_template; now if edits are needed, fork to custom and edit.
  - You set the template body; now set table rows or count.
  - You set the rows/count; now hand off in prose + highlight_section("submit").
A reply that ends after one or two tool calls with no final hand-off prose is a
bug. Stop ONLY when: (a) the user's request is fully done AND you've handed off,
(b) you genuinely need information the user has not supplied, or (c) a tool
returned an error you can't work around.

When the custom-draft has the WRONG columns for what you're about to do, call
set_template_columns BEFORE set_table_rows so the row shape matches. Column
names must be HTCondor identifiers (letters/digits/underscore; not starting
with a digit).

For "just run this N times" requests where there's no per-job parameter
variation, use set_table_count instead of set_table_rows. The page emits
"queue N" and the user doesn't have to look at an empty manual table. Default
N=1 covers "just submit one job".

When you have finished setting up everything you intend to (template + rows, plus any
inputs / resources the user asked for), end your turn with an EXPLICIT hand-off in
the assistant text — do not rely on UI affordances alone. The submit button may be
below the fold on a long page; the user might not see a flash highlight. Always:

  1. Write a sentence in your reply telling the user the jobs are ready and asking
     them to click the Submit button (which says something like "Submit batch (N
     jobs)") at the bottom of the page. Briefly summarize what you set up so they
     know what they're about to send.
  2. Also call highlight_section({"section":"submit"}) so the button flashes for
     users who can see it. The highlight is a SUPPLEMENT to the text, not a
     replacement.

A reply like "Let me configure it with your two jobs" is NOT acceptable as a final
turn; either keep working OR hand off explicitly in prose plus a highlight.

IMPORTANT RULES for set_template_body:
  - DO NOT write a "queue" line. The page adds it automatically from the table rows.
    If you put "queue 1" or "queue from (...)" in the body, the form will refuse to
    submit and the user will see a red error. Just write everything ABOVE the queue.
  - Templates are reusable scaffolds; rows in the table are the per-job parameters.
    Don't try to encode the per-job differences in the body — they belong in rows.

BEFORE writing a custom body from scratch: call list_submit_templates first. The
catalog already contains common scaffolds (sleep, hello-world, simple Python,
GPU jobs, etc.).

When you find a matching template, you MUST actually activate it — listing alone
does not change the page. The two activation paths:
  - select_template({"id": "<id>"})            — use the template as-is.
  - select_template followed by switch_to_custom_template({"start_from":"current"})
                                                — fork into the custom draft so you
                                                  can layer edits on top.
Do NOT stop after listing without activating; the user will see no change otherwise.

Use the UI tools to direct the user's eye after answering — when you mutate the
draft, the affected section flashes briefly so they can see what you did.

If a useful change is needed that none of your tools cover, describe the EXACT manual
edit the user should make — don't pretend you did it.

INLINE FILES (the wrapper script + additional sandbox files):
  - The "wrapper script" is the executable. Manage it via set_inline_script /
    clear_inline_script. Standard pattern: a small shell script that sets the
    environment and invokes the payload. Filename ends in .sh; first line is
    a shebang.
  - Additional inline files are payload scripts the wrapper invokes. Manage
    these via add_inline_file / set_inline_file_content / replace_in_inline_file
    / read_inline_file / delete_inline_file. Common pattern: wrapper.sh +
    analyze.py, where wrapper.sh runs "python analyze.py".
  - When iterating: read_inline_file BEFORE replace_in_inline_file so you know
    the exact bytes you're editing (and so you can quote what you changed back
    to the user). replace_in_inline_file requires the find string to match
    EXACTLY ONCE — pass surrounding context to disambiguate.
  - Don't manage the wrapper script via add_inline_file / set_inline_file_content —
    those tools refuse to touch the wrapper. Use set_inline_script instead.

SAVING A TEMPLATE:
  - When the user says "save this as a template" or has scaffolded something
    likely to be reused (a parameter sweep, a recurring nightly run), call
    save_template with a slug-friendly id, a clear name, and a one-sentence
    description. The SPA opens a confirmation dialog where the user can edit
    those fields and toggle visibility (private vs. shared with everyone on
    this server). Save does NOT happen until the user clicks the dialog button.
  - The user might iterate. Saving over an existing id of theirs prompts
    "Overwrite?" in the dialog — that's expected, not an error.
  - Other users' shared templates show in list_submit_templates with an "owner"
    field and "mine":false. The user can SELECT those (load as starting point)
    but cannot save over them — the save_template dialog will create a new
    entry in the user's own private/shared space, not edit the original.`

// jobDetailPageInstructions is appended to the chat system prompt when
// the SPA reports `page=job-detail`. The user is investigating a single
// job — usually because it's behaving badly (held, stuck idle, exited
// non-zero, runs slow, etc.) — and the panel layout reflects that.
//
// === KEEP IN SYNC WITH frontend/src/app/jobs/[id]/JobDetailClient.tsx ===
const jobDetailPageInstructions = `The user is on a single job's detail page. The URL contains
the job's <cluster>.<proc> id. Your tools are scoped to THIS job — when a tool needs a
job_id you should pass the same id from the page context (the SPA includes it in the
request body so you don't need to ask the user).

The page already shows the user the high-level facts (status, hold reason, exit code,
last host, requested vs. used resources). DO NOT just re-read those back to them — they
can see the page. Help with deeper investigation:
  - "why is this held?" → read the job log for the most recent HoldReason event, and
    if the job is idle/held, recommend running match analysis.
  - "what's it doing right now?" → if running, run a quick command in the job
    (run_in_job: e.g. "ps -ef", "ls -la", "tail -n 30 mylog.txt") to see the live state.
  - "why is it slow?" → check stdout/stderr for stalls, check ResidentSetSize vs
    RequestMemory, run "top -b -n 1 | head -20" inside the job.
  - "what happened?" → read the userlog event timeline (get_job_log).

Tools available here:
  - get_job_attributes: read specific ClassAd attributes (or all). Use to look up
    HoldReasonCode, RemoteHost, ResidentSetSize, JobStartDate, etc. — anything not
    already on the page header.
  - get_job_log: parsed userlog event list (submit, execute, hold, evict, …).
    Use this to build a timeline.
  - get_match_analysis: condor_q -better-analyze-style breakdown of why an idle/held
    job isn't matching slots. Heavy call; only run when the job is idle (status=1)
    or held (status=5), and only when the user is asking about matching.
  - read_job_output: grep / head / tail on stdout or stderr. Specify mode and
    pattern. Output is capped — don't expect full files.
  - run_in_job: run a single non-interactive shell command inside the job's sandbox
    while it's RUNNING (status=2) or transferring output (status=6). Returns
    combined stdout+stderr capped to 64 KiB. Only works while the job is alive.
    Use sparingly — short commands like "ls", "ps", "tail -n 30 logfile". DO NOT
    spawn long-running processes (they'll be killed by the per-call timeout).
  - edit_job_attribute: change a single ClassAd attribute on this job. The user
    can do this in the "All Attributes" table on the page; use the tool when
    they ask conversationally ("bump my priority to 10", "set BatchName"). The
    'expression' MUST be a valid ClassAd literal — strings need surrounding
    quotes (e.g. "training-run"), ints/floats are bare, booleans are true/false,
    arbitrary expressions like RequestMemory * 2 are passed through verbatim.
    Requires user confirmation. Immutable / protected attributes (ClusterId,
    Owner, JobStatus, HoldReason, …) are refused server-side; surface that
    refusal verbatim so the user knows why.

When investigating a held job, your first step should usually be get_job_attributes
with names=["HoldReason","HoldReasonCode","HoldReasonSubCode"] to read the exact
reason the schedd recorded. Don't guess — the codes are precise.`

// archivePageInstructions is appended to the chat system prompt when
// the SPA reports `page=archive`. This page surfaces the schedd's
// history database (every completed and removed job) as an
// infinite-scrolling table.
//
// === KEEP IN SYNC WITH frontend/src/app/archive/page.tsx ===
const archivePageInstructions = `The user is on the archive page — a flat table of every
job in the schedd's HISTORY (completed and removed jobs). They can scroll to load more;
the SPA paginates via a (ClusterId, ProcId) keyset cursor. The archive can hold
hundreds of thousands of records, so think pagination-first: don't try to slurp
everything at once.

Tools available here:
  - query_jobs_archive: server-side, owner-scoped query against the schedd's history.
    Constraint vocabulary is the same as query_jobs (the live queue) but the typical
    fields are different — JobStatus is always 3 (Removed) or 4 (Completed); look at
    ExitCode / ExitBySignal for "did it succeed?", at CompletionDate / QDate for "when",
    at RemoteWallClockTime for "how long". The result includes a "next_cursor" you can
    feed back as before_cluster / before_proc to fetch the next page when you didn't
    find what you were looking for. Stop when "end_of_history" comes back true.
  - set_filter: client-side substring match on whatever's currently loaded in the
    table. Useful for narrowing the user's view to "training-run" or "exit code 1"
    after they've scrolled in some history.

Workflow tips:
  - When the user asks "did my X job succeed?", query with a constraint that names
    X (JobBatchName, Cmd substring, or a cluster id range). Don't dump 200 unrelated
    rows.
  - "Show me my failed jobs" → constraint "ExitCode != 0 || ExitBySignal".
  - "What ran yesterday?" → constraint "CompletionDate > <epoch_24h_ago>".
  - When a query returns a non-empty next_cursor and you didn't find the user's
    target, paginate again with that cursor — but cap yourself at 5 pages or so
    (1000 records) before declaring it not found, otherwise you'll burn time
    walking ancient history.
  - The page's filter input is for the user's eyes — if you've found the answer,
    set_filter to match what you found so the user sees those rows on screen.`

// chatPageInstructions returns the per-page system-prompt suffix map
// the engine expects. Centralized so both the production engine
// constructor and tests use the same mapping.
func chatPageInstructions() map[string]string {
	return map[string]string{
		"jobs":       jobsPageInstructions,
		"submit":     submitPageInstructions,
		"job-detail": jobDetailPageInstructions,
		"archive":    archivePageInstructions,
	}
}

// buildChatTools is the real implementation, called from
// handlers_chat.go's stub. Each server-side tool here enforces owner
// scoping: the LLM can pass any constraint it likes, and we rewrite
// it to AND in `Owner == "<actor>"` before issuing the schedd RPC.
// The single-job mutations (hold/release/remove) read the job ad
// first and refuse if Owner != actor — defense in depth so a
// schedd ACL gap can't be exploited via the chat path.
func (s *Handler) buildChatTools() []chat.Tool {
	tools := []chat.Tool{
		// Jobs page (server-side, owner-scoped).
		s.toolQueryJobs(),
		s.toolHoldJob(),
		s.toolReleaseJob(),
		s.toolRemoveJob(),
		s.toolRemoveJobs(),
		s.toolEditJobsByConstraint(),
		// Archive page (server-side, owner-scoped, read-only).
		s.toolQueryJobsArchive(),
		// Jobs page (client-side UI nudges).
		toolSetFilter(),
		toolExpandBatch(),
		toolHighlightJob(),
		// Submit page (server-side reference data).
		s.toolListSubmitTemplates(),
		// Submit page (client-side draft mutations + UI nudges).
		toolHighlightSection(),
		toolSelectTemplate(),
		toolSetTemplateBody(),
		toolSetInlineScript(),
		toolClearInlineScript(),
		toolSetResources(),
		toolAddTemplateInputFile(),
		toolSetTemplateColumns(),
		toolSetTableRows(),
		toolSetTableCount(),
		toolSwitchToCustomTemplate(),
		toolSetTemplateDescription(),
		toolAddInlineFile(),
		toolReadInlineFile(),
		toolReplaceInInlineFile(),
		toolSetInlineFileContent(),
		toolDeleteInlineFile(),
		toolSaveTemplate(),
		// Job-detail page (single-job investigation).
		toolGetJobAttributes(),
		toolGetJobLog(),
		toolGetMatchAnalysis(),
		toolReadJobOutput(),
		s.toolRunInJob(),
		s.toolEditJobAttribute(),
		// Universal (read-only pool data; no page tag).
		s.toolQuerySlots(),
	}
	// Doc lookup tools are read-only reference search; only useful when
	// the docs were compiled into the binary (`-tags embed_condor_docs`).
	// Skipping them when not embedded keeps the LLM from advertising
	// tools whose every call returns ErrNotEmbedded.
	if condordocs.IsEmbedded() {
		tools = append(tools, toolDocJobAttributes(), toolDocSearch())
	}
	return tools
}

// ---------------------------------------------------------------------
// Server-side tools
// ---------------------------------------------------------------------

// queryJobsArgs is what the LLM passes as the tool input.
type queryJobsArgs struct {
	// Constraint is a ClassAd expression filter (e.g. `JobStatus == 5`
	// for held jobs, `BatchName == "training-run"`). The chat layer
	// always ANDs in `Owner == "<actor>"` before issuing.
	Constraint string `json:"constraint,omitempty"`
	// Limit caps the result count. Defaults to 50 server-side; we
	// also clamp here so the LLM can't ask for 100k rows that flood
	// the context window.
	Limit int `json:"limit,omitempty"`
}

func (s *Handler) toolQueryJobs() chat.Tool {
	return &chatTool{
		name:  "query_jobs",
		pages: jobsPageTools,
		description: `List the user's jobs, optionally filtered by a ClassAd ` +
			`expression in 'constraint' (HTCondor's classad query language). ` +
			`Common attributes: JobStatus (1=Idle, 2=Running, 3=Removed, 4=Completed, 5=Held), ` +
			`HoldReason, BatchName (JobBatchName), QDate (epoch seconds), ClusterId, ProcId, ` +
			`Owner, Cmd (command), Args. Returns up to 'limit' (default 50, max 100) most recent jobs.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"constraint": {
					"type": "string",
					"description": "Optional ClassAd filter expression. Auto-scoped to the authenticated user."
				},
				"limit": {
					"type": "integer",
					"description": "Max jobs to return (1-100; default 50).",
					"minimum": 1,
					"maximum": 100
				}
			}
		}`),
		exec: func(ctx context.Context, actor string, in json.RawMessage) (string, error) {
			var args queryJobsArgs
			if err := json.Unmarshal(in, &args); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}
			limit := args.Limit
			if limit <= 0 {
				limit = 50
			}
			if limit > 100 {
				limit = 100
			}
			constraint := scopeToOwner(actor, args.Constraint)

			schedd := s.getSchedd()
			ads, _, err := schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
				Limit: limit,
				Projection: []string{
					"ClusterId", "ProcId", "JobStatus", "HoldReason", "HoldReasonCode",
					"Owner", "Cmd", "Args", "QDate", "JobStartDate", "JobBatchName",
					"NumShadowStarts",
				},
			})
			if err != nil {
				return "", fmt.Errorf("schedd query: %w", err)
			}

			summary := make([]map[string]any, 0, len(ads))
			for _, ad := range ads {
				summary = append(summary, summarizeJobForChat(ad))
			}
			out, _ := json.Marshal(map[string]any{
				"jobs":       summary,
				"count":      len(summary),
				"constraint": constraint,
			})
			return string(out), nil
		},
	}
}

// queryJobsArchiveArgs is what the LLM passes to query_jobs_archive.
//
// The archive (HTCondor's history database) can hold hundreds of
// thousands of records. Two pagination knobs let the LLM walk it
// without blowing context windows or schedd budget:
//
//   - `limit`: per-call cap (default 50, max 200). The LLM should
//     start small and grow if a query was empty.
//   - `before_cluster` / `before_proc`: keyset cursor for "give me
//     records strictly older than (cluster, proc)". Tail of one
//     response feeds head of the next. The tool result includes a
//     `next_cursor` field so the LLM doesn't have to derive it.
//
// `scan_limit` is the schedd-side cap on how many records get
// scanned per call. Without it a deeply-buried match can take
// minutes; the default (10000) keeps each call fast and lets the
// LLM iterate via the cursor.
type queryJobsArchiveArgs struct {
	Constraint    string `json:"constraint,omitempty"`
	Limit         int    `json:"limit,omitempty"`
	ScanLimit     int    `json:"scan_limit,omitempty"`
	BeforeCluster int    `json:"before_cluster,omitempty"`
	BeforeProc    int    `json:"before_proc,omitempty"`
}

func (s *Handler) toolQueryJobsArchive() chat.Tool {
	return &chatTool{
		name:  "query_jobs_archive",
		pages: archivePageTools,
		description: `Query the schedd's history (the "archive") for completed and removed jobs ` +
			`matching a ClassAd expression. Same constraint vocabulary as query_jobs (the live ` +
			`queue). Auto-scoped to the authenticated user. Common attributes: ` +
			`JobStatus (3=Removed, 4=Completed), ExitCode, ExitBySignal, QDate, CompletionDate, ` +
			`RemoteWallClockTime, JobBatchName, Cmd, Args, ClusterId, ProcId. ` +
			`USE FOR: "show my failed jobs", "find that python run from yesterday", ` +
			`"how long did the training-run batch take?". The archive is potentially HUGE — ` +
			`pass 'before_cluster' / 'before_proc' from a previous response's "next_cursor" to ` +
			`paginate deeper. Records come in newest-first order.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"constraint": {
					"type": "string",
					"description": "Optional ClassAd filter expression. Auto-scoped to the user. Examples: \"ExitCode != 0\", \"JobBatchName == \\\"training-run\\\"\", \"CompletionDate > 1700000000\"."
				},
				"limit": {
					"type": "integer",
					"description": "Max records to return per call (1-100; default 50). Bump this only if a small query came back empty.",
					"minimum": 1,
					"maximum": 100
				},
				"scan_limit": {
					"type": "integer",
					"description": "Server-side cap on how many history records to scan before giving up (default 10000). Increase if a buried match isn't getting found within the default scan window.",
					"minimum": 1
				},
				"before_cluster": {
					"type": "integer",
					"description": "Pagination cursor: ClusterId of the last record you saw. Combined with before_proc, asks for records strictly older than that point. Use the next_cursor from a previous response."
				},
				"before_proc": {
					"type": "integer",
					"description": "Pagination cursor companion to before_cluster (the ProcId)."
				}
			}
		}`),
		exec: func(ctx context.Context, actor string, in json.RawMessage) (string, error) {
			var args queryJobsArchiveArgs
			if err := json.Unmarshal(in, &args); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}
			limit := args.Limit
			if limit <= 0 {
				limit = 50
			}
			if limit > 100 {
				limit = 100
			}
			scanLimit := args.ScanLimit
			if scanLimit <= 0 {
				scanLimit = 10000
			}

			// Owner-scope the LLM's constraint, then AND in the
			// pagination cursor. Same predicate the SPA uses on the
			// archive page — kept consistent so the LLM and the user
			// scrolling the table see the same record set.
			constraint := scopeToOwner(actor, args.Constraint)
			if args.BeforeCluster > 0 {
				cursorPredicate := fmt.Sprintf(
					"(ClusterId < %d || (ClusterId == %d && ProcId < %d))",
					args.BeforeCluster, args.BeforeCluster, args.BeforeProc,
				)
				constraint = fmt.Sprintf("(%s) && %s", constraint, cursorPredicate)
			}

			schedd := s.getSchedd()
			ads, err := schedd.QueryHistoryWithOptions(ctx, constraint, &htcondor.HistoryQueryOptions{
				Source:    htcondor.HistorySourceJobHistory,
				Limit:     limit,
				ScanLimit: scanLimit,
				Backwards: true,
				Projection: []string{
					"ClusterId", "ProcId", "Owner", "QDate", "JobStartDate",
					"CompletionDate", "RemoteWallClockTime", "JobStatus",
					"ExitCode", "ExitBySignal", "Cmd", "Args", "JobBatchName",
				},
			})
			if err != nil {
				return "", fmt.Errorf("schedd history query: %w", err)
			}

			summary := make([]map[string]any, 0, len(ads))
			for _, ad := range ads {
				summary = append(summary, summarizeJobForChat(ad))
			}

			// next_cursor: the (ClusterId, ProcId) of the last
			// record returned, IF the page filled to the limit.
			// When the page is short we've hit the end of history
			// (or the scan_limit cap) and there's no next.
			var nextCursor map[string]int
			if len(ads) == limit && len(ads) > 0 {
				last := ads[len(ads)-1]
				cluster, _ := last.EvaluateAttrInt("ClusterId")
				proc, _ := last.EvaluateAttrInt("ProcId")
				nextCursor = map[string]int{
					"before_cluster": int(cluster),
					"before_proc":    int(proc),
				}
			}

			out, _ := json.Marshal(map[string]any{
				"jobs":        summary,
				"count":       len(summary),
				"constraint":  constraint,
				"next_cursor": nextCursor,
				"end_of_history": nextCursor == nil &&
					len(ads) < limit,
			})
			return string(out), nil
		},
	}
}

// jobActionArgs is the shared input shape for hold/release/remove.
type jobActionArgs struct {
	ClusterID int    `json:"cluster_id"`
	ProcID    int    `json:"proc_id"`
	Reason    string `json:"reason,omitempty"`
}

func (a *jobActionArgs) jobID() string {
	return fmt.Sprintf("%d.%d", a.ClusterID, a.ProcID)
}

func (s *Handler) toolHoldJob() chat.Tool {
	return s.singleJobActionTool(
		"hold_job",
		`Place a held lock on one of the user's jobs (ClassAd JobStatus=5). `+
			`Held jobs stop running and stay in the queue until released. Use `+
			`'reason' to record why. Requires user confirmation by default.`,
		"Held via chat assistant",
		func(ctx context.Context, schedd *htcondor.Schedd, constraint, reason string) (*htcondor.JobActionResults, error) {
			return schedd.HoldJobs(ctx, constraint, reason)
		},
	)
}

func (s *Handler) toolReleaseJob() chat.Tool {
	return s.singleJobActionTool(
		"release_job",
		`Release a held job back to the idle queue so HTCondor can run it again. `+
			`Use after the user has fixed whatever caused the hold. Requires user `+
			`confirmation by default.`,
		"Released via chat assistant",
		func(ctx context.Context, schedd *htcondor.Schedd, constraint, reason string) (*htcondor.JobActionResults, error) {
			return schedd.ReleaseJobs(ctx, constraint, reason)
		},
	)
}

func (s *Handler) toolRemoveJob() chat.Tool {
	return s.singleJobActionTool(
		"remove_job",
		`Remove (cancel + delete) one of the user's jobs from the queue. This is `+
			`permanent — the job won't be retried. Requires user confirmation by `+
			`default. Use 'reason' to record why.`,
		"Removed via chat assistant",
		func(ctx context.Context, schedd *htcondor.Schedd, constraint, reason string) (*htcondor.JobActionResults, error) {
			return schedd.RemoveJobs(ctx, constraint, reason)
		},
	)
}

// removeJobsArgs is what the LLM passes to remove_jobs (bulk).
//
// Two ways to identify the target set, in priority order:
//   - `cluster_id` (recommended for "remove this batch") — single
//     int, gets translated to `ClusterId == N`.
//   - `constraint` — arbitrary ClassAd expression. Always wrapped
//     with `Owner == actor` before issuing.
//
// Either one MUST be provided; passing both is a typo and we reject
// it explicitly so the LLM gets a clear error rather than a quietly
// over-broad query (e.g. "ClusterId == 42 && (any_other)" wouldn't
// usually surprise, but rejecting up-front keeps the contract crisp).
type removeJobsArgs struct {
	ClusterID  int    `json:"cluster_id,omitempty"`
	Constraint string `json:"constraint,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// removeJobsMaxAffected caps a single bulk-remove call. Set high
// enough that "remove all my held jobs" works for typical users (a
// few hundred is normal during a flapping run), low enough that an
// LLM mistake-or-jailbreak with `constraint=""` (which would expand
// to `Owner == actor`, matching every one of the user's jobs) gets
// rejected before it touches the queue. The user can override by
// removing in narrower batches.
const removeJobsMaxAffected = 1000

// toolRemoveJobs is the bulk version of remove_job. Owner-scoped via
// scopeToOwner; pre-counts matches to refuse over-broad calls AND to
// surface the count in the tool result so the assistant can tell the
// user what just happened ("removed 47 jobs from batch 42").
//
// Confirmation gate: enabled. Same auto-approve story as remove_job
// but a SEPARATE auto-approve key (`remove_jobs`) so a user who
// auto-approved single removes still gets a confirm card on a bulk
// call — the blast radius is meaningfully different.
func (s *Handler) toolRemoveJobs() chat.Tool {
	return &chatTool{
		name:    "remove_jobs",
		pages:   jobsPageTools,
		confirm: true,
		description: `Remove (cancel + delete) MULTIPLE of the user's jobs at once — typically ` +
			`an entire batch or every job matching a ClassAd filter. Permanent: removed ` +
			`jobs aren't retried. Requires user confirmation. ` +
			`USE FOR: "remove the whole batch 42" (cluster_id: 42), "delete every held job" ` +
			`(constraint: "JobStatus == 5"), "clean up everything from the failed sweep" ` +
			`(constraint: "JobBatchName == \"sweep-2026-04\""). ` +
			`BEFORE CALLING: call query_jobs first with the same constraint so you can tell ` +
			`the user how many will be affected ("This will remove 47 jobs — proceed?"). ` +
			`Owner-scoping is enforced server-side: you cannot match other users' jobs even ` +
			`if you craft a constraint that tries to. The server caps a single call at ` +
			`1000 affected jobs; for larger removals, narrow the filter and run multiple times.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"cluster_id": {
					"type": "integer",
					"description": "Remove every job in this batch (ClusterId). Use for \"the whole batch N\"."
				},
				"constraint": {
					"type": "string",
					"description": "ClassAd expression filter (e.g. \"JobStatus == 5\" or \"JobBatchName == \\\"sweep\\\"\"). Mutually exclusive with cluster_id."
				},
				"reason": {
					"type": "string",
					"description": "Optional human-readable reason recorded with each removal."
				}
			}
		}`),
		exec: func(ctx context.Context, actor string, in json.RawMessage) (string, error) {
			var args removeJobsArgs
			if err := json.Unmarshal(in, &args); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}

			// Translate the cluster_id shortcut. The two-input shapes
			// are mutually exclusive so the LLM doesn't accidentally
			// build "ClusterId == N AND <something narrower>" thinking
			// it scopes when actually the && is restrictive.
			var llmConstraint string
			switch {
			case args.ClusterID > 0 && args.Constraint != "":
				return "", fmt.Errorf("pass either cluster_id OR constraint, not both")
			case args.ClusterID > 0:
				llmConstraint = fmt.Sprintf("ClusterId == %d", args.ClusterID)
			case strings.TrimSpace(args.Constraint) != "":
				llmConstraint = args.Constraint
			default:
				return "", fmt.Errorf("either cluster_id or constraint is required (refusing to remove every job)")
			}

			constraint := scopeToOwner(actor, llmConstraint)
			schedd := s.getSchedd()

			// Pre-count: query the matching set with a projection
			// just big enough to count (ClusterId/ProcId), capped one
			// past the safety limit so we can detect an over-broad
			// match without dragging the whole result set across.
			preview, _, err := schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
				Limit:      removeJobsMaxAffected + 1,
				Projection: []string{"ClusterId", "ProcId"},
			})
			if err != nil {
				return "", fmt.Errorf("preview query: %w", err)
			}
			if len(preview) == 0 {
				out, _ := json.Marshal(map[string]any{
					"action":     "remove_jobs",
					"matched":    0,
					"affected":   0,
					"constraint": constraint,
					"note":       "no jobs matched; nothing to do",
				})
				return string(out), nil
			}
			if len(preview) > removeJobsMaxAffected {
				return "", fmt.Errorf("constraint matches more than %d jobs; narrow the filter and try again",
					removeJobsMaxAffected)
			}

			reason := strings.TrimSpace(args.Reason)
			if reason == "" {
				reason = "Bulk-removed via chat assistant"
			}

			results, err := schedd.RemoveJobs(ctx, constraint, reason)
			if err != nil {
				return "", fmt.Errorf("schedd remove_jobs: %w", err)
			}
			out, _ := json.Marshal(map[string]any{
				"action":            "remove_jobs",
				"matched":           len(preview),
				"affected":          results.Success,
				"not_found":         results.NotFound,
				"permission_denied": results.PermissionDenied,
				"bad_status":        results.BadStatus,
				"already_done":      results.AlreadyDone,
				"errors":            results.Error,
				"reason":            reason,
				"constraint":        constraint,
			})
			return string(out), nil
		},
	}
}

// singleJobActionTool factors the shared structure for hold/release/
// remove: parse args, verify the target is owned by the actor, build
// a constraint that names that exact job AND the owner (so a schedd
// without strict ACLs still can't accidentally touch someone else's
// job), invoke the schedd action, return a structured result.
func (s *Handler) singleJobActionTool(
	name, description, defaultReason string,
	action func(ctx context.Context, schedd *htcondor.Schedd, constraint, reason string) (*htcondor.JobActionResults, error),
) chat.Tool {
	return &chatTool{
		name:        name,
		pages:       jobsPageTools,
		description: description,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"cluster_id": {"type": "integer", "description": "ClusterId of the target job"},
				"proc_id":    {"type": "integer", "description": "ProcId of the target job"},
				"reason":     {"type": "string",  "description": "Optional human-readable reason"}
			},
			"required": ["cluster_id", "proc_id"]
		}`),
		confirm: true,
		exec: func(ctx context.Context, actor string, in json.RawMessage) (string, error) {
			var args jobActionArgs
			if err := json.Unmarshal(in, &args); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}
			if args.ClusterID <= 0 || args.ProcID < 0 {
				return "", fmt.Errorf("cluster_id must be > 0 and proc_id must be >= 0")
			}

			schedd := s.getSchedd()

			// Step 1: confirm the target job exists AND is owned by
			// the authenticated user. Without this any LLM whose
			// constraint-rewrite was somehow bypassed could nuke
			// another user's job; with it, the worst case is a
			// "no such job" reply.
			ownerConstraint := fmt.Sprintf("ClusterId == %d && ProcId == %d && Owner == %s",
				args.ClusterID, args.ProcID, classadStringLit(actor))
			ads, _, err := schedd.QueryWithOptions(ctx, ownerConstraint, &htcondor.QueryOptions{
				Limit:      1,
				Projection: []string{"ClusterId", "ProcId", "Owner", "JobStatus"},
			})
			if err != nil {
				return "", fmt.Errorf("ownership check: %w", err)
			}
			if len(ads) == 0 {
				return "", fmt.Errorf("job %s either does not exist or is not owned by %s",
					args.jobID(), actor)
			}

			// Step 2: dispatch the action. Constraint includes the
			// owner check redundantly so the schedd's per-RPC ACL
			// is also satisfied by content, not just by token
			// identity.
			reason := strings.TrimSpace(args.Reason)
			if reason == "" {
				reason = defaultReason
			}
			results, err := action(ctx, schedd, ownerConstraint, reason)
			if err != nil {
				return "", fmt.Errorf("schedd %s: %w", name, err)
			}
			out, _ := json.Marshal(map[string]any{
				"action":            name,
				"job_id":            args.jobID(),
				"affected":          results.Success,
				"not_found":         results.NotFound,
				"permission_denied": results.PermissionDenied,
				"bad_status":        results.BadStatus,
				"already_done":      results.AlreadyDone,
				"errors":            results.Error,
				"reason":            reason,
			})
			return string(out), nil
		},
	}
}

// ---------------------------------------------------------------------
// Client-side tool stubs
//
// These don't execute on the server — the engine forwards the
// tool_use to the SPA, which runs the registered handler in the
// browser and posts the result back. The schemas here are what the
// LLM sees; the SPA-side handler is responsible for the actual
// effect (see frontend/src/components/ChatPanel.tsx in Phase 4).
// ---------------------------------------------------------------------

func toolSetFilter() chat.Tool {
	return &chatTool{
		name:  "set_filter",
		pages: jobsPageTools,
		description: `Apply a substring filter to the jobs table the user is looking ` +
			`at — keeping only rows whose batch name, cluster id, command line, owner, ` +
			`or display status contains the query. Use to narrow the user's view to ` +
			`what they asked about, e.g. "show me my held jobs" → set_filter("held"), ` +
			`or "the training-run batch" → set_filter("training-run"). Pass the empty ` +
			`string to clear the filter.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"query": {
					"type": "string",
					"description": "Substring to match against batch rows; empty string clears."
				}
			},
			"required": ["query"]
		}`),
		clientSide: true,
	}
}

func toolExpandBatch() chat.Tool {
	return &chatTool{
		name:  "expand_batch",
		pages: jobsPageTools,
		description: `Open the inline expanded view for a batch (cluster) so the user ` +
			`can see all the job rows it contains. Use after answering a question that ` +
			`points at a specific batch.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"cluster_id": {
					"type": "integer",
					"description": "ClusterId of the batch to expand"
				}
			},
			"required": ["cluster_id"]
		}`),
		clientSide: true,
	}
}

func toolHighlightJob() chat.Tool {
	return &chatTool{
		name:  "highlight_job",
		pages: jobsPageTools,
		description: `Briefly highlight a specific job row in the table (visual flash) ` +
			`to draw the user's attention. Use sparingly, after answering a question ` +
			`about that exact job.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"cluster_id": {"type": "integer"},
				"proc_id":    {"type": "integer"}
			},
			"required": ["cluster_id", "proc_id"]
		}`),
		clientSide: true,
	}
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// scopeToOwner is the centerpiece of the chat layer's owner-scoping
// guarantee. Whatever ClassAd expression the LLM passes, we wrap it
// so the result evaluates to (Owner == "<actor>") AND (whatever the
// LLM asked for). The LLM cannot remove or escape the leading clause
// — the AND-wrapper is unconditional.
//
// Empty-string actor is rejected at the handler layer, not here, so
// this function never produces a `Owner == ""` constraint that
// matches everything.
func scopeToOwner(actor, llmConstraint string) string {
	owner := fmt.Sprintf("Owner == %s", classadStringLit(actor))
	c := strings.TrimSpace(llmConstraint)
	if c == "" {
		return owner
	}
	return fmt.Sprintf("(%s) && (%s)", owner, c)
}

// classadStringLit quotes a value as a ClassAd string literal,
// escaping internal quotes. ClassAd uses C-style backslash escapes
// for the few special chars in identifiers; usernames are tightly
// constrained so this is mostly belt-and-braces against a
// hypothetical odd Owner value.
func classadStringLit(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// summarizeJobForChat picks the small set of fields useful to the
// LLM out of a full job ClassAd and renders them as plain Go types
// the json encoder can serialize. We keep it minimal to avoid
// blowing the LLM's context with attributes it'll never use.
func summarizeJobForChat(ad *classad.ClassAd) map[string]any {
	out := map[string]any{}
	if v, ok := readInt(ad, "ClusterId"); ok {
		out["cluster_id"] = v
	}
	if v, ok := readInt(ad, "ProcId"); ok {
		out["proc_id"] = v
	}
	if v, ok := readInt(ad, "JobStatus"); ok {
		out["job_status"] = v
		out["job_status_name"] = jobStatusName(v)
	}
	if v, ok := readString(ad, "Owner"); ok {
		out["owner"] = v
	}
	if v, ok := readString(ad, "Cmd"); ok {
		out["cmd"] = v
	}
	if v, ok := readString(ad, "Args"); ok && v != "" {
		out["args"] = v
	}
	if v, ok := readString(ad, "JobBatchName"); ok && v != "" {
		out["batch_name"] = v
	}
	if v, ok := readString(ad, "HoldReason"); ok && v != "" {
		out["hold_reason"] = v
	}
	if v, ok := readInt(ad, "HoldReasonCode"); ok && v != 0 {
		out["hold_reason_code"] = v
	}
	if v, ok := readInt(ad, "QDate"); ok {
		out["qdate"] = v
	}
	if v, ok := readInt(ad, "JobStartDate"); ok && v != 0 {
		out["start_date"] = v
	}
	if v, ok := readInt(ad, "NumShadowStarts"); ok && v != 0 {
		out["num_shadow_starts"] = v
	}
	return out
}

// readString / readInt are tiny helpers for pulling typed values out
// of a ClassAd without stack-trace-y error surfaces. The chat tool
// is best-effort: missing fields just don't appear in the summary.
func readString(ad *classad.ClassAd, name string) (string, bool) {
	expr, found := ad.Lookup(name)
	if !found {
		return "", false
	}
	s, err := expr.Eval(nil).StringValue()
	if err != nil {
		return "", false
	}
	return s, true
}

func readInt(ad *classad.ClassAd, name string) (int, bool) {
	expr, found := ad.Lookup(name)
	if !found {
		return 0, false
	}
	v := expr.Eval(nil)
	if i, err := v.IntValue(); err == nil {
		return int(i), true
	}
	if s, err := v.StringValue(); err == nil {
		if n, err := strconv.Atoi(s); err == nil {
			return n, true
		}
	}
	return 0, false
}

// jobStatusName labels the integer JobStatus with the conventional
// name so the LLM doesn't have to memorize the table. Unknown codes
// pass through as a numeric string.
func jobStatusName(code int) string {
	switch code {
	case 1:
		return "idle"
	case 2:
		return "running"
	case 3:
		return "removed"
	case 4:
		return "completed"
	case 5:
		return "held"
	case 6:
		return "transferring_output"
	case 7:
		return "suspended"
	default:
		return fmt.Sprintf("unknown(%d)", code)
	}
}

// ensure chatToolDeps is satisfied by *Handler (compile-time check)
var _ chatToolDeps = (*Handler)(nil)
