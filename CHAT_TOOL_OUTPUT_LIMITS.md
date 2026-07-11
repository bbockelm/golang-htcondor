# Chat-tool output limits — audit + proposal

Context: a single `run_in_job ps -ef` consumed ~200k tokens. That's
clearly cumulative (across the conversation, the system prompt, the
tool catalog, etc.) but it points at a real problem: most chat tools
either have very loose caps or none at all, so even a single big
response disproportionately fills the context window for every
subsequent turn.

The chat engine itself does **NOT** cap tool-result payload sizes
(I grepped — no `MaxToolResult`, no `toolOutputCap`, only
`pageContextMaxLen = 2048` on the per-request page context string).
Every byte a tool returns flows straight into the Anthropic context
and gets billed.

## Inventory

| Tool | Server/client | Current output cap | Worst case (bytes) | Worst case (tokens) | Notes |
|---|---|---|---|---|---|
| `run_in_job` | server (SSH) | 64 KiB total stdout+stderr | 64 KiB | ~16k | The 200k-token complaint is here. |
| `read_job_output` | client (SPA) | head/tail: 500 lines (no byte cap); grep: 200 matches; underlying fetch capped at 1 MiB | ~1 MiB if lines are wide | ~250k | Description claims "64 KiB" cap but it isn't enforced. |
| `get_job_attributes` | client | full ad: 64 KiB; names projection: unbounded but small | 64 KiB | ~16k | Reasonable. |
| `get_job_log` | client | **none** | parsed event list for entire job history | ~50k+ for re-tried jobs | Long-running jobs with many restarts blow this up. |
| `get_match_analysis` | client | **none** | structured analysis with per-predicate `sample_*_hosts[]` arrays | typically 5–30k tokens; can spike on huge pools | Worst case is moderate but uncontrolled. |
| `doc_search` / `doc_job_attribute` | server | `max_results` ≤ 100, `context_lines` ≤ 100 | 100 × 100 × ~80 = 800 KB | ~200k | **Worst worst-case in the inventory.** |
| `query_jobs` | server | `limit` ≤ 200, each row summarized to ~150 B | ~30 KB | ~7.5k | Reasonable. |
| `query_jobs_archive` | server | same as `query_jobs` | ~30 KB | ~7.5k | Reasonable. |
| `query_slots` (summarize=true) | server | aggregated counts/breakdowns | ~2 KB | ~500 | Excellent. |
| `query_slots` (summarize=false) | server | `limit` ≤ 200, per-slot summary | ~50 KB | ~12k | Acceptable. |
| `remove_jobs` | server | small status object | ~1 KB | ~250 | Fine. |
| `edit_job_attribute` / `edit_jobs_by_constraint` | server | small status | ~1 KB | ~250 | Fine. |
| Submit-flow tools (`set_template_body`, `add_inline_file`, etc.) | client | client-side state mutations | sub-KB | <500 | Fine. |
| `read_inline_file` | client | reads operator's user-saved template file | unclear | <8k typical | Worth checking. |

## Proposal

I'll set defaults based on a budget of **~2k tokens per tool call**
(≈ 6 KiB of mixed text after JSON wrapping). The LLM can explicitly
request "more" up to a hard maximum of **~8k tokens** (≈ 24 KiB)
when it knows it needs it. Anything bigger should require iteration
(`tail` + `head`, `grep` with a narrower pattern, etc.) — the LLM
is good at that loop.

### Concrete changes

| Tool | Default cap | Hard max | New behavior |
|---|---|---|---|
| `run_in_job` | **8 KiB** | **24 KiB** | New `max_output_bytes` arg (1024–24576, default 8192). Reduce `runInJobOutputCap` constant from 64 KiB to 8 KiB. Tool description: "Output is capped — if you need more, pipe through `head -c N`, `tail -c N`, `head -n N`, or `grep`. **Re-running with a tighter pipe is much cheaper than a single big return.**" |
| `read_job_output` | head/tail **30 lines**, grep **40 matches**, **8 KiB** total bytes | head/tail **150 lines**, grep **100 matches**, **24 KiB** | Add a byte-cap pass after the line-cap. Reduce `lines.maximum` from 500 → 150 in the schema. Reduce default lines from 30 → 30 (unchanged). Reduce match cap from 200 → 100. Reword description to drop the false "64 KiB" claim and replace with the actual numbers. |
| `get_job_attributes` (full ad) | **24 KiB** | n/a | Lower the full-ad cap from 64 KiB to 24 KiB and improve the error message: "ClassAd exceeds 24 KiB; pass `names` with the specific attributes you need (typical interesting set: JobStatus, HoldReason, RemoteHost, RequestMemory, …)." |
| `get_job_log` | **40 events** newest-first (server-side parameter) | **100** | Add `max_events` arg (default 40, max 100). Currently returns every event since the job was submitted; jobs with 1000+ events are not uncommon. |
| `get_match_analysis` | trim `sample_*_hosts[]` to **5 entries** each, drop `attribute_distributions` from chat path | n/a | Server-side: keep the existing endpoint full-fat for the SPA panel; add an SPA-side projection step in the chat hook that strips/truncates the heaviest fields before passing to the LLM. |
| `doc_search` / `doc_job_attribute` | `max_results` ≤ **15**, `context_lines` ≤ **15** | `max_results` ≤ **30**, `context_lines` ≤ **40** | Tighten schema upper bounds. Also add a total-byte cap of 24 KiB so a worst-case (30 × 40-line × wide-line) still can't blow out. |
| `query_jobs` / `query_jobs_archive` | `limit` ≤ **50** | **100** | Tighten schema upper bound from 200 → 100. The current default of 50 is fine. |
| `query_slots` (summarize=false) | `limit` ≤ **50** | **100** | Same. |
| `read_inline_file` | **24 KiB** | n/a | Verify and cap if missing. |

Also add a **single shared response-truncating helper** at the chat
engine layer that enforces a global ceiling (e.g. 32 KiB per
tool_result, regardless of which tool produced it) and emits a
`[truncated: NN bytes elided]` marker. Defense-in-depth so a new
tool added later without per-tool caps can't regress.

### Telemetry

Worth adding too: log the tool name + result byte length on every
tool call, structured. Then operators can grep the access log for
fat results without having to suspect a specific tool. The chat
engine already has the call site — one `s.logger.Info` line.

## Recommendation order

1. **`run_in_job` 64 → 8 KiB default + 24 KiB max** — this is what
   the user explicitly hit. One-line change.
2. **`doc_search` schema bounds** — worst-case cost biggest, easy
   fix.
3. **`read_job_output` byte cap** — closes the false-advertising
   gap in the current description.
4. **`get_job_log` server-side cap** — uncapped event list is a
   latent footgun for any job that's restarted a lot.
5. **Engine-level global truncation** — defense-in-depth.
6. **Telemetry** — informs future tuning.

Items 1–4 are local, mechanical changes. Item 5 needs a small chat
engine change. Item 6 is a one-line log.
