# Metrics and usage statistics

What this server counts, where the numbers are kept, and what ends up on
a scrapeable endpoint. Part of the
[HTTP API + MCP server](server.md) documentation.

`GET /metrics` is Prometheus exposition. It requires an API key carrying
the `metrics` scope unless `HTTP_API_METRICS_PUBLIC = true`.

## Usage statistics

The server counts what it is asked to do, in two kinds that work the
same way and are reported side by side: **MCP tool calls** and **REST
API requests**. Both are attributed to a user and a client, both
survive a restart, and both appear on `/metrics` and on the admin
**Usage** page.

Everything below -- the persistence, the label bounds, the admin page,
the `HTTP_API_TOOL_STATS_*` knobs -- applies to both unless it says
otherwise.

### MCP tool calls

`/metrics` reports what the MCP surface is being asked to do, in the
same `htcondor_api` namespace as the HTTP metrics:

| Metric | Type | Labels | Answers |
| --- | --- | --- | --- |
| `htcondor_api_mcp_tool_calls_total` | counter | `tool`, `user`, `client`, `outcome` | what is called, by whom, from which harness |
| `htcondor_api_mcp_tool_duration_seconds` | histogram | `tool`, `client`, `outcome` | how long it takes |
| `htcondor_api_mcp_tool_users` | gauge | `tool` | how many distinct people use each tool |
| `htcondor_api_mcp_tool_last_call_timestamp_seconds` | gauge | `tool` | whether a tool is used at all |

`outcome` is `ok`, `error`, `refused` (disabled by
`HTTP_API_MCP_DISABLED_TOOLS`) or `unknown_tool` (the client named a tool
this server does not have — a stale catalogue, or an agent inventing a
name). A refusal is kept apart from an error on purpose: one is a policy
decision, the other a malfunction.

`client` is what the harness called itself in the MCP `initialize`
handshake, falling back to the HTTP `User-Agent` and then to `unknown`. The
server assigns the session that links an `initialize` to the calls that
follow, so a client that declares itself is attributed to what it said
rather than to its HTTP library. With `HTTP_API_MCP_TRANSPORT=sdk` only
the `User-Agent` is available, because that transport answers
`initialize` itself.

These statistics cover the HTTP MCP surface. The standalone
`condor-mcp` stdio server records nothing: it has no database to persist
to and serves no `/metrics`.
The duration histogram carries no `user` label: how long a tool takes is
a property of the tool and the pool, and a histogram costs fourteen
series per label combination.

### REST API requests

The same treatment for the HTTP API. `/metrics` carries:

| Metric | Type | Labels | Answers |
| --- | --- | --- | --- |
| `htcondor_api_rest_endpoint_calls_total` | counter | `endpoint`, `user`, `client`, `outcome` | which endpoints are called, by whom, from what |
| `htcondor_api_rest_endpoint_users` | gauge | `endpoint` | how many distinct people call each one |
| `htcondor_api_rest_endpoint_last_call_timestamp_seconds` | gauge | `endpoint` | whether an endpoint is used at all |

`endpoint` is the method and the route template together, as
`GET /api/v1/jobs/{id}`. The method is part of it because `GET` and
`DELETE` on one path are different operations carrying different risk.
The template is the same one `htcondor_api_http_requests_total` uses, so
a job id never becomes a label.

`outcome` is finer-grained than the HTTP status class, split by what an
operator would do about it:

| `outcome` | Status | Means |
| --- | --- | --- |
| `ok` | 2xx, 3xx | served, redirects included -- the sign-in flow is mostly redirects |
| `denied` | 401, 403 | refused by authentication or authorization |
| `not_found` | 404 | usually a stale client, or a job that has left the queue |
| `rate_limited` | 429 | policy working under load |
| `client_error` | other 4xx | a request this server understood and judged wrong |
| `error` | 5xx | this server failing |

`client` is resolved rather than taken raw, so it stays bounded and
readable:

| Recorded as | When |
| --- | --- |
| `web UI` | authenticated with this server's session cookie -- the single-page app |
| `oauth:<client_id>` | a bearer from a registered OAuth2 client |
| `api key: <name>` | an `htca-v1-` API key |
| the `User-Agent` product token | anything else, version stripped (`curl/8.4.0` becomes `curl`) |

The version is dropped on purpose: keeping it would mint a series per
client upgrade. The OAuth2 **id** is stored rather than the client's
name so that renaming a client does not split its history in two; the
admin page shows the name beside it.

Only `/api/v1/` is counted. Health probes, static assets and the
sign-in redirects are not the REST API, and the MCP endpoints have
their own counters -- counting them here too would double them on one
page.

There is no REST duration histogram on `/metrics`:
`htcondor_api_http_request_duration_seconds` already publishes this
server's latency by method and route, and a second one would add a
bucket series per `(endpoint, client, outcome)` to say the same thing.
Durations are still counted and still persisted, and the admin page's
mean and p95 come from them.

Set `HTTP_API_REST_STATS=false` to turn REST counting off and keep the
MCP counting. It is the kind whose volume an operator might object to:
the web UI polls.

### Persistence and bounds

**If the stored totals cannot be read, nothing is written.** A flush
replaces a series' whole total rather than adding to it, which is only
correct when the server was seeded from the rows it is about to
overwrite. So a server whose startup read failed keeps counting in
memory but persists nothing, and says so in the log; each flush retries
the read, and on success merges what it counted in the meantime with
what was stored. A single unreadable row is skipped and reported rather
than abandoning the whole read.

**These counters survive a restart.** They are written to the
application database every `HTTP_API_TOOL_STATS_FLUSH_INTERVAL`
(default 5 minutes) and again at shutdown, and read back at startup, so
`/metrics` reports the lifetime of the deployment rather than of the
process. This is deliberately unlike a textbook Prometheus counter,
which resets on restart and is handled by `rate()`; it is here so the
numbers mean something before Prometheus exists.

The durable table keeps the **verbatim** user and client, where
`/metrics` renders a bounded label space (see below), so it answers
questions directly:

```sql
-- Who uses this server, and for what?
SELECT actor, tool, SUM(calls) AS calls,
       ROUND(SUM(duration_sum_seconds), 1) AS seconds
  FROM mcp_tool_stats GROUP BY actor, tool ORDER BY calls DESC LIMIT 20;

-- Which harnesses are in use?
SELECT client, SUM(calls) AS calls FROM mcp_tool_stats
 GROUP BY client ORDER BY calls DESC;

-- What is failing?
SELECT tool, outcome, SUM(calls) AS calls FROM mcp_tool_stats
 WHERE outcome <> 'ok' GROUP BY tool, outcome ORDER BY calls DESC;
```

REST requests are in `rest_endpoint_stats`, with the same columns and
`endpoint` in place of `tool`:

```sql
-- Who is being turned away, and from what?
SELECT actor, endpoint, SUM(calls) AS calls FROM rest_endpoint_stats
 WHERE outcome = 'denied' GROUP BY actor, endpoint ORDER BY calls DESC;

-- Which integrations call this server?
SELECT client, SUM(calls) AS calls FROM rest_endpoint_stats
 GROUP BY client ORDER BY calls DESC;
```

A separate table rather than a kind column on the first: the two have
different outcome vocabularies, and their volumes differ by orders of
magnitude, so sharing one would put every MCP query behind a scan of
the web UI's polling.

A Prometheus label value is a time series, so each of `tool`, `user` and
`client` is capped at 1000 distinct values on `/metrics`
(`HTTP_API_TOOL_STATS_MAX_LABEL_VALUES`). Past the cap the quietest
values render as `other`, ordered by call volume so the busiest keep
their identity.

Separately — and this is the bound that protects memory and disk — the
server holds at most `HTTP_API_TOOL_STATS_MAX_SERIES` (default 10000)
distinct combinations, plus one overflow bucket. The flush writes
exactly what is held, so this caps the table too. Past it, new
combinations fold into `other` rather than being dropped: the totals
stay right and only the detail stops. An unknown tool is recorded under
the name the caller sent, truncated to 64 characters, which is why this
bound exists at all.

## The admin Usage page

The web UI's **Usage** page (`/admin/usage`, admin only) shows the same
counts with real user and client names, on a tab per kind: totals, then
calls per tool or endpoint, per user and per client, each split by
outcome with distinct users or clients, mean duration, an approximate
p95 and the time of the last call. Clicking a row, or choosing from the
selectors, narrows every table. Each tab keeps its own filter.

It reads `GET /api/v1/admin/usage?kind=mcp|rest`, which answers from the
live in-memory counts, so it includes calls not yet written to the
database. Without `kind` it answers about MCP. An unrecognised `kind` is
a 400; a kind this server is not counting returns
`{"enabled": false}` along with the list of kinds. Rows look like:

```json
{"name": "query_jobs", "calls": 412, "users": 7, "clients": 2,
 "outcomes": {"ok": 400, "error": 9, "refused": 0, "unknown_tool": 3},
 "avg_seconds": 0.21, "p95_seconds": 0.5,
 "last_call": "2026-10-08T14:02:11Z"}
```

`outcomes` is keyed by the kind's own vocabulary, and the response's
`outcomes` array gives it in display order -- so the page draws its
columns from the server rather than hard-coding either kind's.

`p95_seconds` is the upper edge of the duration bucket holding the 95th
percentile. When that lies past the last edge (300 s), it is `null` and
`p95_over_seconds` gives the edge instead. `users` and `clients` do not
count calls that carried no identity (`unknown`) or the overflow bucket
(`other`).

The response also carries `totals`, `by_name`, `by_user`, `by_client`,
the `filter` in force, `options` (every name, user and client,
unfiltered), `kinds` (the tabs), and `noun`/`title` (what the first
column is called for this kind).

`name` is always the value the server recorded, because it is what a
filter matches on. Where that value is an identifier -- an
`oauth:<client_id>` -- the row also carries a `label` with the client's
name, and `client_labels` maps the same ids for the selector. The name
is resolved when the page is loaded, not when the call was counted: the
request path should not pay a database read for a label.

## Usernames on /metrics

The `user` label puts real account names on `/metrics`, alongside what
each one ran and when. That endpoint can be served unauthenticated with
`HTTP_API_METRICS_PUBLIC`, and is otherwise reachable with an API key
carrying the `metrics` scope — a credential this server deliberately
treats as low-value, on the reasoning that the worst it permits is a
scrape. Publishing a roster of who uses the access point changes that
trade.

Set `HTTP_API_TOOL_STATS_OMIT_USER=true` to render every user label as
`omitted`. Counts and every other metric are unaffected, and the
application database still records the real name, so the admin page and
the SQL queries above keep working — both are gated on more than a
metrics key. It applies to both kinds.
