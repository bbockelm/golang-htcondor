# Multi-AP mode: one API server in front of many access points

Run one `htcondor-api` in front of every access point whose schedd ad matches
a ClassAd constraint — fifty or more of them — with reads served from a single
aggregate HTCondorDB (a "mirror of mirrors"), actions routed to the schedd that
owns the job, and new submissions placed by a site-provided user→schedd
mapping service.

Status: milestones 1 and 2 (spoke prerequisites and the hub) are in review as
bbockelm/htcondordb#242, PelicanPlatform/classad#280 and
PelicanPlatform/classad#281. Everything on the golang-htcondor side is design
only.

## Terms

- **AP set** — the schedds matching `HTTP_API_SCHEDD_CONSTRAINT` in the
  collector. Computed, not listed; it changes as APs come and go.
- **Spoke** — the per-AP `htcondordb` that already runs scheddsync next to its
  schedd. Unchanged in role.
- **Hub** — a new `htcondordb` mode that fans in every spoke of the AP set into
  one catalog. The API server reads from it.
- **Home AP** — the schedd AP assignment names for a user. New
  submissions go there; existing jobs stay wherever they are.

```
  AP 1:  schedd ── job_queue.log/history ──▶ htcondordb (spoke) ──┐
  AP 2:  schedd ── job_queue.log/history ──▶ htcondordb (spoke) ──┤  dbrpc Watch
   …                                                              ├──────────────▶ htcondordb (hub)
  AP N:  schedd ── job_queue.log/history ──▶ htcondordb (spoke) ──┘                     ▲
            ▲                                                                           │ dbrpc reads
            │ CEDAR: actions, spool, ssh, submit                                        │
            └────────────────────────────── htcondor-api (multi-AP) ────────────────────┘
                                                   │
                                                   └─▶ AP assignment (mapfile | site REST | …): user → schedd
```

## What exists today

Verified against `main` of both repositories (golang-htcondor `4e900cc`,
htcondordb `9760e41`).

**htcondordb**

- **scheddsync** writes `jobs` (proc ads, cluster attributes chained in at
  write time), `clusters`, `jobsets`, `clusterprivate`, `users`, `header`,
  `logmeta`, and archives `history` and `epoch_history`
  (`cmd/htcondordb/scheddsync_manager.go:483-601`). Keys are raw
  job_queue.log keys (`123.0`). **No row names its schedd**; `GlobalJobId` is
  present only because the schedd put it in the ad.
- **cedarsync** (`cedarsync/`, `cmd/htcondordb/cedarsync_manager.go`) already
  does CEDAR fan-in: one `Runner` per source, `HTCONDORDB_REPLICATE_SOURCES`,
  a `Src` stamp, durable cursors. It is the right skeleton and the wrong
  sinks — see "The hub" for why its sinks would put wrong data in an
  aggregate.
- **dbrpc Watch** gives snapshot+tail semantics (empty cursor → Reset,
  full snapshot, `Synced`, live tail) and resume from an opaque cursor. The
  cursor's epoch is **random per process**, so every source restart forces a
  full replay.
- **historyimport** is the only federation-aware path: it pulls
  `condor_history` from every schedd matching a constraint, stamps
  `ScheddName` and dedups on `GlobalJobId`. History only, and it pulls from
  schedds rather than from spokes.
- Indexes (categorical/value), aggregates, `GROUP BY`, `TopK`, projection and
  the commit-sequence page cursor all work on any table and need nothing new
  to serve a federated catalog.
- The collector ad (`dbad/ad.go`) carries per-source freshness but **does not
  name the schedd it mirrors**. Authorization is per connection
  (READ/WRITE/DAEMON); there is no row-level scoping.

**golang-htcondor**

- The server holds exactly one `*htcondor.Schedd` (`webapi/httpserver/handler.go:60-75`),
  discovered once and re-located every 60 s. MCP, chat, interactive, Jupyter
  and the DAG tools all reach it through `getSchedd()`.
- Every job reference is a bare `cluster.proc`: REST paths, MCP arguments,
  page tokens, share URLs (`webapi/shareurl/shareurl.go:104-112`), watch rows
  (`tracked_json`), the SSH gateway username, Jupyter rows, the `jobssh` cache
  key.
- `webapi/dbmirror` routes reads to one mirror, with stable `Reason` codes,
  freshness gates and `HTTP_API_DBMIRROR_REQUIRED`. It pairs mirror to schedd
  by host match because the ad does not say.
- Identity: the server mints one IDTOKEN per caller (`sub=user@UID_DOMAIN`,
  `iss=TRUST_DOMAIN`, one signing key) and authenticates to the schedd **as
  the caller**. The schedd is the trust root.
- The rate limiter, credd, DAGMan path, superuser policy, revocation oracles
  and `/readyz` health are all single-valued.

## Decisions

### Hub and spoke, not scatter-gather

The alternative is for the API server to query all fifty spokes in parallel
and merge. Rejected:

- **Latency is the slowest spoke, availability is the weakest.** At fifty
  members something is always restarting.
- **Everything that makes the mirror useful is single-table.** Global
  ordering, `LIMIT`, the commit-sequence page cursor, `GROUP BY`, `TopK` and
  the dashboard aggregates would each need a cross-stream merge layer.
- **Fan-out multiplies load.** The dashboard alone would cost fifty
  aggregate queries per refresh.

The hub costs one more copy of the data and one more hop of lag. Both are
bounded and measured (see "Freshness").

Writing scheddsync output straight to a remote hub, with no spoke, is also
rejected. The spoke's local store is the **durable buffer**: it absorbs a WAN
outage or a hub restart without re-reading schedd files. It is also what lets
the hub resume by cursor instead of re-snapshotting. And it keeps serving any
per-AP API server the site still runs. scheddsync must run on the AP as the
condor user anyway.

The one place fan-out survives is a read scoped to a single AP whose hub copy
is stale: that falls back to the AP's own spoke, then its schedd — today's
single-AP chain, run per AP.

### The AP set is a collector constraint, evaluated by both tiers

```
HTTP_API_SCHEDD_CONSTRAINT          = regexp("^ap[0-9]+\\.example\\.org$", Name)
HTCONDORDB_FEDERATE_SCHEDD_CONSTRAINT = regexp("^ap[0-9]+\\.example\\.org$", Name)
```

Both are evaluated against `ScheddAd`s. The API server needs the schedd ads
anyway (addresses for actions); the hub needs them to find spokes. Each
computes its membership independently from the same expression. That avoids
making the API server's ability to act on a job depend on the hub being up.

Disagreement is reported rather than prevented. An AP in the API's set but not
the hub's appears in every response's source block as `absent`. It is never
silently missing from results.

**Membership is sticky.** A schedd ad disappearing from the collector is a
restart, a network blip or a collector failover far more often than a
decommissioning. "Source absent" is not "source empty" (the same rule that bit
the history cache):

- Neither tier drops an AP on ad expiry. The hub keeps its rows and marks the
  source `absent` with a last-seen time. The API server keeps its last-known
  address and fails actions on that AP with a specific error instead of "no
  such job".
- Retirement is explicit: either `HTCONDORDB_FEDERATE_RETIRE_AFTER` (default
  7 days unseen) or the admin command `.retire <schedd>`. Only retirement
  deletes rows, and only from mutable tables (`jobs`, `syncstatus`,
  `federation_sources`). The archives are append-only, so a retired AP's
  history stays queryable until archive retention ages it out — usually what
  you want for accounting anyway.

### Spokes say which schedd they mirror

New spoke ad attributes: `MirroredScheddName` and `MirroredScheddAddress`,
filled from the schedd ad that scheddsync's files belong to. The value comes
from `SCHEDD_NAME` / the address file, resolved against the collector the
same way the API server does it today. This fixes the host-match heuristic in
`dbmirror.pickMirror` for single-AP mode too.

The hub does not take the claim on faith. A spoke whose `MirroredScheddName`
host differs from its own `MyAddress` host is rejected. That check is the
current heuristic, demoted from "how we pair" to "how we validate". Without it,
a misconfigured or hostile spoke could publish rows under another AP's name.
A static spoke entry (`HTCONDORDB_FEDERATE_SPOKE_<NAME>_ADDRESS` and `_SCHEDD`)
covers sites whose spoke runs on a different host. The admin has asserted the
pairing, so host validation is skipped.

Two spokes claiming one schedd (an HA pair) is resolved the way `pickMirror`
already resolves it: prefer the one reporting `Syncing` and caught up, and
decline rather than guess on a tie.

### A job id is a structured value, not a string

A job is identified by the triple `(schedd, cluster, proc)`. That triple is a
type, and every layer passes the type around; no code outside one codec ever
builds or splits a string:

```go
// package jobid (golang-htcondor root module; importable by htcondordb)
type ID struct {
	Schedd  string // schedd Name as advertised; "" only in single-AP mode
	Cluster int64
	Proc    int64
}

// Codec is the ONLY place an ID becomes text or text becomes an ID.
type Codec interface {
	Format(ID) string
	Parse(string) (ID, error)
}
```

What this buys is the freedom to change the textual form later without a
migration. The rules that make that true:

- **Wire formats carry the fields, not a rendering.** JSON responses carry
  `{"schedd": "...", "cluster": 123, "proc": 0}` as separate members. MCP tool
  arguments take `schedd`, `cluster` and `proc`, or a single `job` string that
  goes through the codec. Agents copy fields; they do not parse.
- **Durable state stores the fields.** Watch rows, Jupyter and session rows,
  and share-URL payloads (`{s, c, p}` inside the HMAC) get columns or members
  per field. Nothing persisted depends on the codec, so changing the codec
  invalidates no stored data.
- **The hub's row key is an opaque internal encoding.** It is built by one
  function in the hub and never parsed by a consumer. Readers select on the
  `ScheddName`, `ClusterId` and `ProcId` attributes that every hub row carries,
  so the hub's key format is free to change too, at the cost of a rebuild.
- **Text appears only where a human or a protocol forces a single token**:
  URL path segments, the SSH gateway username and the web UI route. All three
  go through the codec. The codec is configurable, so a site can trial a
  different form.

The default codec renders `123.0@ap40.uw.osg-htc.org`, chosen because:

- it splits at the first `@` (schedd names may themselves contain `@`);
- it needs no escaping in a URL path segment;
- it survives as an SSH username, because OpenSSH splits `user@host` at the
  *last* `@`.

This default is provisional. It is the first thing to revisit once the friends
have used it.

`GlobalJobId` is not reused as the ID. It needs `QDate`, which callers don't
have, and its `#` separator is the URL fragment delimiter. It remains the
*dedup identity* for archive rows, which is a different job.

Rules:

- **Responses always carry `schedd`** on every job in multi-AP mode, so agents
  and the UI always hold a complete ID.
- **Mutations require a complete ID.** A request naming only `cluster.proc` is
  a 400 that names the candidates. Cluster ids on different APs are
  independent. A hub lookup can resolve `123.0` to the user's completed job on
  ap1 while the 123.0 they just submitted on ap3 has not reached the hub yet. A
  wrong guess on `remove` is not recoverable.
- **Reads accept an incomplete ID** when it resolves to exactly one of the
  caller's jobs across live and history; the response carries the complete ID.
  Two or more matches → 409 with the candidates.
- **Single-AP mode is unchanged.** `ID.Schedd` defaults to the one schedd, and
  an ID naming it explicitly is accepted.

### Freshness is end to end, per AP, and measured through the pipe

A hub row for AP X is stale by two amounts: how far the spoke is behind the
schedd, plus how far the hub is behind the spoke. Measuring them with
timestamps from two hosts would make clock skew into staleness.

So each spoke writes a heartbeat row into a small replicated table,
`syncstatus`, every 5 s:

```
SpokeLagSeconds, JobQueueCaughtUp, HistoryGap, LastSyncTime, Seq
```

`SpokeLagSeconds` is the lag the spoke measured on itself, computed with its own
clock when it writes the row. That rule is already established for the
collector ad. The row travels the same Watch stream as the data, in order.

While a source is caught up, its lag is the time since its last verified read
pass. While it is behind, its lag is the time since it was *last* caught up,
so it grows for as long as the spoke is catching up. "Time since the last pass
that applied records" would read a few seconds throughout a 10 GB catch-up.
A spoke that has not been caught up since it started reports no lag, and the
hub treats that AP as stale. The hub computes, using
only its own clock:

```
staleness(X) ≤ (hub_now − heartbeat_received_at_hub) + SpokeLagSeconds + heartbeat_interval
```

An idle AP keeps heartbeating, so "quiet" and "stuck" are distinguishable.
A stopped heartbeat is staleness that grows; it is never a frozen last value.

The hub publishes per-source state as a mutable table, `federation_sources`,
one row per AP, readable over dbrpc: name, state
(`fresh|stale|absent|untrusted|retiring`), staleness, last seen, rows, last
reset. The hub's collector ad carries only a summary (`SourcesTotal`,
`SourcesFresh`, `SourcesStale`, `SourcesAbsent`, `MaxSourceStaleness`). Fifty
sources' worth of attributes do not belong in a collector ad. The API server
watches `federation_sources` instead of polling the ad, so a transition reaches
it in seconds.

### Reads: one hub query, freshness reported, nothing silently omitted

Every multi-AP read response gains a `sources` block:

```json
"sources": {
  "aps": 52, "fresh": 50,
  "degraded": [
    {"schedd": "ap17.example.org", "state": "stale",  "staleness_seconds": 412},
    {"schedd": "ap31.example.org", "state": "absent", "last_seen": "2026-10-03T22:14:09Z"}
  ]
}
```

- **Unscoped reads** (all my jobs, dashboard, history search) are served
  entirely from the hub. A degraded AP's rows are included as-is and flagged.
  The default does not fall back, because a merged hub+schedd result cannot
  carry a single page cursor. `HTTP_API_MULTI_AP_STALE=exclude` drops degraded
  APs' rows instead, still listed in `degraded`.
- **Reads scoped to one AP** (`?schedd=…`, or `get_job` on a complete ID) use the
  existing single-AP chain for that AP: hub if fresh, else that AP's spoke
  through today's `dbmirror` gates, else its schedd. `dbmirror.Locator` becomes
  a per-AP map built from **one** collector query of `HTCondorDB` ads, keyed
  by `MirroredScheddName`.
- **There is no hub fallback.** The hub is the only practical source of
  unscoped reads. With it down, unscoped reads return 503, and scoped reads and
  all actions keep working. Multi-AP mode therefore implies
  `HTTP_API_DBMIRROR_REQUIRED` for unscoped reads.
- **Owner scoping** keeps today's unconditional self-scope, ANDed into the
  constraint by the existing parse-and-reserialize injection. It keys on
  `User` (`owner@uid_domain`) instead of `Owner`, because `Owner` alone is
  ambiguous if two APs ever differ in `UID_DOMAIN`. The hub has no row-level
  ACL; this clause is the scope.
- **The identity precondition** ("the schedd identified this caller") is
  satisfied by any trusted member. Token validity is a property of the
  signature, and every member trusts the same key (see "Trust"). Use the home
  AP when known, else the first healthy member. `actorForSession` and
  `MarkValidated` are unchanged; they just take a schedd argument.
- **Admins.** Superuser reads of other users' jobs are scoped per AP:
  `ScheddName in {APs where the caller is in QUEUE_SUPER_USERS}`. Policy is
  read from each member, not from "the" schedd. Being superuser on one AP must
  not expose the other forty-nine.

Pagination: hub `jobs` reads keep the existing `db1:` commit-sequence cursor;
it is already per table, and the hub is one table. The history keyset
(`before_cluster`/`before_proc`) is not unique across APs. It becomes
`(EnteredHistoryTime, ScheddName, ClusterId, ProcId)` under a new `hub1:`
prefix. Each mode refuses the other's tokens with a 400, the established rule.

### Actions go to the owning schedd, chosen by the id

The single `Handler.schedd` becomes an **AP registry**:
`name → {*htcondor.Schedd, address, last confirmed, trust state}`. It is fed by
one collector query of the constraint every 60 s. This is the existing address
updater, generalized; it also fixes the stale-address capture in the dbmirror
locator, `handler.go:1049`. `getSchedd()` becomes `scheddFor(jobID)`. Every
call site already has the job id in hand.

Single-job actions (hold, release, remove, edit, stdout/stderr/log, peek,
files, input/output spool, ssh, proxy, exec, tail) parse the job ID and
dial that AP. Nothing else changes: CEDAR runs as the caller, and the target
schedd enforces its own authorization.

**Bulk constraint actions** (`POST /api/v1/jobs/hold`, `remove_jobs`, …) fan
out to members with bounded concurrency and report per-AP results. The hub
narrows the fan-out, but it only ever **skips an AP that is provably empty**:
its source is fresh within the bulk tolerance and shows zero matching rows. An
AP that is stale or absent is always contacted, because "remove all my idle
jobs" silently missing the ones submitted thirty seconds ago is the bug this
rule exists to prevent.

State that must gain an AP in its key:

| State | Today's key | Becomes |
|---|---|---|
| `ratelimit.Manager` schedd limiter | user | (AP, user), plus a per-AP global limit. Fifty APs must not share one budget, and one hot AP must not starve the rest. |
| `jobssh.Cache` | {Owner, Cluster, Proc} | + Schedd |
| DAG graph cache | (cluster, proc, dot) | + Schedd |
| `jobPollHub` | constraint | (AP, constraint) |
| DAGMan `BIN` (`sync.Once`) | — | per AP, lazily |
| `requiredCredCache` | (user, service) | (credd, user, service) |
| Superuser policy, revocation oracles | the schedd | per AP |
| Share URL payload | {c, p, o, e, k, w} | + `s` (schedd), inside the HMAC. URLs without `s` are refused in multi-AP mode; they are short-lived. |
| `jupyter_sessions`, interactive terminals | cluster/proc | + `schedd` column (migration) |
| `pingHealth.Schedd`, `/readyz` | one field | per-AP map. **Readiness never depends on a single AP** — at fifty, one is always down. Ready means the hub is reachable and the AP registry is non-empty. |

### Trust: one signing key, one trust domain, one UID_DOMAIN (v1)

The server mints one IDTOKEN per caller, and every member schedd, every spoke
and the hub must accept it. v1 requires all members to share the pool signing
key, `TRUST_DOMAIN` and `UID_DOMAIN`. A site with one pool and one signing key
already satisfies this.

A mismatch fails silently: cedar's client drops a token whose `iss` differs
from the server's trust domain and offers nothing usable. That is exactly how
the ap40 mirror outage presented. So the registry **probes each member on
registration**. It pings with a minted service-identity token, then checks
that the identity the schedd reports back is exactly `sub@UID_DOMAIN`. The
schedd's collector ad does not carry `UidDomain`; only its state dump does.
The ping's mapped identity tests trust and domain in one round trip. A member that fails is marked `untrusted`.
Actions on it fail fast with "this access point does not trust this API
server's tokens" rather than a post-auth EOF, and its rows are flagged in
`sources`.

The GECOS identity map makes the same assumption: one account namespace across
the AP set. Per-AP signing keys (`HTTP_API_SCHEDD_<NAME>_SIGNING_KEY`) are a
clean later extension, because minting is already per call. They are not in
v1.

The hub authenticates to spokes at READ level. **READ excludes private
attributes, so the hub holds no claim ids or other secrets.** It needs nothing
higher. The API server reads the hub at READ level with the existing
`HTTP_API_DBMIRROR_TOKEN_SUBJECT` token. Hub tables must be read-only to
clients; that gap is already open for synced tables and has to close before
the hub ships.

### Submit: AP assignment picks the AP

"Placement" is already taken: `condor_placementd` is HTCondor's token-issuing
daemon, and golang-htcondor integrates it under `/api/v1/placement/*`. This
mechanism is called **AP assignment**: package `webapi/apassign`, knob prefix
`HTTP_API_AP_ASSIGNMENT`. It answers one question — which AP should this
user's *new* work go to — and is pluggable, because sites will answer it very
differently.

```go
type Assigner interface {
	// Assign returns an Assignment, ErrNoAnswer (not mine; ask the next
	// backend), ErrDenied (stop: this user may not submit), or another error
	// (the backend is broken; do not fall through).
	Assign(ctx context.Context, req Request) (Assignment, error)
}

type Request struct {
	User    string   // HTCondor identity after mapping: alice@example.org
	Subject string   // OIDC subject, before mapping
	Groups  []string
	Kind    string   // "job" | "dag" | "interactive" | "jupyter" | "container_build"
}

type Assignment struct {
	Schedd     string        // home AP
	Alternates []string      // other APs this user may target explicitly
	TTL        time.Duration
	Source     string        // which backend answered, for logs and /api/v1/aps
}
```

**Backends form an ordered chain**, configured the same way as
`HTTP_API_IDENTITY_MAP`. The first backend to answer wins. An unknown backend
name refuses to start the server.

```
HTTP_API_AP_ASSIGNMENT          = mapfile, rest
HTTP_API_AP_ASSIGNMENT_DEFAULT  = ap01.example.org      # last resort; optional
```

v1 backends:

- **`static`** — always the one schedd. Single-AP mode is this backend, so
  single-AP and multi-AP share one submit path.
- **`mapfile`** — HTCondor mapfile syntax, first match in file order, reloaded
  when the file changes:

  ```
  # match    principal                          schedd
  USER       alice@example.org                  ap12.example.org
  GROUP      cms                                ap20.example.org
  USER       /^(.*)@physics\.example\.org$/      ap30.example.org
  SUBJECT    /^https:\/\/idp\.example\.org\//     ap31.example.org
  ```

  The match field is `USER`, `GROUP`, `SUBJECT` or `*`. Regex principals use
  the usual `/…/` form. A line may list alternates after the schedd
  (`ap12.example.org ap13.example.org`). This is enough for a site that keeps
  the assignment in configuration management and never runs a service.
- **`rest`** — a site service. The contract we would ask the friends to
  implement:

  ```
  GET {HTTP_API_AP_ASSIGNMENT_REST_URL}/v1/assignment?user=alice%40example.org&subject=…&kind=job
  Authorization: Bearer <HTTP_API_AP_ASSIGNMENT_REST_TOKEN_FILE>

  200 {"schedd":"ap12.example.org","alternates":["ap13.example.org"],"ttl_seconds":300}
  404 → ErrNoAnswer (next backend)
  403 → ErrDenied
  ```

- **`HTTP_API_AP_ASSIGNMENT_DEFAULT`** — not a backend in the chain, but the
  answer when every backend says `ErrNoAnswer`. With no default set, that case
  is 403 "no access point is assigned to you".

Behavior common to all backends, implemented once in the chain:

- **Errors do not fall through.** A broken backend must not silently send
  everyone to the last-resort AP. On error, the chain uses this user's last
  known good answer for up to `HTTP_API_AP_ASSIGNMENT_STALE_SECONDS` (default
  1 h), then returns 503. A slow backend has a hard timeout (2 s), not the HTTP
  client default.
- **Answers are validated.** An assignment outside the AP set, or to a member
  marked `untrusted`, is a 503 plus an error log. A mapfile typo or a remote
  service cannot send work outside the set.
- **Answers are cached per user** for the answer's TTL (backend default:
  mapfile 60 s, rest 300 s), capped.
- **Explicit targeting.** A caller may pass `schedd=`. It is honored only if it
  names the assignment's `Schedd` or one of its `Alternates`; otherwise 403.
- **Assignment happens once per submission.** The response carries complete
  IDs. The second step of a two-step submit (`/input`, `upload_job_input`,
  `create_input_upload_url`) addresses the job by that ID and **never
  re-assigns**. Otherwise a mapping change between the steps would spool input
  to the wrong AP and leave the job held at code 16 forever.
- **Every submitter goes through it:** REST submit, MCP `submit_job`,
  `submit_dag`, `build_container`, interactive sessions, Jupyter, apps.
  DAGMan's node jobs land on the DAGMan job's schedd, which is what we want.
  An existing interactive session or Jupyter instance stays on its AP even if
  the user's assignment changes. The session key gains the AP and lookup goes
  by the stored row, not by re-assigning.
- **Credentials follow assignment.** The credd is per AP. Credential endpoints
  act on the home AP's credd by default, with `?schedd=` for others. The
  submit-time "ensure required credentials" check runs against the target AP's
  credd. Moving a user's home AP does not migrate stored credentials; the
  first submit to the new AP prompts for them, which is the same flow a new
  user sees.

### Watches

The durable watch machinery (`webapi/jobwatch`) works unchanged against one
hub `jobs` Watch stream that covers every AP, which is cheaper than today's
per-AP polling would be. Two changes:

- `tracked_json` entries gain `schedd`.
- **Absence from the queue is evidence of completion only for a fresh AP.**
  The evaluator treats "no longer in a complete queue" as "finished". With
  many APs, "complete" is per AP. If ap17's source is stale or absent, its jobs
  are not in the rows the hub returned, and counting that as completion would
  fire a false "your job finished" notification for every job on ap17. The
  evaluator gates absence on that AP's `federation_sources` state and
  otherwise waits.

The per-job SSE (`/api/v1/jobs/{id}/watch`) keeps polling, but polls the
owning AP.

## The hub

A new mode of `htcondordb`, package `federate/`. It reuses cedarsync's
`Runner` loop (dial, Watch, backoff, cursor) and replaces its sinks.

### Tables

| Hub table | From spoke | Key / identity | Indexes |
|---|---|---|---|
| `jobs` (mutable) | `jobs` | opaque encoding of (`ScheddName`, `ClusterId`, `ProcId`) | categorical `ScheddName`, `User`, `JobStatus` |
| `history` (archive) | `history` | dedup on `GlobalJobId` | categorical `ScheddName`, `Owner`, `GlobalJobId`; value `ClusterId`; zones `CompletionDate`, `EnteredHistoryTime` |
| `epoch_history` (archive) | `epoch_history` | dedup on `GlobalJobId`+`RunInstanceID`+`EpochAdType` | as history, zones on `EpochWriteDate` |
| `syncstatus` (mutable) | `syncstatus` | `schedd` | — |
| `federation_sources` (mutable) | computed by the hub | `schedd` | — |

`clusters`, `jobsets`, `clusterprivate`, `users`, `header` and `logmeta` are
not replicated. They are spoke-internal, and `jobs` rows already carry their
cluster's attributes because chaining happens at write time on the spoke.
That makes the hub **depend on the spoke's chaining being correct**. The
chaining-gap fix (`rebuildChildren`) must be on every spoke before rollout;
otherwise the hub inherits the ap40 partial rows fifty times over.

Every replicated row gets `ScheddName` **set by the hub from the source's
validated identity, overwriting** whatever the row carried. Stock
`replicate.Sink` stamps `Src` only if absent, which is right for transparent
tiers and wrong here. A row cannot claim to belong to another AP.

### Why the stock sinks cannot be used

From the survey of `db/replicate` (classad v0.30.11). Each of these produces
wrong data, not slow data:

1. **`NewTableSink` writes the raw source key.** Two APs' `123.0` collide, and
   a delete from ap1 destroys ap2's row.
2. **`NewTableSink` ignores Reset**, so rows deleted at the source during a
   disconnect stay forever as phantom jobs.
3. **`NewArchiveSink` does not dedup.** Every Reset re-appends the source's
   entire retained history.
4. **Cursors are committed only on `Synced`.** A hub restart replays
   everything since its last connect.
5. **The source epoch is random per process**, so every spoke restart is a
   Reset. Combined with (2) and (3), a routine spoke restart either leaves
   phantoms or duplicates its whole history in the hub.

### The federating sinks

**Table sink: reconcile, don't replace.**

- Live events upsert or delete the namespaced key.
- On Reset, the sink records the set of keys the replay touches and
  **writes only real deltas**: an incoming ad identical to the stored row is
  skipped. This is the approach scheddsync's own `reconcileReload` already
  takes against job_queue.log compaction, and for the same reason.
- At `Synced`, the sink deletes rows where `ScheddName == X` whose keys the
  replay did not touch (`QueryKeys` by constraint, batched `DeleteWhere`).
- The AP's jobs never vanish mid-replay, and a spoke restart against an
  unchanged queue writes almost nothing. The key set costs memory
  proportional to one AP's queue: about 1M keys for an ap40-sized queue,
  bounded and transient.
- **Clearing first was considered and rejected**, for the same reason it was
  rejected inside scheddsync: every replay would show that AP as empty for its
  duration, and fire the completion watches described above.

**Archive sink: append, with identity dedup during catch-up.**

- In the live tail, records are new by construction and are appended with no
  check.
- From session start until `Synced`, each record is checked against what the
  hub already holds for that AP. That window covers both a Reset replay and
  the at-least-once overlap after a cursor resume.
- The first 256 catch-up records are probed by query. Past that the catch-up is
  treated as a full replay: the AP's identities are loaded once into a set of
  128-bit digests and checked in memory. A per-record probe scans the
  archive's active segment, and that ran a 100k-record replay past ten minutes.
  The set costs about 40 bytes per record, held only while catching up.
  (Value indexes are numeric, so `GlobalJobId` gets a categorical index.)

**Cursors.** Live cursors are committed on a 1 s flush, as
`ha/leaderfollower` already does, not only at `Synced`. Each flush makes the
hub's writes durable *before* it saves the cursor. Otherwise an OS crash could
lose rows that a saved cursor already covers, leaving a permanent gap.

### Persistent archive epochs (classad change)

Dedup makes a spoke-restart replay *correct*, but not cheap. It still streams
and probes the spoke's entire retained history, which can be millions of rows,
every time any of fifty spokes restarts. Archive segments and their append
order are already durable, so the archive's watch epoch and per-shard sequence
can be too. `collections/docs/WATCH.md` claims a persisted `watch.epoch`
already exists; it does not in v0.30.11.

**Ship this in classad before the hub goes to production.** Verify the
append-sequence durability claim first, under a crash mid-seal.

Mutable tables keep the random epoch for now. A durable delete journal is a
bigger change, and a reconcile replay of one AP's queue is affordable.

### Discovery and lifecycle

- Every 60 s the hub queries the collector for the constraint's `ScheddAd`s
  and for `HTCondorDB` ads. It pairs them by validated `MirroredScheddName`
  and starts a runner per table per pair.
- An AP leaving the set becomes `absent`, not deleted; see "Membership is
  sticky".
- Reconfig (`SIGHUP`) re-reads the constraint. An AP that no longer *matches*
  — the admin changed the expression — moves to `retiring` and is deleted
  after `HTCONDORDB_FEDERATE_RETIRE_AFTER`. Changing an expression should not
  be an instant, irreversible bulk delete.
- A spoke's delete journal holds 4096 deletes per shard. A hub disconnected
  longer than that gets a Reset, which the reconcile sink handles.

### Scale and availability

Sizing needs the friends' numbers (see Open questions). The shape:

- **Rows.** Live rows are the sum of the queues: fifty APs at 20k live jobs
  is 1M rows, well within one mutable table's 16 shards. History grows without
  bound, so the hub archive needs `MaxBytes` retention from day one.
  Categorical indexes keep per-user and per-AP reads off full scans.
- **Ingest.** The hub's write rate is the sum of the spokes' tail rates. Tail
  ingest is cheap; bulk ingest is not, which is another argument for
  persistent epochs.
- **Availability.** Run **two independent hubs**, each fed from every spoke,
  rather than raft. The sinks are deterministic functions of spoke data, so two
  hubs converge with no coordination. A spoke serves two Watch streams per
  table without strain. The API server picks the fresher hub with the
  existing freshness-ranked selection. Raft's client-write gap (cedarsync
  writes would bypass it) makes it the wrong tool here anyway.

## API surface changes, summarized

- `HTTP_API_SCHEDD_CONSTRAINT` set ⇒ multi-AP mode. `-schedd`/`SCHEDD_NAME`
  are then an error, not a silent override.
- Jobs are identified by `jobid.ID`: separate `schedd`/`cluster`/`proc`
  fields in JSON, MCP arguments, share URLs and watch rows; the codec's text
  form only in paths and the SSH username.
- `schedd` field on every job row; `?schedd=` filter on list, history,
  credential and submit endpoints.
- `sources` block on every multi-AP read.
- `GET /api/v1/aps`: the registry, with per-AP trust state, hub freshness and
  whether the caller may submit there. The web UI reads this.
- Web UI: an AP column and filter on job lists; "will submit to *ap12*"
  on the submit page; job routes keep `/jobs/[id]` with the codec's text form as
  the segment, so no new dynamic route is needed.
- MCP: instructions describe the AP set instead of "this is the access point
  X". `whoami` reports the home AP. Tools gain an optional `schedd` argument
  where a target is chosen (submit, credentials).
- The `HTCondorAPI` collector ad advertises `ScheddConstraint` and
  `ScheddCount` instead of one `ScheddName`.

## New configuration

| Knob | Where | Default | Meaning |
|---|---|---|---|
| `HTTP_API_SCHEDD_CONSTRAINT` | API | unset (single-AP) | AP set, over `ScheddAd`s |
| `HTTP_API_HUB_NAME` / `_ADDRESS` | API | discover | Pin or override the hub. Discovery picks `HTCondorDB` ads with `FederationConstraint` set. |
| `HTTP_API_MULTI_AP_STALE` | API | `include` | `include` or `exclude` degraded APs' rows in unscoped reads |
| `HTTP_API_JOB_ID_CODEC` | API | `at` | Text form of a job ID in paths and SSH usernames |
| `HTTP_API_AP_ASSIGNMENT` | API | `static` | Ordered backend chain: `static`, `mapfile`, `rest` |
| `HTTP_API_AP_ASSIGNMENT_DEFAULT` | API | unset | Last-resort schedd when no backend answers |
| `HTTP_API_AP_ASSIGNMENT_MAPFILE` | API | — | Mapfile for the `mapfile` backend |
| `HTTP_API_AP_ASSIGNMENT_REST_URL` / `_TOKEN_FILE` | API | — | The site's assignment service |
| `HTTP_API_AP_ASSIGNMENT_STALE_SECONDS` | API | 3600 | Last-known-good window when a backend errors |
| `HTTP_API_BULK_FRESH_SECONDS` | API | 60 | Hub freshness needed to skip an AP in a bulk action |
| `HTCONDORDB_FEDERATE_SCHEDD_CONSTRAINT` | hub | unset | Enables hub mode |
| `HTCONDORDB_FEDERATE_TABLES` | hub | `jobs history syncstatus` | Which spoke tables to fan in |
| `HTCONDORDB_FEDERATE_RETIRE_AFTER` | hub | 7d | Unseen or unmatched AP → its mutable rows deleted (archives age out) |
| `HTCONDORDB_FEDERATE_SPOKES` + `_SPOKE_<NAME>_ADDRESS` / `_SCHEDD` | hub | — | Static spokes (no collector, no host validation) |
| `HTCONDORDB_FEDERATE_FRESH_SECONDS` | hub | 60 | Staleness at or under this is `fresh` |
| `HTCONDORDB_MIRRORED_SCHEDD_NAME` | spoke | derived | Override the schedd name the spoke advertises |
| `HTCONDORDB_SYNCSTATUS_INTERVAL` | spoke | 5s | Heartbeat cadence |

## What will bite

- **Absence ≠ completion, per AP.** Covered under Watches. It also applies to
  the dashboard's "finished recently" counts and to any code that diffs two
  snapshots.
- **Collector expiry ≠ retirement.** A collector restart makes every AP
  vanish at once. If anything keys deletion off ad absence, that is a 50-AP
  data loss.
- **Bare ids reach the wrong job.** Only for mutations is that unrecoverable,
  hence the hard rule. Test it with the same `123.0` on two APs, one of them
  lagging.
- **Trust mismatches are silent.** The member probe exists because the last
  one presented as an unrelated EOF.
- **Re-placing between submit steps** strands jobs at hold code 16.
- **One shared rate limit across fifty APs** produces 429s that look like a
  hot user and are actually a hot AP.
- **Spoke chaining gaps multiply.** The hub has no cluster ads to repair them
  from.
- **A slow assignment backend is a slow submit.** Hence the hard 2 s
  timeout before the last-known-good path.
- **The tests that would pass on broken code** assert only "my jobs appear".
  Assert both directions: the other AP's same-numbered job is absent, and a
  restarted spoke leaves neither phantoms nor duplicates. Count rows, don't
  just find one.

## Milestones

Each milestone ships on its own and is useful on its own.

1. **Spoke prerequisites** (htcondordb, classad).
   - `MirroredScheddName`/`Address` in the ad.
   - `syncstatus` heartbeat table.
   - Synced tables read-only to clients.
   - Persistent archive watch epoch (classad).
   - The chaining-gap fix confirmed deployed.
2. **Hub** (htcondordb `federate/`).
   - Discovery, federating sinks, live cursor commits, `federation_sources`,
     sticky membership and retirement, indexes.
   - Integration test: three real spokes, each with scheddsync over a real
     mini-condor, and the same job id on two of them.
   - Must survive: spoke restart, spoke log compaction, hub restart,
     collector restart, spoke absent for an hour.
3. **Read-only multi-AP API.**
   - AP registry, `jobid.ID` in output, hub routing, `sources` block,
     per-AP `dbmirror` fallback for scoped reads, web UI AP column.
   - With no actions, it is already a pool-wide dashboard and MCP query
     surface. This is the shortest path to something the friends can use.
4. **Actions.**
   - `scheddFor(id)` everywhere, keyed caches and rate limits, share URLs
     with `s`, SSH gateway username via the codec, bulk fan-out, member trust probe,
     per-AP superuser scope.
5. **Submit.**
   - `apassign` chain (`static`, `mapfile`, `rest`) through every submit path, per-AP credd
     and DAGMan discovery, session rows with schedd.
6. **Rest of the history surface and HA.**
   - `epoch_history` and `job_metrics` federated. Transfer history once a
     spoke table exists for it.
   - Watches on the hub stream; a second hub.

## Open questions

For the friends:

1. Do all the APs share one pool signing key, `TRUST_DOMAIN` and
   `UID_DOMAIN`? If not, v1's trust model does not fit, and per-AP keys move
   into scope.
2. One collector, or several? The AP set is one constraint over one collector
   in this design. Several collectors means a list of (collector, constraint)
   pairs, which is mechanical but is new configuration.
3. Can their service implement the `rest` contract above, or would a mapfile
   do? Does assignment
   ever depend on the submission itself (GPUs → a different AP)? If so,
   `apassign.Request` needs request attributes and the answer cannot be cached
   per user.
4. Rough sizes: live jobs per AP, completions per day, and history retention
   wanted. These size the hub and decide whether one hub is enough.
5. Do users' accounts exist on every AP? Is a user allowed to *read* jobs
   on APs other than their home AP? This design assumes yes for their own jobs.

For us:

6. Should a user see jobs on APs where they have no account but which the hub
   shows (via `User` match)? Today the schedd would have refused the identity
   check there.
7. Short display aliases for APs. Fifty FQDNs make for a wide table. An
   optional schedd ad attribute, surfaced as a display name only and never as
   an id, would cover it.
