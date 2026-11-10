# Multi-AP mode

## Status

Implemented. One `htcondor-api` fronts every access point whose schedd ad
matches `HTTP_API_SCHEDD_CONSTRAINT`: reads come from a federation hub that
fans in the per-AP mirrors, actions go to the schedd that owns the job, and
new work goes to the AP a user's assignment names.

- Spoke prerequisites and the hub: htcondordb `federate/`, classad's durable
  archive watch epoch and per-table write gate.
- API server: `webapi/multiap` (hub reads, routing, bulk, hub HA),
  `webapi/apregistry` (the AP set), `webapi/apassign` (submit routing),
  `jobid` (the job id type and its codecs).
- Two hubs with sticky failover, federated `epoch_history` and `job_metrics`.

How to run and what each endpoint answers is [docs/server-multi-ap.md](../docs/server-multi-ap.md).
This note is the reasoning behind it: the alternatives that were rejected,
the rules that exist to prevent a specific wrong answer, and what is still
open.

Not done: a run at the scale that motivated the work. Everything has been
exercised against a handful of APs in tests, not against the fifty-plus a
site actually has, so the sizing below is projection. Per-AP signing keys
are still out of scope.

## The problem

A site runs tens of access points. One API server per AP gives every user a
different URL, a different MCP endpoint and no pool-wide view; a user who
submits on ap12 and ap30 has no one place that answers "what are my jobs
doing". The API server, though, is built around exactly one schedd: one
`*htcondor.Schedd`, one mirror, one credd, one rate limit, and a job
identified everywhere by a bare `cluster.proc`.

Multi-AP mode makes the AP a dimension of every answer rather than a
property of the deployment.

## Hub and spoke, not scatter-gather

The alternative is to query all fifty spokes in parallel and merge.
Rejected:

- **Latency is the slowest spoke, availability is the weakest.** At fifty
  members something is always restarting.
- **Everything that makes the mirror useful is single-table.** Global
  ordering, `LIMIT`, the commit-sequence page cursor, `GROUP BY`, `TopK` and
  the dashboard aggregates would each need a cross-stream merge layer.
- **Fan-out multiplies load.** The dashboard alone costs fifty aggregate
  queries per refresh.

The hub costs one more copy of the data and one more hop of lag. Both are
bounded and measured.

Writing scheddsync output straight to a remote hub, with no spoke, is also
rejected. The spoke's local store is the **durable buffer**: it absorbs a WAN
outage or a hub restart without re-reading schedd files, it lets the hub
resume by cursor instead of re-snapshotting, and it keeps serving any per-AP
API server the site still runs. scheddsync has to run on the AP as the
condor user anyway.

The one place fan-out survives is a read scoped to a single AP whose hub copy
is stale: that falls back to the AP's own spoke, then its schedd — the
single-AP chain, run for one AP.

## The AP set is a collector constraint, evaluated by both tiers

The API server and the hub each evaluate the same expression against
`ScheddAd`s, independently. The API server needs the schedd ads anyway, for
addresses to act on; the hub needs them to find spokes. Computing membership
separately keeps the API server's ability to act on a job from depending on
the hub being up.

Disagreement is reported rather than prevented. An AP in the API's set but
not the hub's shows up in every response's `sources` block as `absent`. It is
never silently missing from results.

**Membership is sticky.** A schedd ad disappearing from the collector is a
restart, a network blip or a collector failover far more often than a
decommissioning, and "source absent" is not "source empty" — the same rule
that bit the history cache. Neither tier drops an AP on ad expiry: the hub
keeps its rows and marks the source `absent` with a last-seen time, and the
API server keeps its last-known address and fails actions on that AP with a
specific error instead of "no such job". Retirement is explicit
(`HTCONDORDB_FEDERATE_RETIRE_AFTER`, or `.retire <schedd>`), and only
retirement deletes rows, and only from the mutable tables. The archives are
append-only, so a retired AP's history stays queryable — usually what you
want for accounting.

A collector restart makes every AP vanish at once. Anything that keys
deletion off ad absence is a 50-AP data loss.

## Spokes say which schedd they mirror

A spoke advertises `MirroredScheddName` and `MirroredScheddAddress`. Before
this, `dbmirror` paired mirror to schedd by host match, because the ad did
not say; that heuristic is now demoted from "how we pair" to "how we
validate" — a spoke whose mirrored host differs from its own `MyAddress` host
is rejected, which catches a spoke copied to another host still claiming its
old AP. A static spoke entry skips the check, because the admin has asserted
the pairing.

Trust in the claim is HTCondor's usual trust in collector ads: a daemon the
collector lets advertise is trusted for what it advertises.

Two spokes claiming one schedd (an HA pair) resolve the way `pickMirror`
already resolves it: prefer the one reporting `Syncing` and caught up,
decline rather than guess on a tie.

## A job id is a structured value, not a string

A job is `(schedd, cluster, proc)`. That triple is a type (`jobid.ID`), every
layer passes the type around, and no code outside one `Codec` builds or
splits a string. What this buys is the freedom to change the textual form
later without a migration. The rules that make that true:

- **Wire formats carry the fields, not a rendering.** JSON and MCP arguments
  carry `schedd`, `cluster` and `proc` separately. Agents copy fields; they
  do not parse.
- **Durable state stores the fields.** Watch rows, session rows and
  share-URL payloads get a member per field, so changing the codec
  invalidates no stored data.
- **The hub's row key is an opaque internal encoding**, built by one function
  in the hub and never parsed by a consumer. Readers select on `ScheddName`,
  `ClusterId` and `ProcId`, which every hub row carries.
- **Text appears only where a human or a protocol forces a single token**:
  URL path segments, the SSH gateway username, the web UI route.

The default codec renders `123.0@ap40.uw.osg-htc.org`: it splits at the first
`@` (schedd names may themselves contain `@`), needs no escaping in a URL
path segment, and survives as an SSH username, because OpenSSH splits
`user@host` at the *last* `@`. It is provisional, and the first thing to
revisit once a site has used it.

`GlobalJobId` is not the ID. It needs `QDate`, which callers do not have, and
its `#` separator is the URL fragment delimiter. It remains the dedup
identity for archive rows, which is a different job.

**Mutations require a complete ID**; a request naming only `cluster.proc` is
a 400 that names the candidates. Cluster ids on different APs are
independent, so a hub lookup can resolve `123.0` to a completed job on ap1
while the 123.0 just submitted on ap3 has not reached the hub yet. A wrong
guess on `remove` is not recoverable. Reads are allowed to accept an
incomplete ID when it resolves to exactly one of the caller's jobs; two or
more matches is a 409 listing them.

## Freshness is measured end to end, per AP

A hub row for AP X is stale by two amounts: how far the spoke is behind the
schedd, plus how far the hub is behind the spoke. Measuring them with
timestamps from two hosts would turn clock skew into staleness.

So each spoke writes a heartbeat into the replicated `syncstatus` table, and
the lag in it is the lag the spoke measured **on itself, with its own
clock**. The row travels the same Watch stream as the data, in order, and the
hub adds only differences of its own clock.

While a source is caught up, its lag is the time since its last verified read
pass. While it is behind, its lag is the time since it was *last* caught up,
so it grows for as long as the spoke is catching up. "Time since the last
pass that applied records" reads as a few seconds throughout a 10 GB
catch-up, which is exactly when it must not. A spoke that has not been caught
up since it started reports no lag at all, and the hub treats that AP as
stale.

An idle AP keeps heartbeating, so "quiet" and "stuck" are distinguishable. A
stopped heartbeat is staleness that grows, never a frozen last value.

The hub publishes per-source state as the mutable `federation_sources` table,
one row per AP, and carries only a summary in its collector ad: fifty
sources' worth of attributes do not belong in an ad. The API server watches
the table instead of polling the ad, so a transition reaches it in seconds.

## Reads: one hub query, nothing silently omitted

Every multi-AP read carries a `sources` block naming the degraded APs and how
stale each is. Unscoped reads are served entirely from the hub, and a
degraded AP's rows are included as-is and flagged; the default does not fall
back, because a merged hub+schedd result cannot carry a single page cursor.

**There is no hub fallback for unscoped reads.** With the hub down they
return 503, while scoped reads and every action keep working. Reads scoped to
one AP use the single-AP chain for that AP.

Owner scoping keys on `User` (`owner@uid_domain`), not `Owner`, which is
ambiguous if two APs ever differ in `UID_DOMAIN`. The hub has no row-level
ACL; that clause is the scope.

The identity precondition ("the schedd identified this caller") is satisfied
by any trusted member, because token validity is a property of the signature
and every member trusts the same key. Superuser reads, by contrast, are
scoped per AP: policy is read from each member, since being superuser on one
AP must not expose the other forty-nine.

Pagination: the hub's `jobs` reads keep the commit-sequence cursor, which is
already per table and the hub is one table. The history keyset is not unique
across APs, so it gains `EnteredHistoryTime` and `ScheddName` under its own
token prefix, and each mode refuses the other's tokens.

## Actions go to the owning schedd

The single schedd becomes an **AP registry** — `name → {schedd, address, last
confirmed, trust state}` — fed by one collector query of the constraint.
`getSchedd()` becomes `scheddFor(id)`, and every call site already has the job
id in hand. CEDAR still runs as the caller, and the target schedd still
enforces its own authorization.

**Bulk constraint actions** fan out to members and report per-AP results. The
hub narrows the fan-out, but it only ever skips an AP that is **provably
empty**: fresh within the bulk tolerance and showing zero matching rows. A
stale or absent AP is always contacted, because "remove all my idle jobs"
silently missing the ones submitted thirty seconds ago is the bug this rule
exists to prevent.

Per-AP state that would otherwise be a wrong answer or a shared budget:

| State | Single-AP key | Multi-AP key |
|---|---|---|
| Schedd rate limiter | user | (AP, user), plus a per-AP global limit. One hot AP must not starve the rest. |
| `jobssh` cache | {owner, cluster, proc} | + schedd |
| DAG graph cache | (cluster, proc, dot) | + schedd |
| Job poll hub | constraint | (AP, constraint) |
| DAGMan `BIN` discovery | one `sync.Once` | per AP, lazily |
| Required-credential cache | (user, service) | (credd, user, service) |
| Superuser policy, revocation oracles | the schedd | per AP |
| Share URL payload | job + owner | + schedd, inside the HMAC |
| Jupyter and interactive session rows | cluster/proc | + schedd |
| `/readyz` | the schedd | the hub plus a non-empty registry. **Readiness never depends on one AP** — at fifty, one is always down. |

## Trust: one signing key, one trust domain, one UID_DOMAIN

The server mints one IDTOKEN per caller, and every member schedd, every spoke
and the hub must accept it. This requires all members to share the pool
signing key, `TRUST_DOMAIN` and `UID_DOMAIN`. A site with one pool and one
signing key already satisfies it.

A mismatch fails silently: CEDAR's client drops a token whose `iss` differs
from the server's trust domain and offers nothing usable — which is how the
ap40 mirror outage presented. So the registry **probes each member on
registration**: it pings with a minted service-identity token and checks that
the identity the schedd reports back is exactly `sub@UID_DOMAIN`. The schedd's
collector ad does not carry `UidDomain`, only its state dump does, so the
ping's mapped identity is what tests trust and domain in one round trip. A
member that fails is marked `untrusted`, and actions on it fail fast with a
message that says so rather than a post-auth EOF.

The GECOS identity map makes the same one-namespace assumption. Per-AP signing
keys are a clean later extension, because minting is already per call.

The hub authenticates to spokes at READ, which **excludes private attributes,
so the hub holds no claim ids or other secrets**. Hub tables are read-only to
clients (classad's per-table write gate).

## Submit: AP assignment, not placement

"Placement" was already taken: `condor_placementd` is HTCondor's token-issuing
daemon, and the API server integrates it under `/api/v1/placement/*`. This
mechanism is **AP assignment** (`webapi/apassign`,
`HTTP_API_AP_ASSIGNMENT`). It answers one question — which AP should this
user's *new* work go to — and is pluggable, because sites answer it very
differently: `static`, `mapfile` (HTCondor mapfile syntax over USER, GROUP or
SUBJECT) and `rest` (a site service), in an ordered chain, with an optional
last-resort default.

The behaviour that matters is in the chain, not the backends:

- **Errors do not fall through.** A broken backend must not silently send
  everyone to the last-resort AP. On error the chain uses this user's last
  known good answer for a bounded window, then returns 503. "No answer" and
  "broken" are different outcomes.
- **Answers are validated.** An assignment outside the AP set, or to an
  untrusted member, is an error. A mapfile typo cannot send work outside the
  set.
- **A slow backend is a slow submit**, so the call has a hard timeout rather
  than the HTTP client default.
- **Explicit targeting** is honoured only for the assignment's own schedd or
  its alternates.
- **Assignment happens once per submission.** The second step of a two-step
  submit addresses the job by its complete ID and never re-assigns —
  otherwise a mapping change between the steps spools input to the wrong AP
  and leaves the job held at code 16 forever.
- **An existing session stays where it is.** Lookup goes by the stored row,
  not by re-assigning.
- **Credentials follow assignment.** The credd is per AP; moving a user's home
  AP does not migrate stored credentials, and the first submit to the new AP
  prompts for them, which is the flow a new user already sees.

## Watches: absence is completion only for a fresh AP

The watch evaluator treats "no longer in a complete queue" as finished. With
many APs, "complete" is per AP: if ap17's source is stale or absent, its jobs
are not in the rows the hub returned, and counting that as completion fires a
false "your job finished" for every job on ap17.

So absence counts only when the hub vouches for that AP — fresh, staleness
measured, jobs stream connected, jobs table caught up across the read, and
the read newer than the job's last sighting there. Anything else waits for
the history record. The first end-to-end test of this rule was vacuous,
because the hub keeps a stopped spoke's rows until retirement: stopping a
spoke does not make its jobs disappear. The rule needs unit tests that
construct the degraded states directly.

The same asymmetry applies to the dashboard's "finished recently" and to any
code that diffs two snapshots. A delete alone is not a completion: it is also
what retiring or replaying an AP looks like.

## The hub

htcondordb's `federate/` package reuses cedarsync's runner loop (dial, Watch,
backoff, cursor) and replaces its sinks. It replicates `jobs`, `history`,
`syncstatus` and, optionally, `epoch_history` and `job_metrics`, and computes
`federation_sources` itself.

`clusters`, `jobsets`, `clusterprivate`, `users`, `header` and `logmeta` are
not replicated: they are spoke-internal, and `jobs` rows already carry their
cluster's attributes because chaining happens at write time on the spoke.
That makes the hub **depend on the spoke's chaining being correct** — the
chaining-gap fix has to be on every spoke, or the hub inherits the ap40
partial rows fifty times over.

Every replicated row gets `ScheddName` **set by the hub from the source's
validated identity, overwriting** whatever the row carried. A row cannot
claim to belong to another AP.

### Why the stock sinks could not be used

Each of these produces wrong data, not slow data:

1. `NewTableSink` writes the raw source key, so two APs' `123.0` collide and
   a delete from ap1 destroys ap2's row.
2. `NewTableSink` ignores Reset, so rows deleted at the source during a
   disconnect stay forever as phantom jobs.
3. `NewArchiveSink` does not dedup, so every Reset re-appends the source's
   entire retained history.
4. Cursors are committed only on `Synced`, so a hub restart replays
   everything since its last connect.
5. The source epoch is random per process, so every spoke restart is a Reset.
   With (2) and (3), a routine spoke restart either leaves phantoms or
   duplicates a whole history.

### The federating sinks

**Table sink: reconcile, don't replace.** Live events upsert or delete the
namespaced key. On Reset the sink records which keys the replay touches and
writes only real deltas — an incoming ad identical to the stored row is
skipped — and at `Synced` deletes that AP's rows the replay did not touch.
The AP's jobs never vanish mid-replay, and a spoke restart against an
unchanged queue writes almost nothing. Clearing first was rejected for the
reason it was rejected inside scheddsync: every replay would show that AP as
empty for its duration, and fire exactly the false completions above.

**Archive sink: append, with identity dedup during catch-up.** In the live
tail records are new by construction. From session start until `Synced` each
record is checked against what the hub holds for that AP, which covers both a
Reset replay and the at-least-once overlap after a cursor resume. The first
few hundred records are probed by query; past that the catch-up is treated as
a full replay and the AP's identities are loaded once into an in-memory digest
set, because a per-record probe scans the archive's active segment and ran a
100k-record replay past ten minutes.

**Cursors flush on a timer, not only at `Synced`**, and each flush makes the
hub's writes durable *before* saving the cursor. The other order loses rows a
saved cursor already covers.

**Durable archive epochs** (classad) are what make a spoke restart cheap
rather than merely correct: without them, dedup still streams and probes the
spoke's entire retained history every time any of fifty spokes restarts.
Mutable tables keep the random epoch, since a reconcile replay of one AP's
queue is affordable and a durable delete journal is a much bigger change.

### Availability: two hubs, not raft

Two independent hubs, each fed from every spoke. The sinks are deterministic
functions of spoke data, so two hubs converge with no coordination, and a
spoke serves two Watch streams per table without strain. Raft is the wrong
tool: its client-write gap means the federating writes would bypass it
anyway.

The API server reads **one hub at a time**, with sticky selection and
hysteresis. Cursors, `JobsSyncedAt` and absence evidence are all hub-local, so
mixing two hubs within a read, or across the pages of one, produces answers
that are individually consistent and jointly wrong.

## What bites

- **Absence is not completion, per AP** — the whole of the watch section.
- **Collector expiry is not retirement.** One collector restart, every AP
  gone at once.
- **A bare id reaches the wrong job.** Unrecoverable only for mutations,
  which is why the rule is hard there. Test it with the same `123.0` on two
  APs, one of them lagging.
- **Trust mismatches are silent**, which is why the member probe exists.
- **Re-assigning between submit steps** strands jobs at hold code 16.
- **One shared rate limit across fifty APs** produces 429s that look like a
  hot user and are actually a hot AP.
- **Spoke chaining gaps multiply.** The hub has no cluster ads to repair them
  from.
- **Tests that pass on broken code** assert only "my jobs appear". Assert
  both directions: the other AP's same-numbered job is absent, and a
  restarted spoke leaves neither phantoms nor duplicates. Count rows; don't
  just find one.

## Still open

1. **Scale.** Fifty APs at 20k live jobs is 1M rows, within one mutable
   table's shards, but that is arithmetic, not a measurement. The hub's
   archive needs byte-bounded retention from day one. Nobody has run the
   fifty-spoke test.
2. **Several collectors.** The AP set is one constraint over one collector.
   Several means a list of (collector, constraint) pairs — mechanical, but
   new configuration.
3. **Assignment that depends on the submission** (GPUs to a different AP)
   would need request attributes in `apassign.Request`, and the answer could
   not be cached per user.
4. **Jobs on APs where the user has no account** but which the hub shows via
   a `User` match. The schedd would have refused the identity check there.
5. **Short display aliases for APs.** Fifty FQDNs make a wide table. A
   display name only, never an id.
