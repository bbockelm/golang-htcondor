# Multi-AP mode

One server fronting every access point whose schedd ad matches a
collector constraint, instead of one schedd. Part of the
[HTTP API + MCP server](server.md) documentation.

```
HTTP_API_SCHEDD_CONSTRAINT = regexp("^ap[0-9]+\\.example\\.org$", Name)
```

Reads come from a federation hub: an htcondordb running with
`HTCONDORDB_FEDERATE_SCHEDD_CONSTRAINT` that fans every access point's own
htcondordb (its spoke) into one catalog. See the htcondordb federation
documentation for running one; give it the same constraint. Run two for
availability ([two hubs](#two-hubs) below). Actions go to
the schedd of the access point the job is on, as you. New work goes to the
access point your [assignment](#ap-assignment) names.

What it serves:

| Request | Answer |
| --- | --- |
| `GET /api/v1/jobs`, MCP `query_jobs` | Your queued jobs on every access point, from the hub. `?schedd=` (MCP `schedd`) limits it to one. Pages continue with `next_page_token`. |
| `GET /api/v1/jobs/archive`, MCP `query_job_archive` | Your completed jobs, newest first by `EnteredHistoryTime`. Pages continue with `next_page_token`; `before_cluster`/`before_proc` are refused, because a cluster id is unique only within one access point. |
| `GET /api/v1/jobs/{id}`, MCP `get_job` | One of your jobs, queued or completed (`archived`). |
| MCP `aggregate_jobs` | Counts over `jobs` or `history`; group by `ScheddName` for a per-access-point count. |
| `GET /api/v1/aps`, MCP `list_access_points` | The access points, whether each is in the collector, how current the hub's copy of each is, and whether it trusts this server (`trust`). |
| One job: `DELETE`/`PATCH /api/v1/jobs/{id}`, `POST .../hold`, `.../release`, `.../warm`; `GET .../stdout`, `.../stderr`, `.../log`, `.../peek`, `.../dag`, `.../files/{name}`, `.../output`, `.../watch`, `.../ssh`; `PUT .../input`, `POST .../input/multipart`, `.../input/share`, `.../output/share`; `/api/v1/jobs/{id}/proxy/...` | As in single-AP mode, against the job's own access point. `{id}` must be complete. |
| MCP `remove_job`, `hold_job`, `release_job`, `edit_job`, `get_job_stdout`, `get_job_stderr`, `get_job_output`, `upload_job_input`, `create_input_upload_url`, `create_output_download_url`, `tail_job_output`, `exec_in_job` | As in single-AP mode, against the job's access point. `job_id` must be complete, or bare with `schedd`. |
| Bulk: `POST /api/v1/jobs/hold`, `.../release`, `DELETE /api/v1/jobs`, `PATCH /api/v1/jobs`, MCP `remove_jobs` | Run on every access point; see below. |
| `GET /api/v1/share/output`, `PUT /api/v1/share/input` | A share URL acts on the access point it was minted for. |
| `POST /api/v1/jobs`, MCP `submit_job`, `submit_dag`, `build_container` | Submit, as you, to your home access point, or with `?schedd=` (MCP `schedd`) to one of its alternates; see [AP assignment](#ap-assignment). The answer carries complete job ids. |
| `/api/v1/creds/user`, `/api/v1/creds/service[/...]`, MCP `list_service_credentials`, `get_credential_status`, `store_service_credential`, `delete_service_credential` | Your home access point's credd, or with `?schedd=` (MCP `schedd`) that of any access point in the set. The response header `X-HTCondor-Access-Point` (MCP: `schedd`) names it. |
| `GET /api/v1/templates` and the rest of `/api/v1/templates` | Submit templates, from this server's own database. |
| `POST /api/v1/interactive/terminal`, `POST /api/v1/jupyter/instances`, `POST /api/v1/apps`, MCP `interactive_session_start` | Start a terminal, a JupyterLab, an app or a named session on your home access point for that kind of work, or with `?schedd=` (MCP `schedd`) on an alternate; see [interactive work](#interactive-work-in-multi-ap-mode). The answer names the access point (`schedd`) and the complete job id. |
| `GET /api/v1/interactive/terminal`, `GET /api/v1/jupyter/instances[/{id}]`, `GET /api/v1/apps[/{id}]`, `DELETE /api/v1/apps/{id}`, the JupyterLab tunnel, events and proxy, MCP `interactive_session_exec`, `interactive_session_list`, `interactive_session_stop` | As in single-AP mode, against the access point each one is on. |
| MCP `watch_jobs`, `check_watches`, `cancel_watch`, `create_watch_url`; `POST /api/v1/watches/{id}/share`, `GET /api/v1/share/watch` | Watches over your jobs on every access point; see below. |
| `GET /api/v1/jobs/watch` | Changes to your jobs on every access point, from the hub's jobs stream; each event's `key` is the complete job id. |
| `GET /api/v1/dashboard`, `.../dashboard/activity`, `.../dashboard/activity/stream` | Your jobs on every access point, from the hub, in total and per access point (`aps`), with the `sources` block; see below. |
| `GET /api/v1/issues`, MCP `analyze_issues` | Held jobs and failed run attempts on every access point, from the hub; every example and cluster names its access point (`schedd`, `schedds`). Run attempts need the hub to federate `epoch_history`; without it the answer says so in `notes`. |
| `GET /api/v1/jobs/epochs`, `.../transfers`, MCP `query_job_epochs`, `query_transfer_history` | Run-attempt and transfer records; see below. |
| `GET /api/v1/metrics/job_metrics` | Resource-usage samples of your jobs on every access point, from the hub; see below. |
| `GET /api/v1/jobs/{id}/match-analysis`, MCP `analyze_job_match` | The job's ad from its access point, the slots from the collector. `{id}` must be complete. |
| `GET /api/v1/collector/...` (not `advertise`), MCP `query_pool` | The pool's collector, which the access points share. |
| MCP `get_access_point_policy` | Your home access point's policy, or with `schedd` that of any access point in the set, as its schedd reports it. The answer names it (`schedd`). |

Everything else -- drain estimates and runtime estimates (they read one
schedd's running jobs), any other method on `/api/v1/metrics/job_metrics`
and any other table under `/api/v1/metrics/`,
the single-schedd status routes (`/api/v1/ping`, `/api/v1/schedd/ping`,
`/api/v1/dbmirror/*`; `/api/v1/aps` and `/readyz` describe the access
points and the hub) and chat -- answers **501** ("not available in
multi-AP mode yet"), and the MCP catalogue offers only the tools above
plus `whoami`, `get_version`, `doc_*` and `skills_*`. Superuser mode is
not available.

**Watches.** One evaluator follows every registered watch over the hub,
and the hub's jobs table is followed as one change stream for every access
point (resumed from its position after a dropped connection). A watch's
constraint selects among your jobs on every access point -- add
`ScheddName` to it to watch one -- and each job it tracks and reports
carries its access point (`schedd`): the same `cluster.proc` on two access
points is two jobs. A job that leaves the queue is reported finished from
its history record, or from its last ad on the hub's stream saying it
completed or was removed, on any access point. Its *absence* from the
queue counts as finished only for an access point the hub reports
`fresh`, with a measured staleness, its jobs stream connected and
error-free, and its jobs table caught up: `JobsSynced` true in the
`federation_sources` rows read just before and just after the queue read,
with the same `JobsSyncedAt` (a hub too old to publish `JobsSynced` is
instead not trusted within ten minutes of the access point's `LastReset`).
It also counts only once that read reflects the access point from after
the job was last seen there (allowing for the reported staleness, a
minute for the hub's row refresh and one hub state interval). A stale,
absent, retiring or untrusted access point, a disconnected, failing or
replaying stream, or an unreachable hub never yields a "finished" on
absence; the watch waits, and fires once the history record arrives or
the access point is current again. A watch entry stored before access
points were recorded resolves from a history record when exactly one
access point has that `cluster.proc`, and otherwise waits. A watch URL is about its owner's jobs
on every access point, so it carries `"s": "*"` inside its signature: a
multi-AP server refuses a watch URL without it, and a single-AP server one
with it. An identity outside `UID_DOMAIN` cannot register or share a
watch.

**Dashboard.** `jobs_by_status` and `jobs_total` count your jobs on every
access point; `aps` gives each access point's counts and its state on the
hub. The activity answer's lists carry `schedd` and `job_id` on each job,
and its `aps` give each access point's `finished_recently`: history
records in the last hour plus jobs the hub's stream saw leave the queue
whose last ad said they completed or were removed. A delete alone is not
counted: it is also what retiring (`.retire`) or replaying an access
point looks like, and a job that leaves held or idle has not been shown
to have finished. An access point that is not fresh has its count marked
`finished_partial`. Hub reads have no cross-user view, so
`owned_by_me=false` is not honoured.

**Run attempts and transfers.** With the hub federating `epoch_history`
(`HTCONDORDB_FEDERATE_TABLES = jobs history syncstatus epoch_history`),
`/api/v1/jobs/epochs` and `.../transfers` (and their MCP tools) read your
records on every access point from it, newest first, each with `schedd`
and `job_id`; `?schedd=` and `?job_id=` narrow them (a bare `123.0` is
accepted when one access point has that job of yours). Transfer records
are the run-attempt records whose `EpochAdType` is `INPUT`, `OUTPUT` or
`CHECKPOINT`. Without `epoch_history` on the hub, a request naming a job
or an access point is sent to that access point's schedd, as in single-AP
mode, and each record carries `ScheddName`; one naming neither is a
**501** with `"reason": "epoch_history_not_federated"` -- answering it
would scan every access point's history file on every request, with no
order or page token across them.

**Resource usage.** With the hub federating `job_metrics` (each spoke
running with `HTCONDORDB_JOB_METRICS`, and the hub with
`HTCONDORDB_FEDERATE_TABLES = jobs history syncstatus job_metrics`),
`GET /api/v1/metrics/job_metrics` takes the same `constraint`,
`group_by`, `bucket`, `agg`, `since` and `until` as in single-AP mode and
aggregates your samples on every access point. Every caller,
administrators included, reads only their own (`User`), on member access
points only. `?job_id=` reads one job's samples: a complete id, or a
bare `123.0` when one access point has that job of yours (on two it is a
**409** with the `candidates`); the answer's `job` names the complete id.
`?schedd=` reads one access point's, and settles a bare `job_id`. A
`group_by` naming `ClusterId` or `ProcId` gains `ScheddName` before
them, since the same `cluster.proc` on two access points is two jobs;
`group_by=ScheddName` aggregates per access point. The answer carries the `sources` block. A hub that does not
federate `job_metrics` answers `{"enabled": false}` with the `sources`
block, as single-AP mode answers without the sampler. One aggregate is
bounded at 30 seconds and 20000 rows, as in single-AP mode. A sample its
access point's htcondordb never tied to its job carries no `User`, so no
read returns it -- not even one naming that job -- and it is missing from
the job page's graphs. The job page draws its resource-usage graphs from
this, by the job's complete id, and says so when the job's access point
records no usage (`not_kept`).

The dashboard, the issues view, run-attempt reads and resource usage also
name, in their `sources` block, each access point whose stream of the
table they read (`jobs`, `history`, `epoch_history`, `job_metrics`) is
disconnected, failing, still catching up or not federated, with a
`reason` naming the table, so a short answer says which access points it
is short of. An access point whose own htcondordb keeps no such table at
all (the hub reports `<Table>Missing`, e.g. a spoke without
`HTCONDORDB_JOB_METRICS` or epoch history) has no rows to be short of:
it is listed in `not_kept` (`schedd`, `table`, `reason`) instead, and
still counts as fresh. Only those two tables are optional; an access
point the hub reports has no `jobs`, `history` or `syncstatus` table is
degraded.

**Actions need a complete id.** A mutation, a sandbox read, a share URL or
an SSH connection naming only `123.0` is a **400** with
`"reason": "incomplete_job_id"` and your jobs with that number as
`candidates` -- it is never resolved for you, because the hub may know
your finished `123.0` on ap1 and not yet the `123.0` you just submitted on
ap3, and a wrong guess on remove cannot be undone. An access point the id
names but this server cannot act on is its own error, never "job not
found": `unknown_access_point` (404, not in the set),
`access_point_absent` (503, not in the collector right now) or
`access_point_untrusted` (503, "this access point does not trust this API
server's tokens"). Action responses carry the complete `job_id`.

**Bulk actions** run on every access point with bounded concurrency and a
per-access-point timeout, and report each:

```json
{"message": "Bulk job hold completed on every access point",
 "constraint": "JobStatus == 1",
 "results": {"total": 4, "success": 4, "not_found": 0, "permission_denied": 0,
             "bad_status": 0, "already_done": 0, "error": 0},
 "jobs_edited": 0,
 "complete": true,
 "aps": [
   {"schedd": "ap1.example.org", "status": "acted", "results": {"total": 2, "success": 2, ...}},
   {"schedd": "ap2.example.org", "status": "skipped",
    "reason": "the federation hub's copy of this access point is 3s behind (within 30s) and holds no matching job"},
   {"schedd": "ap3.example.org", "status": "failed", "error": "..."}]}
```

`status` is `acted`, `no_match`, `skipped`, `failed`, `unreachable` (not in
the collector; not contacted) or `untrusted` (not contacted). By default
every usable access point is contacted. Setting
`HTTP_API_BULK_FRESH_SECONDS` above 0 lets the hub narrow the fan-out: an
access point is then skipped only when it is provably empty -- the hub
reports it fresh with a measured lag within that many seconds, its jobs
stream connected and error-free, and it holds no row that could match your
scoped constraint there (a row the hub cannot evaluate, such as one
missing `Owner` or using a function the hub lacks, counts as a possible
match) -- and this server has not changed anything on it within the
tolerance plus a minute. That last record is per process: it is lost on a
restart and not shared between replicas, so a skip can miss a change
another replica made moments ago. A stale, absent or unmeasured source,
or a hub that does not answer within 5 seconds, is never proof. The
fan-out runs to the end even if the client disconnects (bounded at five
minutes) and is logged per access point. The answer is 200; 404 when
every access point was accounted for and nothing matched; 502 when no
access point could be acted on; 503 when no access point is known yet.
`complete: false` means some access point was not covered -- see `aps`.
The constraint is confined to your jobs per access point exactly as in
single-AP mode, and one that does not parse is a 400 before anything is
contacted.

**Administrators** are scoped per access point: this server's own grant
(admin group, `mcp:admin`, `mcp:superuser`, `MCP_ADMIN_USERS`) is
necessary, and the caller must also be in that access point's
`QUEUE_SUPER_USERS`, read from it. A queue superuser on ap1 reads and acts
on other users' jobs there and nowhere else. Hub reads have no admin view.
Project leads see their own jobs only.

**Trust.** Every member is probed when it joins, when its address changes
and every ten minutes (an untrusted one every minute): a token minted from
the signing key for `htcondor-api-trust-probe@UID_DOMAIN` must be accepted
and reported back as exactly that identity, and the member must report a
`UID_DOMAIN` equal to this server's. A member that refuses the token,
reports another identity, or will not or cannot report a matching
`UID_DOMAIN` is `untrusted` in `/api/v1/aps` and in every `sources` block;
actions on it fail fast, and bulk actions report it. A member that does
not answer at all stays `unknown`. Only trusted members identify callers
(a bearer token's identity is asked of them); a request routed to an
access point is identified by that access point alone.

**Each access point's own verdict.** A refresh revokes a grant only when
every trusted member's user record (`condor_qusers -disable`) says so. A
user disabled on one access point is still refused there: requests routed
to it -- actions, sandbox reads, SSH, share URLs, bulk legs -- answer 403
`"reason": "access_point_denied"`, while the other access points serve
them. Verdicts are reused for a minute.

**Identity in queries.** Routed reads and actions are confined on the
`User` attribute (`owner@UID_DOMAIN`), not the bare `Owner`, and an
identity in another domain is refused.

**Per-access-point state.** Rate limits (`SCHEDD_QUERY_RATE_LIMIT`,
`SCHEDD_QUERY_PER_USER_RATE_LIMIT`) apply per access point, so one busy
access point does not spend the others' budget. Share URLs carry the
access point inside their signature; a multi-AP server refuses one without
it. Job transports, DAG structures and per-job watches are kept per access
point.

**SSH gateway.** Connect to a job as its complete id:
`ssh 123.0@ap1.example.org@gateway.example.org` (OpenSSH splits the user
from the host at the last `@`). A bare `123.0` is refused with your
candidates. A session name (`ssh +work@gateway`, or a bare `ssh gateway`
for the default session) reaches that session on whichever access point it
is on, or starts it on your assigned one; see below.

**Proc-less ids.** `123@ap1.example.org` names a whole cluster for an input
upload (`PUT .../input`, `POST .../input/multipart`, `.../input/share`), as
`123` does with one schedd, and is a 400 everywhere else.

## Interactive work in multi-AP mode

Browser terminals, named interactive sessions (MCP and the SSH gateway),
JupyterLab and apps are placed like a submission: on the access point your
[assignment](#ap-assignment) names for that kind of work -- `interactive`
for terminals, sessions and apps, `jupyter` for JupyterLab -- or, with
`?schedd=` (the `schedd` argument of `interactive_session_start`), on one
of its alternates. From then on each is reached on the access point its
own record names, and the assignment is never asked again for it: a user
whose assignment moves keeps what they have where it is, and only new work
goes to the new access point.

- **Terminals** are named by their complete job id, which the `/ssh`
  bridge, its heartbeat and its disconnect cleanup route by.
- **Sessions** are named by the caller, and a name is unique per user
  across every access point, so `ssh +work@gateway` and
  `interactive_session_exec` always mean one job. Starting a session asks
  every access point that may hold one of your sessions -- those the
  federation hub lists, those this server has reached since it started,
  and the assigned one -- and refuses a name already in use anywhere;
  the per-user session limit counts every access point. A name found on
  two access points (two servers racing, say) is refused with both job
  ids rather than resolved: remove the one you do not want by its id.
  Exec, stop, the heartbeat and lease expiry go to the session's access
  point; if it cannot be reached the call fails naming it. Sessions this
  server did not start or has not reached since its last restart are
  found through the hub, so starting one, or finding one this server
  does not already know, needs the hub to answer. Each access point has
  15 seconds to answer a listing; one that does not is treated as
  unreachable. `interactive_session_list` reports each session's access
  point; one whose access point cannot be asked is reported from the hub,
  and from this server's own record of it, with `access_point_error`.
- **The SSH gateway** resolves a session name the same way, and starts a
  missing one on your assigned access point. It knows you only by your
  account, so an assignment rule on a group does not apply to a session it
  starts. Approving an SSH login with a workspace starts it the same way,
  with the groups your browser session recorded, and the approval screen
  names the access point.
- **JupyterLab** records the access point in the session's row
  (`jupyter_sessions.schedd`), and every status read -- including after a
  restart adopts the session -- goes there. A row written by a single-AP
  server has none; in multi-AP mode its job is not looked for on any
  access point (its cluster id names no access point), so it is listed
  without job status or job id until it expires, and is not reaped
  meanwhile. The reverse holds after switching back to one schedd: a row
  a multi-AP server wrote for another access point is not looked for on
  this one.
- **Apps** have ids of the form `<id>@<schedd>` in this mode, so `GET` and
  `DELETE /api/v1/apps/{id}` go straight to the app's access point. A bare
  id is located through the hub, and one found on two access points is a
  409.

Lists (`GET /api/v1/interactive/terminal`, `GET /api/v1/apps`) come from
the hub, with a `sources` block, like every other multi-AP read.
`GET /api/v1/aps?kind=interactive` (or `jupyter`) reports where that kind
of work would go; the web UI's interactive page uses it to name the access
point and offer the alternates.

## AP assignment

Which access point a user's **new** work goes to is decided by an ordered
chain of backends, `HTTP_API_AP_ASSIGNMENT`. The first backend to answer
wins; an unknown backend name refuses to start the server.

```
HTTP_API_AP_ASSIGNMENT          = mapfile, rest
HTTP_API_AP_ASSIGNMENT_DEFAULT  = ap01.example.org
HTTP_API_AP_ASSIGNMENT_MAPFILE  = /etc/condor/ap-assignment.map
```

An answer names a home access point and, optionally, alternates. A
submission goes to the home access point; `?schedd=` on `POST
/api/v1/jobs` (or the `schedd` argument of `submit_job`, `submit_dag` and
`build_container`), and on the interactive surfaces above, may name the
home access point or an alternate, and anything else is **403**
`"reason": "target_not_allowed"`. Existing jobs
stay where they are: assignment happens once per submission, the answer
carries complete job ids, and every later step -- the input upload of a
two-step submit (`PUT .../input`, `upload_job_input`,
`create_input_upload_url`) above all -- addresses the job by that id. A
change to the assignment between the steps does not move the job. DAGMan's
node jobs land on the DAGMan job's access point.

Backends:

- **`static`** (the default) assigns everyone to
  `HTTP_API_AP_ASSIGNMENT_DEFAULT`; with no default nobody can submit. It
  answers for everyone, so it must be last in the chain.
- **`mapfile`** reads `HTTP_API_AP_ASSIGNMENT_MAPFILE`, in HTCondor mapfile
  syntax. Each line is a match, a principal, the home access point and
  optional alternates; the **first** matching line in file order wins:

  ```
  # match    principal                           schedd            alternates
  USER       alice@example.org                   ap12.example.org  ap13.example.org
  GROUP      cms                                 ap20.example.org
  USER       /@physics\.example\.org$/           ap30.example.org
  SUBJECT    /^svc-/                             ap31.example.org
  GROUP      "High Energy Physics"               ap32.example.org
  *          /.*/                                ap01.example.org
  ```

  `USER` matches the HTCondor identity (`alice@UID_DOMAIN`), with the
  domain compared without regard to case as HTCondor compares domains and
  the user part exactly; `GROUP` any of the caller's groups as the login
  recorded them (the web session's groups, or an OAuth2 grant's; a caller
  presenting an HTCondor token has none); `SUBJECT` the subject this
  server knows the caller by -- the web session's username or the OAuth2
  grant's subject, which is the name *after* identity mapping, not the
  upstream IdP's `sub`; `*` any of the three.

  A principal is a literal, compared exactly; a double-quoted literal
  (which may contain spaces, `\"` and `\\`); or a regular expression in
  slashes, optionally followed by `i` (ignore case) and `U` (ungreedy) as
  HTCondor accepts. This is HTCondor's *hash* mapfile convention
  (`CLASSAD_USER_MAPFILE_*`): unlike a classic `CERTIFICATE_MAPFILE`,
  where every principal is a regular expression, a principal here is an
  expression only between slashes. A literal containing `^`, `$` or `*` is
  logged as a probable mistake. Inside slashes `\/` is a slash and `\\`
  one backslash, exactly as HTCondor reads it. An expression is searched
  for, not anchored: write `^` and `$`. Go's RE2 syntax applies: PCRE2's
  minus backreferences and lookaround, and with `i` RE2 folds case by
  Unicode simple folding where PCRE2 without UTF mode folds ASCII only, so
  a non-ASCII principal may match where HTCondor's would not. A line or
  the rest of a line starting with `#` is a comment. `@include` is
  refused.

  The file is checked for changes every two seconds in the background,
  never while answering a request, and re-read on reconfigure. A file that
  does not parse refuses to start the server; an edit that does not parse
  keeps the last map that did and is logged.
- **`rest`** asks a site service:

  ```
  GET {HTTP_API_AP_ASSIGNMENT_REST_URL}/v1/assignment?user=alice%40example.org&subject=...&kind=job&group=cms&group=...
  Authorization: Bearer <contents of HTTP_API_AP_ASSIGNMENT_REST_TOKEN_FILE>

  200 {"schedd":"ap12.example.org","alternates":["ap13.example.org"],"ttl_seconds":300}
  404 {"result":"no_assignment"}  -> no answer: ask the next backend
  403 {"result":"denied"}         -> this user may not submit
  ```

  `kind` is `job`, `dag`, `container_build`, `interactive` (browser
  terminals, named sessions and apps) or `jupyter`. A 404 or 403 counts only
  with that body: a 404 page from a proxy or a mistyped path, or a 403 for
  some other reason, is an error -- otherwise it would send everyone to the
  default, or deny everyone. **Answer a bad or missing bearer token with
  401**, which is an error. Any other status, a body that is not the
  expected JSON or is over 64 KiB, a redirect (never followed), or no
  answer within 2 seconds is an error. The URL must be `https`, except to
  a literal loopback address (`127.0.0.1`, `[::1]`; not `localhost`).
  The token file is re-read when it changes; one that cannot be read keeps
  the token already read. Errors are logged without the query, which names
  the user.

Behavior common to every backend:

- **Errors do not fall through.** A failing backend never sends anyone to
  the next backend or the default. The user's last known good answer is
  used for up to `HTTP_API_AP_ASSIGNMENT_STALE_SECONDS` (default 3600)
  after it *expired* (its TTL ran out), so an answer with a long TTL is
  covered for the whole window too; after that, or with none, the answer
  is **503** `"reason": "assignment_unavailable"`. A reconfigure makes
  every answer stale but keeps it as last known good. Each backend has a
  hard 2-second timeout. A request whose caller disconnected is not
  counted as a backend failure.
- **The default** (`HTTP_API_AP_ASSIGNMENT_DEFAULT`) is used only when
  every backend has no answer. Without one, that user gets **403** "no
  access point is assigned to you" (`no_access_point_assigned`).
- **Answers are validated.** A home access point outside the AP set is a
  **503** (`assignment_invalid`) and an error in the log; an alternate
  outside the set is dropped and logged. Work is never submitted outside
  the set. A target that is in the set but not in the collector right now,
  or untrusted, is a **503** (`target_unavailable`); an alternate still
  takes work while the home access point is down.
- **Answers are cached** per user, kind, subject and groups for the
  answer's TTL (mapfile 60 s, rest 300 s unless `ttl_seconds` says
  otherwise; at most an hour), up to 10000 entries. An edited mapfile takes
  effect within its two-second check.
- **The access point's own verdict** applies as for actions: a user
  disabled on the target access point is refused there (403
  `access_point_denied`), and the job is owned by the identity that access
  point reports for your credential.

`GET /api/v1/aps` reports your `assignment` and marks each access point
with `submit` (home or alternate) and `home`; `GET /api/v1/auth/me` and
`GET /api/v1/whoami` carry the same `assignment`, and MCP `whoami` reports
`home_access_point` and `alternate_access_points`. The web UI's submit page
says which access point a batch will go to and offers the alternates.

**Credentials follow the access point.** Each access point's schedd names
its credd (`CredDIpAddr`), and a credential is only useful there. The
pre-submit credential check (`HTTP_API_REQUIRED_CREDENTIALS` and the
credd's own check) runs against the target access point's credd, and what
it finds is cached per credd. Moving a user's home access point does not
move stored credentials; the first submission to the new one asks for
them. `HTTP_API_CREDD_ADDRESS` names one credd for one schedd and refuses
to start a multi-AP server.

**Job ids.** A job is identified by schedd, cluster and proc together: two
access points each have a `123.0`. Every job in a response carries
`schedd`, `cluster` and `proc` as separate members, plus `job_id`, the
single-token form used in URLs (`123.0@ap40.example.org`; the text before
the first `@` is `cluster.proc`, the rest is the schedd name). An
incomplete id such as `123.0` is accepted by `GET /api/v1/jobs/{id}` and
`get_job` when exactly one of your jobs, queued or completed, has it; the
answer carries the complete id. Several matches are a **409** whose body
lists them:

```json
{"error": "Conflict", "code": 409,
 "message": "job 123.0 exists on 2 access points; name one",
 "candidates": [
   {"schedd": "ap1.example.org", "cluster": 123, "proc": 0, "job_id": "123.0@ap1.example.org", "archived": false},
   {"schedd": "ap2.example.org", "cluster": 123, "proc": 0, "job_id": "123.0@ap2.example.org", "archived": true}]}
```

**Freshness.** Every list response carries a `sources` block naming each
access point whose rows are not known to be current, and the hub the
rows came from (`hub`, its collector ad `Name`):

```json
"sources": {"hub": "hub-a@db.example.org", "aps": 52, "fresh": 50, "degraded": [
  {"schedd": "ap17.example.org", "state": "stale", "staleness_seconds": 412},
  {"schedd": "ap31.example.org", "state": "absent", "reason": "the federation hub does not hold this access point"}]}
```

`state` is the hub's (`stale`, `absent`, `untrusted`, `retiring`), or
`absent` for an access point the hub does not list. By default a degraded
access point's rows are included as the hub holds them;
`HTTP_API_MULTI_AP_STALE = exclude` leaves them out, and the access point is
still listed in `degraded`. Nothing is omitted silently. A single job on an
access point the hub does not hold fresh is read from that access point's
own htcondordb if it is current, else from its schedd as you; the response
says which (`source`: `hub`, `spoke` or `schedd`).

**Scope.** Every hub read is confined to your own jobs on the `User`
attribute (`owner@UID_DOMAIN`), whatever constraint you pass. An identity in a domain other than `UID_DOMAIN`
(compared case-insensitively, as HTCondor does) is refused with a 403
rather than read as the same name in `UID_DOMAIN`. The access points must share one `UID_DOMAIN`,
`TRUST_DOMAIN` and pool signing key: a bearer token's identity is
confirmed by asking an access point's schedd, and any one of them can
answer.

**The access point set** is polled from the collector every 60 seconds. An
access point whose ad disappears stays listed (`in_collector: false`)
with its last address; nothing is removed because the collector stopped
mentioning it.

**Health.** `/readyz` is ready when some hub answers and at least one
access point matches, and lists every access point's state and every
hub's to an admin session or a `metrics` API key (anyone else gets the
counts); one access point being down never makes the server unready, nor
does one of two hubs. The collector ad carries `ScheddConstraint` and
`ScheddCount` instead of `ScheddName`.

<a id="two-hubs"></a>**Two hubs.** For availability, run two federation hubs, each an
independent htcondordb fed from every spoke, rather than one replicated
hub. Their tables are deterministic functions of the spokes' data, so the
two converge with no coordination between them. Give each its own
`HTCONDORDB_NAME` (the collector keys their ads on it) and the same
`HTCONDORDB_FEDERATE_SCHEDD_CONSTRAINT`; nothing else differs. This
server discovers every `HTCondorDB` ad carrying `FederationConstraint`,
re-discovering every 30 seconds, or uses the hubs `HTTP_API_HUB_NAME`
lists. A discovery that finds no hub at all (a collector that just
restarted) keeps the hubs last found for five minutes.

It reads from **one hub at a time** -- the active hub -- and never mixes
the two within a request or a watch evaluation: a watch cursor, a
`JobsSyncedAt` and a job's absence each mean something only on the hub
that reported it. Every hub's `federation_sources` is read every 5
seconds. The active hub is kept while it answers and is not clearly
worse, and replaced when:

- it stops answering: `HTTP_API_HUB_FAIL_AFTER` reads of its
  `federation_sources` in a row failed (default 2, so about 10 seconds),
  or as many reads of its data in a row failed on the connection -- it
  could not be dialed, the connection dropped, the read timed out. A
  query the hub refused does not count, and a failed read brings the
  next check forward. Reads move to the answering hub with the most fresh
  access points. With nowhere to go, the active hub is kept.
- another hub has reported at least `HTTP_API_HUB_SWITCH_MARGIN` more
  fresh access points (default 1) at every check for
  `HTTP_API_HUB_SWITCH_SECONDS` (default 120), and the last switch is at
  least that old. A difference that does not last that long -- each
  hub's state pass lands at its own moment -- never switches. An access
  point counts as fresh for this only with its jobs stream caught up
  (`JobsSynced`, or, on a hub too old to publish it, no `LastReset`
  within ten minutes): a hub replaying an access point does not rank as
  holding it.

Nothing switches back just because the first hub returned. With one hub
there is nothing to choose and nothing changes. `/api/v1/aps` reports the
hub the answer came from (`hub`), every hub with the active one marked
(`hubs`: `name`, `address`, `active`, `reachable`, `fresh_aps`), and the
last switch (`hub_switch`: `from`, `to`, `reason` `unreachable` or
`fresher`, `at`); a switch is logged as a warning.

What a switch does to each consumer:

- **Reads** (lists, history, single jobs, the dashboard, issues, run
  attempts, utilization, MCP tools) are pinned to the active hub when the
  request starts. One already running finishes on its hub; the next is
  served by the new one, and its `sources` block is the new hub's.
  Cached answers (issues, utilization) are kept per hub.
- **Settling.** Two hubs are not in step: the new one may not yet hold a
  job the old one showed, and its `federation_sources` can say an access
  point is fresh while its jobs stream is still behind (`StalenessSeconds`
  is measured on the heartbeat stream, and `JobsSynced` says a catch-up
  finished, not that nothing is queued behind it). So for
  `HTTP_API_HUB_SETTLE_SECONDS` after a switch (default 90: the hub's
  default 60-second fresh threshold and a margin) every access point the
  new hub holds fresh is reported `settling` in `sources`, with a reason
  naming the switch; a by-id read the new hub misses (`GET
  /api/v1/jobs/{id}`, MCP `get_job`) is asked of the access point's own
  htcondordb or schedd instead of answering 404; and a bulk action never
  skips an access point on the new hub's word. What is guaranteed: a
  read says which hub it came from and that hub's own view of every
  access point, and never mixes two hubs. What is not: that a hub
  reporting an access point `fresh` holds every change on it -- a list
  read may lack a job another hub showed, during the settle window or
  after it if the hub's jobs stream is backlogged. A first selection at
  startup is not a switch and does not settle. An access point that is
  settling and that the new hub reports keeps no copy of an optional
  table (`job_metrics`, `epoch_history`) is listed in `not_kept` for it
  as well: it has none of those rows on any hub.
- **Page tokens.** A job list token (`/api/v1/jobs`, MCP `query_jobs`)
  is a position in one hub's change log and names that hub; asked of
  another, it is refused with a 400 (`reason`: `restart_pagination`), and
  the listing must start over from the first page. Back on the hub that
  issued it, it resumes. A token also expires: the hub keeps the snapshot
  a listing reads for a lease period (ten minutes by default) from when
  the listing reached each shard, and across a hub restart not at all.
  A token whose snapshot the hub has since reclaimed is refused the same
  way, with a 400 and `restart_pagination`. History tokens (`/api/v1/jobs/archive`) are
  ordered by the job's values, which every hub orders alike, and carry
  on across a switch.
- **Watches** are evaluated one owner's pass at a time, each pass pinned
  to one hub: its queue read, the `federation_sources` reads around it,
  its history read and the stream's terminal records all come from that
  hub. When the hub changes, the evaluator starts its memory of each
  watch's jobs over. A tracked job counts as gone by its absence only
  once it has been seen in the new hub's queue (and then only where that
  hub vouches for its access point, as above); a job the new hub has
  never shown -- it may still be in its jobs stream's backlog -- is
  finished only by the new hub's history record or a terminal record on
  its stream, which a job that really finished reaches in time. A server
  that restarts with two hubs known treats every tracked job the same
  way until it sees it. Nothing fires on the new hub on evidence gathered
  on the old one.
- **The jobs stream** (`/api/v1/jobs/watch`, the activity ticker,
  terminal records) ends when the active hub changes and starts over on
  the new one, from its head, as on a Reset: what it held from the old
  hub is dropped, its departures with it, and the old hub's cursor is
  never sent to the new one. A Reset never reports departures.
- **Writes** go to the access points, not the hubs, and nothing here
  waits for a write to reach a hub: a list read right after an action
  may show the job as it was, on either hub. The one decision that
  trusts a hub after a write -- a bulk action skipping an access point
  under `HTTP_API_BULK_FRESH_SECONDS` -- refuses for a window after any
  write this server made there, refuses during a settle window, and
  otherwise requires the hub it asks to measure its own lag behind that
  access point within the bound. A by-id read during a settle window
  that the new hub misses is answered by the access point itself.

The web UI shows an access point column and filter on the job and
archive lists, which access points are behind, and an Access Points page;
it offers no actions yet.

`HTTP_API_SCHEDD_CONSTRAINT` together with `-schedd`, `-schedd-addr` or
`SCHEDD_NAME` is a startup error. `UID_DOMAIN` and a collector are
required.
