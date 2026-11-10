# Runtime and drain estimates

How long a job is likely to run, and when an execute node would be empty
if drained now. Both need the
[htcondordb](server.md#further-reading) mirror. Part of the
[HTTP API + MCP server](server.md) documentation.

## Runtime estimates

`GET /api/v1/jobs/{id}/runtime-estimate` estimates how long a job will run
from the runtimes of **the same owner's** similar jobs that have already
completed, and the MCP `get_job` tool carries the same answer as
`runtime_estimate`. It needs the [htcondordb](server.md#further-reading) mirror:
history is read from the mirror's archive every
`HTTP_API_RUNTIME_ESTIMATE_INTERVAL` (default `5m`), never from the
schedd, because a background `condor_history` scan would cost the access
point more than the estimates are worth. Without a mirror the feature is
off; with a mirror that is stale or has a history gap, the estimates in
memory keep answering and the read is retried next interval.

Each completed job is filed under a ladder of groups, from most to least
specific: its cluster, its exact command line (directories, URLs and
hashes dropped), the same command line with every number masked, its
batch name less any run number, its submit directory, its program, and
the owner's jobs as a whole. Every group holds only that owner's jobs,
and only jobs of the same universe (`JobUniverse`; an ad without one
counts as vanilla) that are, like the job asked about, DAG nodes (`DAGManJobId` set) or not, and run
in a container or not: a DAG node is never estimated from its owner's
standalone jobs, nor a container job from bare ones, even ones running
the same command. A job runs in a container when `WantContainer` or
`WantDocker` is true or it names an image in `ContainerImage`,
`DockerImage` or `SingularityImage`; which image does not matter, so
moving to a new image keeps the history. For an interpreter (`python`,
`bash -c`, `apptainer exec`, ...) the program is the script it runs. An
estimate is the median of the most recent 100 runtimes in one group — a
single earlier run is enough, since they are the owner's own jobs. An
owner with no recently finished job of the same kind gets no estimate
(`insufficient_history`): other users' jobs never stand in. Which group
answers is chosen per owner by how well each has predicted that owner's
jobs so far. Each completed job is scored as it would have
been estimated when it was submitted and when it started, from only the
jobs that had finished by then, so the record matches the moment a
question is actually asked. The likely range (`p10_seconds` to
`p90_seconds`) comes from those past estimation errors — the owner's,
pooled with the access point's for the same group level, or the access
point's at every level while those are too few, at the same point in a
job's life (waiting or running) — widened to the group's own spread when
that is larger. Those errors only size the range around an estimate
drawn from the owner's own jobs. Only completed jobs that exited 0 count;
DAGMan and other scheduler/local-universe jobs are left out, and are
never estimated themselves. Nothing about another job — its command, id
or owner — is ever returned.

```json
{
  "job_id": "1234.0",
  "available": true,
  "estimate_seconds": 2710,
  "p10_seconds": 1840,
  "p90_seconds": 5120,
  "basis": {"level": "template", "sample_count": 64},
  "rough": false,
  "elapsed_seconds": 900,
  "remaining_seconds": 1810,
  "exceeded_history": false,
  "model": {"trained_through": "2026-10-10T17:42:11Z", "jobs_ingested": 48213}
}
```

The web UI's job page shows it under the job's status, as "Expected run
time", for a waiting or running job when there is an estimate, and
nothing otherwise.

`elapsed_seconds` and `remaining_seconds` appear only for a running job.
A running job is re-estimated from the runs in its group that lasted
longer than it already has, whenever at least 3 of them did: having
survived this long is information from the first second, not only once
the job passes the median. The upper bound is never narrowed by that
conditioning, which is drawn from a truncated sample and is too tight.
Once the job has outlived all but a couple of the group's runs there is
nothing left to condition on, and if it has also passed the median,
`exceeded_history` is true and no remaining time is given.

When there is no estimate the response is still 200, with
`available: false` and a `reason`: `disabled`, `model_warming_up` (the
history has not been read yet), `insufficient_history` (the owner has no
recently finished job of the same kind), or
`not_estimated` (a scheduler- or local-universe job, such as a DAG's
DAGMan job, whose runtime is never estimated).

`rough` is true when the answer came from one of the broad groups — the
same program whatever its arguments, or the owner's jobs as a whole —
which on a replayed access point were within a factor of two of the actual runtime only a quarter to a third of the time, against
about three quarters for the others; the web UI labels those "rough
guess". `basis.new_command` is true when none of the owner's recently
completed jobs ran the same program.

`memory` says what the runs of the group that answered peaked at, in MiB,
so a page that shows both describes one group:

```json
"memory": {
  "sample_count": 64, "p10_mib": 910, "p25_mib": 1040, "p50_mib": 1210,
  "p75_mib": 1500, "p90_mib": 1980,
  "peak_mib": 6200, "requested_mib": 2048, "above_requested": 9,
  "rough": false, "above_usual": true
}
```

A run's peak is `ResidentSetSize_RAW` (KiB) when the record has it, else
`MemoryUsage` evaluated, as the Utilization page reads it; a run with
neither counts for its runtime and is left out of `memory`, which is
absent when no run in the group has a peak. `peak_mib` is the job's own
peak so far (for a finished job, its peak), `requested_mib` its
`RequestMemory` and `above_requested` how many of the group's runs peaked
above that. `above_usual` is true when a running job, answered from a
specific group (not `rough`) with at least 5 known peaks, has already
peaked at both 1.25 times the group's `p90_mib` and 256 MiB above it;
HTCondor only ever raises a running job's figure, so that excess has
already happened. The jobs listing marks such a job "More memory than
usual". A job that has left the queue is answered from its history
record, which is what the archived job's page shows. It is answered from
groups holding runs other than its own, and its own run is left out of
what it is compared with: `above_usual` applies the same thresholds to
its final peak, and `exceeded_history` is true when its runtime was
longer than the median of the group's other runs and fewer than 3 of
them lasted at least as long.

`POST /api/v1/jobs/runtime-estimates` with `{"jobs": ["1234.0", "1234.1",
...]}` answers for up to 5000 jobs at once (more is a 413), which is how
the web UI's jobs listing asks: once per refresh for the waiting and
running jobs it shows. The answer is `{"available": true, "estimates":
{"1234.0": {...}, ...}, "model": {...}}`, each estimate shaped like the
single-job answer without `job_id` and `model`. Only jobs the caller may
read that are waiting or running are answered; any other id is simply
absent. A server without the feature, or one that has not read its
history yet, answers `{"available": false, "reason": "disabled"}` (or
`"model_warming_up"`) without looking anything up. It is a read, and an
API key or token with only `condor:/READ` may use it.

Metrics, all prefixed `htcondor_api_runtime_estimate_`: `enabled`,
`jobs_ingested_total`, `last_refresh_timestamp_seconds`,
`trained_through_timestamp_seconds`, `refresh_errors_total`,
`refresh_truncations_total`, `keys{level}`, `owners`, and the estimator's
running record of itself, `scored_total{level}` and
`within_2x_total{level}`: every completed job is first scored against the
estimate it would have got when it was submitted, so
`within_2x_total / scored_total` is live accuracy at submit.

## Drain estimates

`GET /api/v1/pool/drain-estimates` answers, for every execute node that is
running jobs or draining, "if this node were drained now, when would it be
empty?" A drain lets each job run until it finishes or its retirement limit
runs out, whichever comes first, then evicts it. The web UI's Pool page
shows it as the "Empty if drained now" column and in its summary cards.

Two numbers go into each job's answer:

- **Its retirement deadline**, known for every job: the startd publishes
  `RetirementTimeRemaining` on each claimed slot, counted from the ad's
  `MyCurrentTime`. A job with a minute or less left (a 30-second limit, or
  one that has already run out — backfill slots have none) is counted in
  `evicted_on_drain` and leaves at its deadline.
- **When it would finish**, known only for jobs submitted from this access
  point (matched by the schedd name in the slot's `GlobalJobId`), from the
  [runtime estimates](#runtime-estimates). On a shared pool most jobs come
  from elsewhere and have none.

So a node whose jobs all have a known end gets `likely_empty_seconds`; one
that also runs jobs nobody can estimate gets `at_least_seconds` (the
estimated part) and `unknown_up_to_seconds` (the latest retirement deadline
among the rest). `at_most_seconds` is the startd's own
`ExpectedMachineGracefulDrainingCompletion` when it publishes one, else the
latest deadline. `exceeded` counts jobs running longer than comparable jobs
have. With runtime estimates off (`HTTP_API_RUNTIME_ESTIMATE_INTERVAL=0`, or
no mirror), the response has the same shape with `estimates_available:
false` and the retirement bounds alone.

```json
{
  "generated_at": "2026-10-11T19:10:00Z",
  "age_seconds": 12,
  "stale": false,
  "estimates_available": true,
  "access_point": "ap2001.chtc.wisc.edu",
  "summary": {"machines": 1, "jobs_running": 4, "jobs_estimated": 2, "jobs_from_this_ap": 2,
              "cores_freeing_next_hour": 8, "draining_nodes": 0, "draining_likely_empty_within_2h": 0},
  "machines": [{
    "machine": "e2231.chtc.wisc.edu", "draining": false,
    "jobs_total": 4, "jobs_estimated": 2, "jobs_from_this_ap": 2,
    "jobs_unknown_end": 2, "jobs_unknown_from_other_aps": 2,
    "likely_empty_seconds": 5400, "likely_empty_at": "2026-10-11T20:40:00Z",
    "at_least_seconds": 5400, "at_most_seconds": 259200, "at_most_at": "2026-10-14T19:10:00Z",
    "unknown_up_to_seconds": 233000, "evicted_on_drain": 0, "exceeded": 0,
    "expected_ends": [{"seconds": 2700, "usually_by_seconds": 5400, "cpus": 4},
                      {"seconds": 5400, "usually_by_seconds": 8100, "cpus": 4}]
  }]
}
```

`?machine=NAME` answers for one node and adds `slots`, one per running job:
`name`, `owner` (`RemoteOwner`), `submitted_from` (the schedd in its
`GlobalJobId`), `from_this_ap`, `running_seconds`, `expected_end` and
`usually_by` (about 90% of comparable jobs are done by then) when estimated,
`exceeded`, `retirement_deadline` and `evicted_on_drain`. Without it the
slots are left out, since a large pool has one per running job.

The answer covers every user's jobs and every signed-in user may read it,
so it is not computed as any of them: one computation, run as this daemon,
reads the claimed slots from the collector and this access point's running
jobs (`JobStatus == 2`, from the htcondordb mirror when there is one, else
one schedd query), and is served to everyone for a minute. A request only
waits for that answer. If a refresh fails, the last good answer is served
with `stale: true` and an `error`; if the running jobs cannot be read, the
answer has the retirement bounds and an `error` saying the estimates are
missing. Not available in multi-AP mode.
