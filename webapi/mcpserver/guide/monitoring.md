# Monitoring jobs

## Job states

Every job has a JobStatus attribute:

    1 = Idle      -- waiting to be matched to a resource
    2 = Running   -- executing on a remote machine
    3 = Removed   -- deleted by the user or system
    4 = Completed -- finished execution
    5 = Held      -- paused due to an error; see HoldReason
    6 = Transferring Output -- sending results back
    7 = Suspended -- temporarily paused

## Waiting

Do not call query_jobs or get_job in a loop. Register watch_jobs once (for
example event="done" on a cluster) and collect it with check_watches, which
can block for you with wait_seconds. cancel_watch drops a watch you no longer
need. For waiting outside this conversation, see create_watch_url in the
"workflow" topic.

## Reading output

- While the job RUNS: tail_job_output reads the end of stdout/stderr from the
  execute node; exec_in_job runs one command inside the job (ls the sandbox,
  check a process, read a file mid-run).
- After it FINISHES: get_job_stdout, get_job_stderr, get_job_output.

tail_job_output does not work on a scheduler-universe job (a DAGMan manager):
it runs on the access point with no starter to tail, so read its spool with
get_job_stdout / get_job_output instead -- those work while it runs.

## Key job attributes

    ClusterId, ProcId -- job identifier (ClusterId.ProcId, e.g. 123.0)
    Owner             -- submitting user
    JobStatus         -- numeric state (see above)
    HoldReason        -- why a job is held
    RemoteHost        -- machine running the job
    RequestCpus, RequestMemory, RequestDisk -- resource requests
    NumJobStarts      -- how many times the job has started
    EnteredCurrentStatus -- timestamp of last state change

doc_job_attributes explains any other attribute.

## Constraint expressions

query_jobs, watch_jobs and the history tools filter with ClassAd expressions:

    Owner == "alice"                 -- jobs owned by alice
    JobStatus == 5                   -- held jobs
    ClusterId == 123                 -- all procs in cluster 123
    JobStatus == 1 && RequestCpus > 4 -- idle jobs wanting >4 CPUs

## Jobs that have left the queue

- query_job_archive -- completed and removed jobs from the history.
- query_job_epochs -- one record per run attempt, for jobs that restarted.
- query_transfer_history -- file transfer details.
- query_history_db -- completed jobs from the history database, far faster than
  scanning the schedd, where the access point has one.
- query_jobs_as_of -- the queue as it was at a past instant, where the
  database keeps that.
- aggregate_jobs -- counts grouped by attribute ("how many held, per user"),
  instead of listing jobs to count them.
