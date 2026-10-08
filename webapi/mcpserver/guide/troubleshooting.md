# Troubleshooting

## Start with analyze_issues

analyze_issues -- what is going wrong on this access point, grouped into
problems. Reach for it before listing held jobs and reading their reasons
yourself: one root cause appears as thousands of distinct hold reasons,
because the execute node, sandbox path and output filename vary per
occurrence, so a listing makes one problem look like a thousand. It also
covers jobs that could not keep running (the shadow lost contact, the lease
expired), which the queue forgets within minutes because the job is simply
retried. Each cluster says how many DISTINCT USERS it spans, which is the
difference between one person's broken submit file and a site problem.

## A job that stays Idle

analyze_job_match explains why a job is or is not matching slots. It is the
first stop for a job stuck idle: usually a resource request (memory, disk,
GPUs) that no slot satisfies, or a Requirements expression that excludes
every machine.

## A job that is Held (JobStatus 5)

Read HoldReason (and HoldReasonCode / HoldReasonSubCode) with get_job. Then
either fix the cause and release_job, or remove_job and resubmit. edit_job
changes an attribute in place, for example raising RequestMemory on a job
held for exceeding its memory request, before release_job.

Common causes:

- Missing input file, or a system executable with transfer_executable left on
  (see the "submit_files" topic).
- Memory or disk over the request: raise RequestMemory / RequestDisk.
- "Job credentials are not available": the access point requires an OAuth
  service credential the user does not have. get_credential_status and
  list_service_credentials show what is stored; store_service_credential adds
  one (the value must be valid JSON); delete_service_credential removes one.

## A job that ran more than once

query_job_epochs lists each run attempt with where it ran and how it ended.
NumJobStarts > 1 on a job means it restarted.

## Checking the server itself

get_version reports this server's build (version, git commit, linked library
versions); use it to confirm which code is deployed. whoami reports who this
server authenticated you as, whether you are an administrator, and whether the
other tools are confined to your own jobs; ask it when a query returns less
than you expect.

hold_job pauses a job you want to keep but not run; release_job resumes it.
