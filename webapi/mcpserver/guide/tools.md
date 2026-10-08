# Every tool, by task

Some tools appear only where the access point supports them (a credential
manager, a job history database, site skills, embedded documentation).

## Submitting
- submit_job -- submit a job from a submit file.
- upload_job_input -- upload the executable and small inputs after submit_job.
- create_input_upload_url -- a URL to PUT a tar of large inputs to.
- submit_dag -- submit a DAGMan workflow (see the "dag" topic).
- build_container -- build and publish an Apptainer image (see "containers").

## Waiting and watching
- watch_jobs / check_watches / cancel_watch -- wait for a job event without
  polling.
- create_watch_url -- a URL that blocks until a watch fires, for something
  outside the conversation to hold.
- query_jobs / get_job -- a one-off snapshot of jobs in the queue.

## Output
- tail_job_output -- the end of a RUNNING job's stdout/stderr.
- exec_in_job -- run one command inside a running job.
- get_job_stdout / get_job_stderr / get_job_output -- a FINISHED job's output.
- create_output_download_url -- a URL that GETs a tar of a job's sandbox.

## Changing jobs
- hold_job / release_job -- pause and resume jobs.
- edit_job -- change job attributes (e.g. increase RequestMemory).
- remove_job / remove_jobs -- cancel jobs.

## Diagnosis
- analyze_issues -- what is going wrong on this access point, grouped.
- analyze_job_match -- why a job is or is not matching slots.
- query_job_epochs -- retry history for jobs that ran more than once.

## History
- query_job_archive -- completed and removed jobs.
- query_transfer_history -- file transfer details.
- query_history_db -- completed jobs from the history database.
- query_jobs_as_of -- the queue at a past instant.
- aggregate_jobs -- grouped counts instead of listings.

## Interactive work
- interactive_session_start / interactive_session_exec /
  interactive_session_list / interactive_session_stop -- a long-lived job to
  run several commands in (see "interactive").

## Credentials
- get_credential_status / list_service_credentials -- what is stored.
- store_service_credential / delete_service_credential -- add or remove one.

## Reference
- doc_guide -- these topics.
- doc_search -- full-text search over the HTCondor reference pages.
- doc_job_attributes / doc_machine_attributes / doc_submit_syntax /
  doc_config_variables -- one reference page each.
- skills_list / skills_get -- this site's own documentation.

## Server
- get_version -- this server's build.
- whoami -- who you are authenticated as and what you can see.
- advertise_to_collector -- publish a ClassAd to the HTCondor collector.
