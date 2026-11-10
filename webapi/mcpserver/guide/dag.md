# Workflows with dependencies (DAGMan)

When the work is a graph rather than a job -- step B needs step A's output, a
step should be retried on failure, a script runs before or after a step -- use
submit_dag instead of submitting the steps one at a time and sequencing them
yourself. DAGMan runs on the access point and keeps going while you are not.

1. submit_dag -- pass the workflow as ordinary DAG syntax. Put the node submit
   descriptions inline with SUBMIT-DESCRIPTION so the whole workflow is one
   self-contained file; anything referenced by file name goes in the same
   call's `files`, and there is no second chance -- a workflow's spool is
   written once, so bulk data has to reach the node jobs as HTTP/HTTPS/OSDF
   URLs in their own transfer_input_files instead. One description serves a
   whole stage: VARS gives each node its own values. Node outputs land in the
   workflow's directory, so a downstream node picks one up by name in
   transfer_input_files -- declare it in the producer's transfer_output_files
   so the pre-submit check can see who produces it. Pass dry_run to check a
   workflow without submitting it.
2. get_job on the DAGMan job (job_id="N.0") -- progress by node and by node
   job, for a one-off "how far along is it". DAGMan publishes this into its
   own job ad, so it is the same cheap query as any other get_job; there is no
   separate workflow-status tool.
3. To wait for the whole workflow, register
   watch_jobs(constraint="ClusterId == N", event="done") for the cluster
   submit_dag returned and collect it with check_watches -- do not call
   get_job in a loop.
4. get_job_output on the DAGMan job (job_id="N.0") -- the node jobs' outputs
   come back into the workflow's own spool directory, not to anywhere else,
   and this returns the whole spool, DAGMan's own <dag>.dagman.out log
   included.
5. To read a running workflow's DAGMan log, get_job_output on the manager
   cluster -- its spool is readable while it runs (each call fetches the whole
   spool, so do it when you need it, not on a timer). Not tail_job_output: the
   manager is a scheduler-universe job with no starter to tail.
6. The node jobs are not in the manager's cluster: they carry
   DAGManJobId == N and DAGNodeName. List the running ones with
   query_jobs(constraint="DAGManJobId == N") and the finished ones with
   query_job_archive on the same constraint.

Removing the DAGMan job removes the workflow, including node jobs already
running. A SUBDAG whose .dag file an earlier node generates is supported and
normal: name it in the DAG and let the run produce it. When nodes fail,
DAGMan leaves a rescue DAG in the spool naming what still has to run; fetch it
with get_job_output and submit it as a new workflow to resume.
