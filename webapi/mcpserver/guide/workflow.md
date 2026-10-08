# Workflow: submit, wait, collect

HTCondor is a high-throughput computing (HTC) workload management system.
Users submit batch jobs that are matched to available compute resources and
executed remotely. An "access point" (AP) is the server through which users
submit and manage their jobs.

## The usual sequence

1. submit_job -- submit a job with an HTCondor submit-file description.
2. upload_job_input -- upload the executable and small input files (< 100 KB
   total recommended). For larger inputs, use HTTP/HTTPS/OSDF URLs in
   transfer_input_files, or create_input_upload_url.
3. watch_jobs / check_watches -- wait for the job to finish (or be held)
   without polling. A watch fires even if the event already happened. Call
   watch_jobs once to register the question; then call check_watches for the
   answer. check_watches is the one that can wait for you (pass wait_seconds)
   and the one to call again until it answers. Use query_jobs for a one-off
   status snapshot.
4. tail_job_output -- while the job RUNS, read the end of its stdout/stderr
   straight from the execute node. This is how you watch progress or find out
   why a job is stuck, instead of waiting for it to finish. Pass the offsets it
   returns back on the next call to get only what is new, and poll no more
   than every 5 seconds.
5. get_job_stdout / get_job_stderr -- retrieve output after the job FINISHES.
   These read the transferred files, so they are the right tools once a job is
   done and the wrong ones while it runs; tail_job_output is the reverse.
6. get_job_output -- retrieve any other output files.

## Moving data that is too big for the conversation

create_input_upload_url -- for input too big to pass through this
conversation, or already sitting on the machine you are running on. It returns
short-lived URLs to PUT a tar of the files to, so the bytes go straight to the
access point instead of through your context. Run the upload with a shell
command (`tar cf - ... | curl -T - '<url>'`); do not read the files in to do
it. The URLs need no credentials and can be handed to whoever holds the data.
Input spools per proc, so a bare cluster id returns one URL per proc and each
takes its own tar.

create_output_download_url -- the mirror of create_input_upload_url, for
results too big to pass through this conversation. It returns a short-lived
URL that GETs a tar of the job's sandbox, so the bytes go straight from the
access point to wherever you want them. Reach for it the moment get_job_output
truncates or does not fit, and fetch it with a shell command
(`curl -fsSL '<url>' | tar xv`) rather than reading it in. The URL needs no
credentials, so it can also just be handed to the person to click. Sandboxes
are per proc, and they exist only while the job is in the queue.

## Waiting outside this conversation

create_watch_url -- to have something OUTSIDE this conversation do the
waiting: it returns a URL that blocks until one watch fires, for an agent
framework or poller to hold. check_watches waits inside your turn; that URL
waits while you are not running.
