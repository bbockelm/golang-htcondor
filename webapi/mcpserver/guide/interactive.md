# Interactive sessions and commands in running jobs

A batch job is one job per command, with a queue wait each time. When several
steps need the same machine and the same files -- build then test, explore a
dataset, reproduce a failure by hand -- start an interactive session instead
and run the steps inside it:

1. interactive_session_start -- name the session; it queues like any other
   job.
2. interactive_session_exec -- run a command in it (waits for the job to
   start). Repeat as needed; each call returns exit code, stdout and stderr.
3. interactive_session_stop -- release the slot when finished.

Three things to know:

- The session name is the only handle. Pass it on every call;
  interactive_session_list finds sessions from earlier conversations.
- A session holds its CPUs and memory until stopped, and is reclaimed
  automatically after ~30 minutes with no calls. Stop sessions you are done
  with.
- Each exec is a fresh shell: the working directory resets and environment
  changes do not carry over, so chain dependent steps in one command with
  '&&'. Files written into the sandbox do persist.

## One command in a job that is already running

To run a single command inside a job that is ALREADY running -- including an
ordinary batch job, not just a session -- use exec_in_job. It connects, runs
the command, and disconnects, which makes it the tool for inspecting a running
job (ls the sandbox, check a process, read a file mid-run) without starting a
session or disturbing the job. Use a session instead when several commands
need the same shell.
