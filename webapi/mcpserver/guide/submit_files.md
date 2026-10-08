# Submit files

## A minimal submit file

A submit file that uploads a custom script:

    executable = my_script.sh
    log        = job.log
    output     = output.txt
    error      = error.txt
    request_cpus   = 1
    request_memory = 1024
    request_disk   = 1024
    queue 1

The "queue" line determines how many job processes to create. Upload
my_script.sh with upload_job_input after submit_job.

## transfer_executable

By default, HTCondor transfers the executable to the remote machine. If the
executable is a standard system command (e.g. /bin/bash, /usr/bin/python3,
/usr/bin/env), set transfer_executable = false so HTCondor uses the command
already installed on the execute node and you do not need to upload it:

    executable = /bin/bash
    transfer_executable = false
    arguments  = -c "echo Hello World"
    log        = job.log
    output     = output.txt
    error      = error.txt
    queue 1

When transfer_executable = false AND no transfer_input_files are specified,
the job does not need input spooling and goes directly to Idle.

Leaving it at the default with a system-path executable does not fail at
submit time in HTCondor itself: the executable is spool-copied, the copy does
not exist, and the job holds on file transfer (HoldReasonCode 13,
HoldReasonSubCode 2). submit_job rejects that combination up front.

## $(...) is macro expansion, not shell substitution

The submit parser expands every $(...) itself, so the shell never sees it; an
undefined name expands to an empty string and the job runs with a corrupted
command line:

    arguments = -c "echo HOST:$(hostname)"   # bash receives: -c "echo HOST:"

$(Cluster), $(Process), $(ProcId), $(ItemIndex), $(Step), $(Row) and
submit-file macros are the intended use. To run shell commands, write a
script, name it as the executable, and upload it with upload_job_input.
submit_job warns when a $(...) name is undefined, but the job is already
submitted by then.

## The submitting environment is not the job's

getenv is silently ignored here: it would capture the environment of this
server, not yours. Set what the job needs with `environment = "NAME=value OTHER=value"`
(the quoted form, space separated).

## Looking things up

doc_submit_syntax finds any submit command in the condor_submit manual page;
doc_job_attributes explains the job attribute a command turns into.
