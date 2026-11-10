## Where the job's output goes

Set `output`, `error` and `log` in every submit description you write, each to
a real file name:

    output = run-$(ProcId).out
    error  = run-$(ProcId).err
    log    = run.log

None of the three has a useful default. Omitting one DISCARDS that stream, and
so does naming /dev/null — never write /dev/null for any of them. Set them even
when the person says they do not care about the output: the first question
asked about a job that misbehaved is what it printed, and once it was thrown
away the only way to answer is to run the job again.

`output` and `error` are per process. When the submission produces more than one
job, put `$(ProcId)` in both names, or every process writes over the same two
files and only the last one survives.

`log` is per submission, and one file shared by all of its processes is correct
— each event records which job it belongs to. The log is the only source of a
job's event timeline (submitted, executed, evicted, held, terminated), so a job
submitted without one cannot answer "when did it start", "how many times was it
evicted" or "why did it stop"; reading it back fails outright with "Job has no
UserLog configured".
