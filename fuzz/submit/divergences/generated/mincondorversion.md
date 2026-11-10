`mincondorversion` is written by the `min_condor_version` / `max_condor_version` submit
commands HTCONDOR-3065 added. The Go parser knows them, so against an oracle
that has them the two sides agree -- and against one that predates them only
Go writes the attribute.

Both also add a Requirements clause comparing TARGET.CondorVersion, which the
oracle this entry is about does not produce either.

Oracle: lacks HTCONDOR-3065
