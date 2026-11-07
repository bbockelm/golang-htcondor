`ExitStatus` was one of the zeroed run-time attributes in the base job ad.
HTCONDOR-4020 removed its assignment, so the C++ side no longer produces it
and Go still does.

It is the same decision as the counters HTCONDOR-3998 removed, made one
release earlier and in its own commit, so it gets its own trait: an oracle
can have one change and not the other.

Oracle: has HTCONDOR-4020
