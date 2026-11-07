`lastsuspensiontime` is one of the zeroed run-time counters condor_submit used to write into
every job ad before reading a submit command. HTCONDOR-3998 stopped
initializing them in the cluster ad, so the C++ side no longer produces it and
Go still does.

Go's `setSubmitTimeDefaults` writes it deliberately: an absent attribute reads
as UNDEFINED, so a constraint that should hold for a job that has not run yet
matches nothing, and arithmetic over it is neither true nor false. Which side
is right is a decision, not a bug, and it is not made here -- this entry only
keeps the difference from failing the nightly while the pinned oracle still
writes the attribute.

Oracle: has HTCONDOR-3998
