`targetannexname` is written by the annex submit commands HTCONDOR-2015 added. The Go
parser knows `annex_name` and `restrict_to_annex`, so against an oracle that
has them the two sides agree -- and against one that predates them only Go
writes the attribute.

Parsing them is not gated: a submit file naming `annex_name` means the same
thing wherever it goes, and an attribute an older schedd ignores costs the job
nothing. The difference recorded here is the pinned oracle being behind, not
the Go parser being wrong.

Oracle: lacks HTCONDOR-2015
