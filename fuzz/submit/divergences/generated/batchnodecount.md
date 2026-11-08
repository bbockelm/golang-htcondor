`batchnodecount` is written by the batch cpu/node submit commands HTCONDOR-4053 added:
batch_cpu_count, batch_cpus_per_node, batch_node_count and batch_whole_nodes,
which the gridmanager passes to the remote batch system.

The Go parser knows them, so against an oracle that has them the two sides
agree -- and against one that predates them only Go writes the attribute.
Parsing them is not gated: a submit file naming one means the same thing
wherever it goes, and an attribute an older schedd ignores costs the job
nothing.

Oracle: lacks HTCONDOR-4053
