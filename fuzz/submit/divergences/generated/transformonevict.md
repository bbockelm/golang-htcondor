`transformonevict` is written from the local-universe path HTCONDOR-3926 changed: with no
default `RequestMemory` in that universe there is nothing for the transform to
carry, so the C++ side stops emitting it and Go still does.

It travels with requestcpus/requestmemory/requestdisk; fixing those fixes this.

Oracle: has HTCONDOR-3926
