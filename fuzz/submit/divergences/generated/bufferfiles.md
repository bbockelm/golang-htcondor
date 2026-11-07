`bufferfiles` comes from the standard-universe RemoteIO buffering that HTCONDOR-3998
removed, along with the `buffer_size`, `buffer_files` and `buffer_block_size`
keywords that set it. Go still parses those keywords and still writes the
attribute.

The keywords are gone from the C++ submit table, so a submit file that sets
one is now a file Go accepts and HTCondor does not -- which is a parse-time
difference this attribute comparison does not see.

Oracle: has HTCONDOR-3998-remoteio
