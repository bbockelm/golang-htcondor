`requestcpus` is one of the default resource requests condor_submit writes for every
job. HTCONDOR-3926 sets `UseDefaultResourceParams = false` for the local and
scheduler universes, where no startd matches and the request means nothing, so
the C++ side omits it there and Go still writes it.

Go applies the defaults in every universe.

Oracle: has HTCONDOR-3926
