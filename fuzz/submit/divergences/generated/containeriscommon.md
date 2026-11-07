`ContainerIsCommon` is no longer the target attribute of the
`container_is_common` keyword. HTCONDOR-3932 made the keyword specially
parsed, with no attribute of its own, so the C++ side stops writing it under
this name while Go still does.

Oracle: has HTCONDOR-3932-container
