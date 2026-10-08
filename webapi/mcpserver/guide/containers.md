# Building container images

build_container builds an Apptainer image from a definition file as a job on
the pool's build machines and publishes the .sif to object storage. Pass the
definition text verbatim; the tool supplies the submit attributes that reach a
build-capable slot, the resource requests, the image-cache handling, and the
transfer.

It returns as soon as the job is submitted, because a real image takes
minutes. Wait with watch_jobs (event="done"), then read get_job_stdout for the
build log.

Pass a verify command whenever you can. It runs inside the freshly built
image, and if it fails the image is NOT published -- which matters because the
destination is a shared path other people read from. A failed build publishes
nothing but still returns its logs, so it stays diagnosable.
