C++ sets JobLeaseDuration (2400 by default, from JOB_DEFAULT_LEASE_DURATION); Go omits it. A job ad with no lease tells the schedd not to hold the claim across a disconnect.
