#!/usr/bin/env bash
#
# The one core-module integration test that needs root: binding a port
# below 1024 after condor_master has dropped the daemon to the condor
# account.
#
# It is not part of integration-tests-core.sh because that job does not
# run as root, where this test skips. It is not the whole core suite
# either: run as root, 13 of those tests fail, having been written for an
# ordinary user submitting jobs the schedd then accepts.
#
# In a file rather than inline for the reason given in
# integration-tests-webapi.sh: a comment containing a double quote
# truncates an inline `bash -c "..."`, and the truncated script exits 0 --
# a job that passes having run nothing.
set -euo pipefail

GOWORK=off gotestsum -- \
  -tags=integration -timeout=10m \
  -run 'TestHTCondorAPIBindsPrivilegedPortUnderMaster$' \
  .
