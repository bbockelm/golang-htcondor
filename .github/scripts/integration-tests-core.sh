#!/usr/bin/env bash
#
# The core module's integration-tagged tests. Separate from the webapi
# script (and job) because the root package alone takes ~6.5 minutes,
# and appending it would make one job the critical path.
#
# See integration-tests-webapi.sh for why these live in files rather
# than inline in the workflow.
set -euo pipefail

GOWORK=off gotestsum -- -tags=integration -timeout=25m \
  . ./sandbox/ ./classadlog/ ./metricsd/
