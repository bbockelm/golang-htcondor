#!/usr/bin/env bash
#
# The core module's integration-tagged tests. Separate from the webapi
# script (and job) because the root package alone takes ~6.5 minutes,
# and appending it would make one job the critical path.
#
# See integration-tests-webapi.sh for why these live in files rather
# than inline in the workflow.
set -euo pipefail

PACKAGES=(. ./sandbox/ ./classadlog/ ./metricsd/)

# The same drift check the webapi script does, for the same reason: a
# package whose tests are all behind the integration tag runs nowhere if it
# is missing from this list, and nothing else notices.
#
# webapi is a module of its own with its own script and job, so it is
# excluded here rather than reported as missing from this one.
missing=()
while read -r dir; do
  found=no
  for pkg in "${PACKAGES[@]}"; do
    [ "${pkg%/}" = "." ] && pkg="."
    [ "${pkg%/}" = "./${dir#./}" ] || [ "$pkg" = "$dir" ] && found=yes && break
  done
  [ "$found" = no ] && missing+=("$dir")
done < <(grep -rl '^//go:build integration' --include='*_test.go' --exclude-dir=webapi . | xargs -n1 dirname | sort -u)

if [ ${#missing[@]} -gt 0 ]; then
  echo "These core-module packages have integration-tagged tests but are not in PACKAGES:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo "Add them above, or they run in no job at all." >&2
  exit 1
fi

GOWORK=off gotestsum -- -tags=integration -timeout=25m "${PACKAGES[@]}"
