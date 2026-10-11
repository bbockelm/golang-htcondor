#!/usr/bin/env bash
#
# Run the differential config fuzzer (fuzz/config) against the C++ oracle
# built by build-condor-utils.sh.
#
#   config-fuzz-ci.sh seeds            seed table + committed corpus
#   config-fuzz-ci.sh fuzz <fuzztime>  coverage-guided fuzzing, time-boxed
#
# HTCONDOR_SRC / HTCONDOR_BUILD name the trees; the cgo flags come from
# hack/config-fuzz-env.sh, the same script a developer sources.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=hack/config-fuzz-env.sh
source hack/config-fuzz-env.sh

export GOWORK=off

case "${1:-}" in
seeds)
	log="$(mktemp)"
	go test -count=1 -tags libcondor_utils -v ./fuzz/config/ 2>&1 | tee "$log"

	# Without the oracle linked the tests skip and the package passes, so a
	# green run proves nothing unless TestConfigSeeds actually ran.
	if grep -q -- '--- SKIP: TestConfigSeeds' "$log" ||
		! grep -q -- '--- PASS: TestConfigSeeds' "$log"; then
		echo "::error::TestConfigSeeds did not run against the C++ oracle"
		exit 1
	fi
	;;
fuzz)
	fuzztime="${2:?usage: $0 fuzz <fuzztime>}"
	# A failing input is written under fuzz/config/testdata/fuzz/, which the
	# workflow uploads as an artifact.
	go test -tags libcondor_utils -run '^$' -fuzz 'FuzzConfigParseExpand$' \
		-fuzztime "$fuzztime" ./fuzz/config/
	;;
*)
	echo "usage: $0 seeds | fuzz <fuzztime>" >&2
	exit 2
	;;
esac
