#!/usr/bin/env bash
# Run the differential config fuzzer (Go config parser vs HTCondor libcondor_utils).
#
#   hack/config-fuzz.sh [fuzztime]      # default 2m; e.g. hack/config-fuzz.sh 10m
#
# Why not just `go test -fuzz`: on macOS, SIP strips DYLD_LIBRARY_PATH when
# `go test` re-execs its fuzz workers, so the oracle dylib can't be found. We
# compile the test binary once (-c) and run it directly, where DYLD_LIBRARY_PATH
# survives the exec. This also works unchanged on Linux.
#
# CGO flags and the dylib search path come from config-fuzz-env.sh; override the
# HTCondor tree with HTCONDOR_SRC / HTCONDOR_BUILD if needed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
FUZZTIME="${1:-2m}"

# shellcheck disable=SC1091
source "$HERE/config-fuzz-env.sh"

BIN="$(mktemp -t cfgfuzz).test"
trap 'rm -f "$BIN"' EXIT
( cd "$ROOT" && go test -tags libcondor_utils -c -o "$BIN" ./fuzz/config/ )

# Run from the package dir so any failing input is written under
# fuzz/config/testdata/fuzz/... (a reproducer), and keep the evolving corpus in
# a cache dir outside the tree.
CACHE="${TMPDIR:-/tmp}/cfgfuzz-corpus"
mkdir -p "$CACHE"
echo "config-fuzz: fuzzing FuzzConfigParseExpand for $FUZZTIME"
cd "$ROOT/fuzz/config"
exec "$BIN" -test.run='^$' -test.fuzz='FuzzConfigParseExpand$' \
	-test.fuzztime="$FUZZTIME" -test.fuzzcachedir="$CACHE"
