#!/usr/bin/env bash
# Run the differential submit-file fuzzer (Go submit parser vs HTCondor's C++
# SubmitHash from libcondor_utils).
#
#   hack/submit-fuzz.sh [fuzztime] [target]
#
# Default 2m on FuzzSubmitAds, which mutates submit TEXT. The other target is
# FuzzSubmitGenerated, which mutates the script a vocabulary-directed generator
# reads, so every input is a submit file built from HTCondor's own keyword
# table (see fuzz/submit/gen.go):
#
#   hack/submit-fuzz.sh 10m
#   hack/submit-fuzz.sh 10m FuzzSubmitGenerated
#
# Why not just `go test -fuzz`: on macOS, SIP strips DYLD_LIBRARY_PATH when
# `go test` re-execs its fuzz workers, so the oracle dylib can't be found. We
# compile the test binary once (-c) and run it directly, where DYLD_LIBRARY_PATH
# survives the exec. This also works unchanged on Linux.
#
# CGO flags and the dylib search path come from submit-fuzz-env.sh; override the
# HTCondor tree with HTCONDOR_SRC / HTCONDOR_BUILD if needed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
FUZZTIME="${1:-2m}"
TARGET="${2:-FuzzSubmitAds}"

# shellcheck disable=SC1091
source "$HERE/submit-fuzz-env.sh"

# Keep the evolving corpus in a cache dir outside the tree. Failing inputs are
# written under fuzz/submit/testdata/fuzz/... as reproducers either way.
CACHE="${TMPDIR:-/tmp}/subfuzz-corpus/$TARGET"
mkdir -p "$CACHE"
echo "submit-fuzz: fuzzing $TARGET for $FUZZTIME"

# `go test -fuzz` builds the binary with coverage instrumentation, which is what
# makes the mutation engine coverage-GUIDED; a binary built with `go test -c`
# has none and fuzzes blind ("may be inefficient"). So use go test directly
# wherever the library path survives its re-exec, and fall back to the
# pre-built binary only on macOS, where SIP strips DYLD_LIBRARY_PATH.
if [ "$(uname -s)" != "Darwin" ]; then
	cd "$ROOT"
	exec env GOWORK=off go test -tags libcondor_utils -run='^$' -fuzz="^$TARGET\$" \
		-fuzztime="$FUZZTIME" -fuzzcachedir="$CACHE" ./fuzz/submit/
fi

echo "submit-fuzz: macOS -- running a pre-built binary, so fuzzing is NOT coverage-guided"
BIN="$(mktemp -t subfuzz).test"
trap 'rm -f "$BIN"' EXIT
( cd "$ROOT" && GOWORK=off go test -tags libcondor_utils -c -o "$BIN" ./fuzz/submit/ )
cd "$ROOT/fuzz/submit"
exec "$BIN" -test.run='^$' -test.fuzz="^$TARGET\$" \
	-test.fuzztime="$FUZZTIME" -test.fuzzcachedir="$CACHE"
