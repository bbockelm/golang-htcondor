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
# The oracle runs in-process, so a crash in it kills the worker and Go writes
# out whatever input that worker happened to hold -- which, when it was
# minimizing, is not the input that killed it. The oracle journals each input
# before entering C++ and clears it on return, so anything left here names a
# call that did not come back. A fresh directory per run keeps one run's
# leftovers from being read as the next one's.
JOURNAL="$(mktemp -d -t submit-fuzz-journal)"
export SUBMIT_ORACLE_JOURNAL_DIR="$JOURNAL"

report_journal() {
	for f in "$JOURNAL"/*; do
		[ -e "$f" ] || continue
		echo
		echo "submit-fuzz: the oracle did not return from this input:"
		sed 's/^/    /' "$f"
	done
	rm -rf "$JOURNAL"
}

if [ "$(uname -s)" != "Darwin" ]; then
	cd "$ROOT"
	# No -fuzzcachedir: `go test` does not define it (only the test binary
	# does, as -test.fuzzcachedir), so passing it here fails the run before a
	# single input is generated. The corpus lives in $GOCACHE/fuzz by default,
	# which is already outside the checkout.
	GOWORK=off go test -tags libcondor_utils -run='^$' -fuzz="^$TARGET\$" \
		-fuzztime="$FUZZTIME" ./fuzz/submit/
	rc=$?
	report_journal
	exit "$rc"
fi

echo "submit-fuzz: macOS -- running a pre-built binary, so fuzzing is NOT coverage-guided"
BIN="$(mktemp -t subfuzz).test"
trap 'rm -f "$BIN"' EXIT
( cd "$ROOT" && GOWORK=off go test -tags libcondor_utils -c -o "$BIN" ./fuzz/submit/ )
cd "$ROOT/fuzz/submit"
"$BIN" -test.run='^$' -test.fuzz="^$TARGET\$" \
	-test.fuzztime="$FUZZTIME" -test.fuzzcachedir="$CACHE"
rc=$?
report_journal
exit "$rc"
