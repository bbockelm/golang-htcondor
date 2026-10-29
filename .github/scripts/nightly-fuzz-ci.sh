#!/usr/bin/env bash
#
# Run one differential fuzz target against the C++ oracle built by
# build-condor-utils.sh. Used by the nightly workflow, which builds the
# oracle from HTCondor's main branch rather than a pinned release.
#
#   nightly-fuzz-ci.sh <config|submit> <fuzztime>
#
# Exit status:
#   0   seeds and fuzzing passed
#   1   seeds or fuzzing failed, or the oracle was not linked in
#   2   usage error
#   78  the target is not in this tree (see below); nothing was run
#
# The submit fuzzer lands in its own change. Until it is on main this
# script reports 78 for it so the nightly run still covers the config
# fuzzer instead of failing on a missing package.
#
# Environment:
#   FUZZ_LOG_DIR  where to write nightly-fuzz-<target>.log (default: repo root)
#   RUNNER_TEMP   parent of the fuzz corpus cache dir (default: $TMPDIR)
set -uo pipefail

target="${1:-}"
fuzztime="${2:-}"

case "$target" in
config | submit) ;;
*)
	echo "usage: $0 <config|submit> <fuzztime>" >&2
	exit 2
	;;
esac
if [ -z "$fuzztime" ]; then
	echo "usage: $0 <config|submit> <fuzztime>" >&2
	exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 2

pkg="fuzz/$target"
envscript="hack/$target-fuzz-env.sh"

if [ ! -d "$pkg" ] || [ ! -f "$envscript" ]; then
	echo "::notice::$pkg or $envscript is not in this tree; skipping the $target fuzz target"
	exit 78
fi

# go test -fuzz takes one target, so a package with two Fuzz functions
# needs this script taught which one. Reading the name out of the package
# keeps the nightly run working when a target is renamed.
fuzzname="$(sed -nE 's/^func (Fuzz[A-Za-z0-9_]*)\(.*/\1/p' "$pkg"/*_test.go | sort -u)"
if [ -z "$fuzzname" ]; then
	echo "::error::no Fuzz function found in $pkg" >&2
	exit 1
fi
if [ "$(printf '%s\n' "$fuzzname" | wc -l)" -ne 1 ]; then
	echo "::error::$pkg has more than one Fuzz function: $(echo "$fuzzname" | tr '\n' ' ')" >&2
	exit 1
fi

export GOWORK=off

log="${FUZZ_LOG_DIR:-$ROOT}/nightly-fuzz-$target.log"
mkdir -p "$(dirname "$log")"
: >"$log"

# The cgo flags for the oracle, the same way a developer sets them up.
# shellcheck disable=SC1090
if ! source "$envscript"; then
	echo "::error::$envscript failed; the $target oracle is not usable" >&2
	exit 1
fi

# Keep the evolving corpus out of the checkout. A failing input is still
# written under $pkg/testdata/fuzz/ as a committable reproducer.
corpus="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/nightly-fuzz-corpus-$target"
mkdir -p "$corpus"

echo "nightly-fuzz: $target seeds"
go test -count=1 -tags libcondor_utils -v "./$pkg/" 2>&1 | tee -a "$log"
rc="${PIPESTATUS[0]}"

# Without the oracle linked the differential tests skip and the package
# passes, so a green run proves nothing. Both fuzz packages word the skip
# the same way.
if grep -q 'needs the C++ oracle' "$log"; then
	echo "::error::the $target differential tests skipped: the C++ oracle was not linked in" | tee -a "$log"
	exit 1
fi
if [ "$rc" -ne 0 ]; then
	exit 1
fi

echo "nightly-fuzz: $target fuzzing $fuzzname for $fuzztime"
go test -tags libcondor_utils -run '^$' -fuzz "^$fuzzname\$" \
	-fuzztime "$fuzztime" -fuzzcachedir "$corpus" "./$pkg/" 2>&1 | tee -a "$log"
rc="${PIPESTATUS[0]}"
[ "$rc" -eq 0 ] || exit 1
