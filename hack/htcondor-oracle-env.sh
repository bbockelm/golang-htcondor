#!/usr/bin/env bash
# Shared environment for the differential fuzz oracles that link HTCondor's
# C++ libcondor_utils (fuzz/config, fuzz/submit). Do not source this directly;
# source one of the per-target wrappers, which pass the translation unit whose
# compile flags should be copied:
#
#   source hack/config-fuzz-env.sh   # -> condor_config.cpp
#   source hack/submit-fuzz-env.sh   # -> submit_utils.cpp
#
# Override the tree locations by exporting HTCONDOR_SRC / HTCONDOR_BUILD first.
# HTCONDOR_SRC   = HTCondor source checkout (headers live under src/)
# HTCONDOR_BUILD = CMake build dir (has compile_commands.json + release_dir/lib)

# htcondor_oracle_env <translation-unit-suffix>
htcondor_oracle_env() {
	local tu="$1"
	if [ -z "$tu" ]; then
		echo "htcondor-oracle-env: internal error: no translation unit given" >&2
		return 1
	fi

	: "${HTCONDOR_SRC:=$HOME/projects/htcondor}"
	: "${HTCONDOR_BUILD:=$HTCONDOR_SRC/build}"

	local cc_json="$HTCONDOR_BUILD/compile_commands.json"
	local libdir="$HTCONDOR_BUILD/release_dir/lib"

	if [ ! -f "$cc_json" ]; then
		echo "htcondor-oracle-env: no compile_commands.json at $cc_json" >&2
		echo "  set HTCONDOR_BUILD to your CMake build dir" >&2
		return 1
	fi

	# Copy the -I / -D / -std flags the build uses for this translation unit, so
	# the shim compiles with the exact same view of the headers. Split the
	# recorded command with shlex, not on whitespace: HTCondor passes
	# -DPRE_RELEASE_STR="\" PRE-RELEASE-UWCS\"", which contains a space inside
	# quotes and comes back mangled from a naive split.
	local cxx_flags
	cxx_flags=$(python3 - "$cc_json" "$tu" <<'PY'
import json, shlex, sys
cc_json, tu = sys.argv[1], sys.argv[2]
for e in json.load(open(cc_json)):
    if e.get("file", "").endswith(tu):
        toks = e.get("arguments") or shlex.split(e.get("command", ""))
        print(shlex.join(t for t in toks if t.startswith(("-I", "-D", "-std"))))
        break
PY
	)
	if [ -z "$cxx_flags" ]; then
		echo "htcondor-oracle-env: no compile entry for $tu in $cc_json" >&2
		return 1
	fi

	# The util library is versioned (libcondor_utils_26_2_0). A build directory
	# accumulates every version ever installed into release_dir, so pick the
	# HIGHEST version rather than the first name alphabetically -- `ls | head -1`
	# selects libcondor_utils_25_12_0 over _25_8_0 and silently fuzzes against a
	# stale oracle. Tolerate a non-matching glob (no *.so on macOS) so this stays
	# safe when sourced under `set -e`/`pipefail`.
	local util util_l
	util=$( { ls "$libdir"/libcondor_utils_*.dylib "$libdir"/libcondor_utils_*.so 2>/dev/null || true; } \
		| sed -E 's/.*libcondor_utils_([0-9]+)_([0-9]+)_([0-9]+)\..*/\1.\2.\3 &/' \
		| sort -t. -k1,1n -k2,2n -k3,3n | tail -1 | cut -d' ' -f2-)
	if [ -z "$util" ]; then
		echo "htcondor-oracle-env: no libcondor_utils_* in $libdir" >&2
		return 1
	fi
	util_l=$(basename "$util" | sed -E 's/^lib([^.]+)\.(dylib|so).*/\1/')

	# Embed rpaths for every dir the util library and its transitive deps
	# (libSciTokens -> libssl/libcrypto from libressl) live in.
	local ressl="$HTCONDOR_BUILD/_deps/libressl_libs_darwin-src/lib"
	export CGO_CXXFLAGS="$cxx_flags"
	export CGO_LDFLAGS="-L$libdir -l$util_l -lclassad -Wl,-rpath,$libdir -Wl,-rpath,$libdir/condor -Wl,-rpath,$ressl"
	# libcondor_utils' install name carries no @rpath prefix, so the loader does
	# not use those rpaths; the library path below is what actually finds it.
	export DYLD_LIBRARY_PATH="$libdir:$libdir/condor:$ressl${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
	export LD_LIBRARY_PATH="$libdir:$libdir/condor:$ressl${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

	echo "htcondor-oracle-env: oracle library $(basename "$util")"
	echo "htcondor-oracle-env: CXXFLAGS captured ($(echo "$cxx_flags" | wc -w | tr -d ' ') tokens) from $tu"
}
