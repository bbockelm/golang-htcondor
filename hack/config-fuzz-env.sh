#!/usr/bin/env bash
# Source this to build/run the differential config fuzzer against a local
# HTCondor build tree:
#
#   source hack/config-fuzz-env.sh
#   go test -tags libcondor_utils ./fuzz/config/...
#
# Override the tree locations by exporting HTCONDOR_SRC / HTCONDOR_BUILD first.
# HTCONDOR_SRC   = HTCondor source checkout (headers live under src/)
# HTCONDOR_BUILD = CMake build dir (has compile_commands.json + release_dir/lib)

: "${HTCONDOR_SRC:=$HOME/projects/htcondor}"
: "${HTCONDOR_BUILD:=$HTCONDOR_SRC/build}"

CC_JSON="$HTCONDOR_BUILD/compile_commands.json"
LIBDIR="$HTCONDOR_BUILD/release_dir/lib"

if [ ! -f "$CC_JSON" ]; then
	echo "config-fuzz-env: no compile_commands.json at $CC_JSON" >&2
	echo "  set HTCONDOR_BUILD to your CMake build dir" >&2
	return 1 2>/dev/null || exit 1
fi

# Pull the -I / -D / -std flags the build uses for the config translation unit,
# so we compile the shim with the exact same view of the headers.
CXX_FLAGS=$(python3 - "$CC_JSON" <<'PY'
import json, sys
cc = json.load(open(sys.argv[1]))
for e in cc:
    if e.get("file", "").endswith("condor_config.cpp"):
        cmd = e.get("command") or " ".join(e.get("arguments", []))
        print(" ".join(t for t in cmd.split() if t.startswith(("-I", "-D", "-std"))))
        break
PY
)

# The util library is versioned (libcondor_utils_25_8_0). Find it and derive -l.
# Tolerate a non-matching glob (e.g. no *.so on macOS) so this stays safe when
# sourced under `set -e`/`pipefail` from config-fuzz.sh.
UTIL=$( { ls "$LIBDIR"/libcondor_utils_*.dylib "$LIBDIR"/libcondor_utils_*.so 2>/dev/null || true; } | head -1)
UTIL_L=$(basename "$UTIL" | sed -E 's/^lib([^.]+)\.(dylib|so).*/\1/')

# Embed rpaths for every dir the util library and its transitive deps
# (libSciTokens -> libssl/libcrypto from libressl) live in, so the test binary
# finds them without DYLD_LIBRARY_PATH. This matters on macOS, where SIP strips
# DYLD_LIBRARY_PATH when `go test` re-execs the compiled binary.
RESSL="$HTCONDOR_BUILD/_deps/libressl_libs_darwin-src/lib"
export CGO_CXXFLAGS="$CXX_FLAGS"
export CGO_LDFLAGS="-L$LIBDIR -l$UTIL_L -lclassad -Wl,-rpath,$LIBDIR -Wl,-rpath,$LIBDIR/condor -Wl,-rpath,$RESSL"
# Belt-and-suspenders for direct binary runs / Linux.
export DYLD_LIBRARY_PATH="$LIBDIR:$LIBDIR/condor:$RESSL${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export LD_LIBRARY_PATH="$LIBDIR:$LIBDIR/condor:$RESSL${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

echo "config-fuzz-env: CGO_LDFLAGS=$CGO_LDFLAGS"
echo "config-fuzz-env: $( [ -n "$CXX_FLAGS" ] && echo "CXXFLAGS captured ($(echo "$CXX_FLAGS" | wc -w | tr -d ' ') tokens)" || echo "WARNING: no CXXFLAGS captured" )"
