#!/usr/bin/env bash
# Source this to build/run the differential config fuzzer against a local
# HTCondor build tree:
#
#   source hack/config-fuzz-env.sh
#   go test -tags libcondor_utils ./fuzz/config/...
#
# Override the tree locations by exporting HTCONDOR_SRC / HTCONDOR_BUILD first.
# HTCONDOR_SRC   = HTCondor source checkout (headers live under src/)
# HTCONDOR_BUILD = CMake build dir (has compile_commands.json). The libraries
#                  are taken from release_dir/lib after `ninja install`, or
#                  from src/condor_utils + src/classad in a build dir where
#                  only the condor_utils target was built (as CI does).

: "${HTCONDOR_SRC:=$HOME/projects/htcondor}"
: "${HTCONDOR_BUILD:=$HTCONDOR_SRC/build}"

CC_JSON="$HTCONDOR_BUILD/compile_commands.json"

if [ ! -f "$CC_JSON" ]; then
	echo "config-fuzz-env: no compile_commands.json at $CC_JSON" >&2
	echo "  set HTCONDOR_BUILD to your CMake build dir" >&2
	return 1 2>/dev/null || exit 1
fi

# Pull the -I / -isystem / -D / -std flags the build uses for the config
# translation unit, so we compile the shim with the exact same view of the
# headers. shlex keeps quoted -D values intact, and Go splits CGO_CXXFLAGS
# honouring the same quoting.
CXX_FLAGS=$(python3 - "$CC_JSON" <<'PY'
import json, shlex, sys
cc = json.load(open(sys.argv[1]))
for e in cc:
    if e.get("file", "").endswith("condor_config.cpp"):
        args = e.get("arguments") or shlex.split(e.get("command", ""))
        out = []
        i = 0
        while i < len(args):
            t = args[i]
            if t == "-isystem" and i + 1 < len(args):
                out += [t, args[i + 1]]
                i += 2
                continue
            if t.startswith(("-I", "-D", "-std", "-isystem")):
                out.append(t)
            i += 1
        print(shlex.join(out))
        break
PY
)

# The util library is versioned (libcondor_utils_25_14_1) and a build tree that
# has been through several releases holds more than one; take the newest.
# Sort on the version fields of the basename (portable: no `sort -V`), and
# tolerate a non-matching glob so this stays safe under `set -e`/`pipefail`.
newest_util() {
	{ ls "$1"/libcondor_utils_*.dylib "$1"/libcondor_utils_*.so 2>/dev/null || true; } |
		while read -r f; do echo "$(basename "$f") $f"; done |
		sort -t_ -k3,3n -k4,4n -k5,5n | tail -1 | cut -d' ' -f2-
}

UTILDIR="$HTCONDOR_BUILD/release_dir/lib"
CLASSADDIR="$UTILDIR"
UTIL=$(newest_util "$UTILDIR")
if [ -z "$UTIL" ]; then
	UTILDIR="$HTCONDOR_BUILD/src/condor_utils"
	CLASSADDIR="$HTCONDOR_BUILD/src/classad"
	UTIL=$(newest_util "$UTILDIR")
fi
if [ -z "$UTIL" ]; then
	echo "config-fuzz-env: no libcondor_utils_* under $HTCONDOR_BUILD/release_dir/lib or $HTCONDOR_BUILD/src/condor_utils" >&2
	echo "  build it first: ninja condor_utils (or ninja install)" >&2
	return 1 2>/dev/null || exit 1
fi
UTIL_L=$(basename "$UTIL" | sed -E 's/^lib([^.]+)\.(dylib|so).*/\1/')

# Directories the util library and its transitive deps live in: the util and
# classad dirs, the installed condor/ subdir, and (macOS) libressl, which
# libSciTokens pulls in for libssl/libcrypto.
RESSL="$HTCONDOR_BUILD/_deps/libressl_libs_darwin-src/lib"
LIBPATH="$UTILDIR"
[ "$CLASSADDIR" != "$UTILDIR" ] && LIBPATH="$LIBPATH:$CLASSADDIR"
[ -d "$UTILDIR/condor" ] && LIBPATH="$LIBPATH:$UTILDIR/condor"
[ -d "$RESSL" ] && LIBPATH="$LIBPATH:$RESSL"

# Embed rpaths for every one of those dirs so the test binary finds them
# without DYLD_LIBRARY_PATH, which macOS SIP strips when `go test` re-execs
# the compiled binary. (A dylib whose install name is bare rather than
# @rpath/... is not found through rpath; hack/config-fuzz.sh runs the test
# binary directly so DYLD_LIBRARY_PATH applies.)
RPATHS=""
IFS=: read -r -a _cfz_dirs <<<"$LIBPATH"
for d in "${_cfz_dirs[@]}"; do
	RPATHS="$RPATHS -Wl,-rpath,$d"
done
unset _cfz_dirs

export CGO_CXXFLAGS="$CXX_FLAGS"
LDIRS="-L$UTILDIR"
[ "$CLASSADDIR" != "$UTILDIR" ] && LDIRS="$LDIRS -L$CLASSADDIR"

export CGO_LDFLAGS="$LDIRS -l$UTIL_L -lclassad$RPATHS"
# On Linux the rpath above is not enough: libcondor_utils carries its own
# RUNPATH ($ORIGIN/../lib:...), which the loader uses (not the test binary's)
# to resolve its dependency on libclassad.so.N, and a plain build dir has no
# ../lib. LD_LIBRARY_PATH covers it, and `go test` passes it through on Linux.
# DYLD_LIBRARY_PATH is belt-and-suspenders for direct binary runs on macOS.
export LD_LIBRARY_PATH="$LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export DYLD_LIBRARY_PATH="$LIBPATH${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"

echo "config-fuzz-env: using $UTIL"
echo "config-fuzz-env: CGO_LDFLAGS=$CGO_LDFLAGS"
echo "config-fuzz-env: $( [ -n "$CXX_FLAGS" ] && echo "CXXFLAGS captured ($(echo "$CXX_FLAGS" | wc -w | tr -d ' ') tokens)" || echo "WARNING: no CXXFLAGS captured" )"
