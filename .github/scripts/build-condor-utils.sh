#!/usr/bin/env bash
#
# Build HTCondor's libcondor_utils (and libclassad) from source for the
# differential config fuzzer's C++ oracle (fuzz/config/oracle).
#
# The oracle includes HTCondor's internal headers: condor_common.h pulls
# in the cmake-generated config.h, and condor_config.h ships in no
# package. So the oracle needs a configured source tree, not an installed
# HTCondor -- only the condor_utils target is built.
#
# Environment:
#   HTCONDOR_REF    git ref to clone (required unless HTCONDOR_SRC exists)
#   HTCONDOR_SRC    source checkout; cloned here if missing
#   HTCONDOR_BUILD  CMake build dir; configured here if not yet configured
#   INSTALL_DEPS=1  apt-get the build dependencies (Ubuntu 24.04) first
#
# Uses ccache when it is on PATH. Afterwards, hack/config-fuzz-env.sh with
# the same HTCONDOR_SRC / HTCONDOR_BUILD sets up the cgo flags.
set -euo pipefail

: "${HTCONDOR_SRC:?set HTCONDOR_SRC}"
: "${HTCONDOR_BUILD:?set HTCONDOR_BUILD}"

if [ "${INSTALL_DEPS:-0}" = 1 ]; then
	sudo apt-get update -q
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
		ca-certificates git cmake ninja-build g++ make pkg-config ccache \
		python3 python3-dev \
		libcurl4-openssl-dev libkrb5-dev libldap-dev libmunge-dev libpam0g-dev \
		libpcre2-dev libscitokens-dev libssl-dev libsqlite3-dev libsystemd-dev \
		libx11-dev libxss-dev uuid-dev zlib1g-dev libcrypt-dev libselinux1-dev \
		libdbus-1-dev
fi

if [ ! -d "$HTCONDOR_SRC/src/condor_utils" ]; then
	: "${HTCONDOR_REF:?set HTCONDOR_REF (or point HTCONDOR_SRC at a checkout)}"
	git clone --depth 1 --branch "$HTCONDOR_REF" \
		https://github.com/htcondor/htcondor.git "$HTCONDOR_SRC"
fi

launcher=()
if command -v ccache >/dev/null; then
	launcher=(-DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache)
	# Hash paths relative to the directory holding the source and build
	# trees, and the compiler by content rather than mtime, so a cache
	# restored onto a fresh runner still hits.
	export CCACHE_BASEDIR="${CCACHE_BASEDIR:-$(dirname "$HTCONDOR_SRC")}"
	export CCACHE_COMPILERCHECK="${CCACHE_COMPILERCHECK:-content}"
	export CCACHE_MAXSIZE="${CCACHE_MAXSIZE:-1G}"
	ccache --zero-stats >/dev/null
fi

if [ ! -f "$HTCONDOR_BUILD/build.ninja" ]; then
	# PROPER uses the system libraries rather than downloading externals.
	# Only condor_utils is built, so everything optional is off.
	cmake -S "$HTCONDOR_SRC" -B "$HTCONDOR_BUILD" -GNinja \
		-DPROPER:BOOL=ON \
		-DWITH_VOMS:BOOL=false \
		-DWITH_LIBVIRT:BOOL=false \
		-DWITH_PYTHON_BINDINGS:BOOL=OFF \
		-DBUILD_TESTING:BOOL=OFF \
		-DWITH_BLAHP:BOOL=OFF \
		-DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON \
		"${launcher[@]}"
fi

ninja -C "$HTCONDOR_BUILD" -j "$(nproc)" condor_utils

if command -v ccache >/dev/null; then
	ccache --show-stats
fi
