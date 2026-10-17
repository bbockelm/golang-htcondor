#!/bin/bash
# Build and install HTCondor from source for the placement onboarding test.
#
#   build-htcondor.sh SOURCE_DIR PREFIX
#
# Ubuntu 24.04, as GitHub's ubuntu-24.04 runner. Installs the build
# dependencies with apt (sudo when not root), configures with the placementd
# and without the optional security libraries and bindings the test does not
# use, and installs into PREFIX.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 SOURCE_DIR PREFIX" >&2; exit 2; }
src=$(cd "$1" && pwd)
prefix=$2

sudo=""
[ "$(id -u)" = 0 ] || sudo=sudo

# The runtime half of these (libssl, libpcre2, libcurl, libuuid, libsqlite3)
# is on the runner image already; harness.sh needs nothing more at run time.
$sudo apt-get update -q
DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y -q --no-install-recommends \
	build-essential cmake ninja-build git pkg-config \
	libssl-dev libpcre2-dev uuid-dev libcurl4-openssl-dev libsqlite3-dev \
	zlib1g-dev libcrypt-dev libexpat1-dev python3-dev

build=$(mktemp -d "${TMPDIR:-/tmp}/htcondor-build.XXXXXXXX")
cmake -S "$src" -B "$build" -G Ninja \
	-DCMAKE_BUILD_TYPE=RelWithDebInfo \
	-DCMAKE_INSTALL_PREFIX="$prefix" \
	-DWITH_PLACEMENT:BOOL=ON \
	-DWITH_SCITOKENS:BOOL=OFF \
	-DWITH_KRB5:BOOL=OFF \
	-DWITH_MUNGE:BOOL=OFF \
	-DWITH_VOMS:BOOL=OFF \
	-DWITH_LIBVIRT:BOOL=OFF \
	-DWITH_BLAHP:BOOL=OFF \
	-DWITH_PYTHON_BINDINGS_V2:BOOL=OFF \
	-DWITH_PYTHON_BINDINGS_V3:BOOL=OFF \
	-DWANT_PYTHON3_BINDINGS:BOOL=OFF \
	-DENABLE_JAVA_TESTS:BOOL=OFF
ninja -C "$build" -j "$(nproc)" install
rm -rf "$build"

# The test cannot run without these; fail the build, not the test, when
# a configure change quietly drops one.
for f in sbin/condor_master sbin/condor_placementd sbin/condor_schedd sbin/condor_startd \
	bin/condor_submit bin/condor_q bin/condor_ping bin/condor_config_val; do
	[ -x "$prefix/$f" ] || { echo "build-htcondor: $prefix/$f was not installed" >&2; exit 1; }
done
"$prefix/bin/condor_version"
