#!/usr/bin/env bash
# Source this to build/run the differential config fuzzer against a local
# HTCondor build tree:
#
#   source hack/config-fuzz-env.sh
#   go test -tags libcondor_utils ./fuzz/config/...
#
# See hack/htcondor-oracle-env.sh for HTCONDOR_SRC / HTCONDOR_BUILD.
# shellcheck source=hack/htcondor-oracle-env.sh
. "$(dirname "${BASH_SOURCE[0]}")/htcondor-oracle-env.sh"
htcondor_oracle_env condor_config.cpp
