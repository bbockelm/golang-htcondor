#!/usr/bin/env bash
# Source this to build/run the differential submit-file fuzzer against a local
# HTCondor build tree:
#
#   source hack/submit-fuzz-env.sh
#   go test -tags libcondor_utils ./fuzz/submit/...
#
# See hack/htcondor-oracle-env.sh for HTCONDOR_SRC / HTCONDOR_BUILD.
# shellcheck source=hack/htcondor-oracle-env.sh
. "$(dirname "${BASH_SOURCE[0]}")/htcondor-oracle-env.sh"
htcondor_oracle_env submit_utils.cpp
