#!/usr/bin/env bash
# Source this to build/run the differential config fuzzer against a local
# HTCondor build tree:
#
#   source hack/config-fuzz-env.sh
#   go test -tags libcondor_utils ./fuzz/config/...
#
# Everything is in hack/htcondor-oracle-env.sh, shared with the submit fuzzer;
# this only names the translation unit whose compile flags to copy. See there
# for HTCONDOR_SRC / HTCONDOR_BUILD.
ORACLE_TU=condor_config.cpp ORACLE_LABEL=config-fuzz-env \
	. "$(dirname "${BASH_SOURCE[0]}")/htcondor-oracle-env.sh"
