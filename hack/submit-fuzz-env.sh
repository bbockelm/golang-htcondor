#!/usr/bin/env bash
# Source this to build/run the differential submit-file fuzzer against a local
# HTCondor build tree:
#
#   source hack/submit-fuzz-env.sh
#   go test -tags libcondor_utils ./fuzz/submit/...
#
# Everything is in hack/htcondor-oracle-env.sh, shared with the config fuzzer;
# this only names the translation unit whose compile flags to copy. See there
# for HTCONDOR_SRC / HTCONDOR_BUILD.
ORACLE_TU=submit_utils.cpp ORACLE_LABEL=submit-fuzz-env \
	. "$(dirname "${BASH_SOURCE[0]}")/htcondor-oracle-env.sh"
