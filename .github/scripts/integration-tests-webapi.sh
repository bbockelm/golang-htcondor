#!/usr/bin/env bash
#
# The webapi module's integration-tagged tests, run inside the
# golang-htcondor:integration-test image with the repo bind-mounted at
# /workspace.
#
# This lives in a file rather than inline in the workflow because the
# inline form is a shell string inside a double-quoted `bash -c "..."`:
# a comment containing a double quote truncates the script, and the
# truncated script exits 0. That happened -- a comment quoting an error
# message ended the script before the tests, and the job passed in 1m38s
# without running any of them.
set -euo pipefail

# Build the htcondordb the mirror integration test runs against. The
# version comes from .github/tools, an isolated module that exists so
# Dependabot has something to bump -- a pin in a shell script here would
# age silently, and the test would go on passing against a release
# nobody uses.
#
# Built rather than downloaded because htcondordb publishes no container
# or release binary for this platform, and a 'go build' of a pinned
# module version is reproducible in the same way a pinned image tag
# would be.
#
# If this build fails the test SKIPS rather than fails, which would hide
# the gap it exists to close -- so fail the job here instead.
(cd .github/tools && GOWORK=off go build -o /workspace/.gocache/htcondordb github.com/bbockelm/htcondordb/cmd/htcondordb)

# The JupyterLab tunnel helper is a real binary the jupytertunnel
# integration test execs. Without it that test skips, and a skip is
# indistinguishable from a pass in the check list.
#
# Built directly rather than with `make build-jupyter-helper`: that
# target cross-compiles arch-suffixed copies into the embed staging dir,
# which is not the plain webapi/bin/htcondor-jupyter-helper the test
# looks for -- so following the skip message's advice never made the
# test run. One build for this container's own platform is what it
# needs.
#
# -buildvcs=false because the workspace is a bind mount owned by the
# runner, so git inside the container refuses it as dubious ownership
# and the stamp fails with 'error obtaining VCS status: exit status
# 128'. The htcondordb build above passes the flag for the same reason.
(cd webapi && GOWORK=off go build -buildvcs=false \
  -o bin/htcondor-jupyter-helper ./cmd/htcondor-jupyter-helper)

# Every webapi package with integration-tagged tests.
#
# This named ./httpserver/ alone for a long time, so the tag was set for
# 1 of the repo's 8 such packages and the other 7 ran in no job at all
# -- which is how four tests in sandbox/ rotted, and how a
# silently-broken collector stream and an unusable device-code flow went
# unnoticed. The core module's packages run in their own job so the two
# halves do not serialize.
#
# gotestsum comes from the image; GOCACHE/GOMODCACHE are the restored
# caches under the bind-mounted workspace.
cd webapi
GOWORK=off gotestsum -- -tags=integration -timeout=20m \
  ./httpserver/ ./mcpserver/ ./cmd/htcondor-api/ ./jupytertunnel/
