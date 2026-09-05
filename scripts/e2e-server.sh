#!/bin/bash
# Bring up a personal HTCondor and the API server for the browser tests.
#
# Runs inside the dev image (which already carries HTCondor and the Go
# toolchain) from the Browser Tests workflow. Prints E2E-READY on stdout
# once both are answering, which is what the workflow polls for --
# a fixed sleep either wastes time or races the schedd.
#
# Authentication is HTTP_API_USER_HEADER, the same hook the Go
# integration tests use (see setupIntegrationTest). It is trusted from
# any peer here, which is safe only because nothing but the test browser
# can reach this container, and is why the knob is named
# HTTP_API_USER_HEADER_TRUST_ANY.
set -euo pipefail

WORKDIR=${WORKDIR:-/tmp/e2e-condor}
PORT=${E2E_PORT:-8080}
TRUST_DOMAIN=${E2E_TRUST_DOMAIN:-test.htcondor.org}

# lib/condor is where the server opens its application database. It refuses
# to create the parent itself (deliberately -- a daemon silently creating
# directories under a mistyped path is worse), so make it here.
mkdir -p "$WORKDIR"/{log,spool,execute,lock,passwords.d,tokens.d,lib/condor}

cat > "$WORKDIR/condor_config" <<EOF
CONDOR_HOST = \$(FULL_HOSTNAME)
COLLECTOR_HOST = \$(CONDOR_HOST):9618
LOCAL_DIR = $WORKDIR
LOG = $WORKDIR/log
SPOOL = $WORKDIR/spool
EXECUTE = $WORKDIR/execute
LOCK = $WORKDIR/lock
RUN = $WORKDIR/lock
SEC_PASSWORD_DIRECTORY = $WORKDIR/passwords.d
SEC_TOKEN_SYSTEM_DIRECTORY = $WORKDIR/tokens.d
DAEMON_LIST = MASTER, COLLECTOR, SCHEDD, NEGOTIATOR, STARTD
UID_DOMAIN = $TRUST_DOMAIN
TRUST_DOMAIN = $TRUST_DOMAIN
FILESYSTEM_DOMAIN = $TRUST_DOMAIN
USE_SHARED_PORT = False
NETWORK_INTERFACE = 127.0.0.1
ALLOW_WRITE = *
ALLOW_READ = *
ALLOW_DAEMON = *
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_DEFAULT_AUTHENTICATION_METHODS = FS, TOKEN
# A single-slot startd is enough to prove a submitted job is accepted
# and matched; the browser tests do not wait for one to complete.
NUM_CPUS = 1
START = True
EOF

export CONDOR_CONFIG="$WORKDIR/condor_config"

echo "starting condor_master"
condor_master -f &
CONDOR_PID=$!

# Wait for the schedd rather than the master: the master is up long
# before the queue will answer, and a submit against a not-yet-ready
# schedd is the classic source of a flaky first test.
for i in $(seq 1 60); do
  if condor_q >/dev/null 2>&1; then break; fi
  if ! kill -0 "$CONDOR_PID" 2>/dev/null; then
    echo "condor_master exited early"; cat "$WORKDIR"/log/MasterLog 2>/dev/null | tail -40; exit 1
  fi
  sleep 1
done
condor_q >/dev/null 2>&1 || { echo "schedd never answered"; tail -40 "$WORKDIR"/log/SchedLog 2>/dev/null; exit 1; }
echo "schedd is answering"

# The signing key backs the IDTOKENs the server mints for the caller it
# attributes a request to.
KEYDIR="$WORKDIR/passwords.d"
if [ ! -f "$KEYDIR/POOL" ]; then
  condor_store_cred add -c -p "$(head -c 32 /dev/urandom | base64)" >/dev/null 2>&1 || true
fi

echo "building htcondor-api with the UI embedded"
# -buildvcs=false, deliberately. The Go toolchain stamps VCS metadata by
# default and fails the build outright when it cannot read the repo:
#
#   error obtaining VCS status: exit status 128
#
# which happens here for two unrelated reasons -- the bind-mounted workspace
# is owned by a different uid than the builder, and a git worktree's .git is a
# file pointing at a path that does not exist inside the container. Marking
# the directory safe fixes only the first. Nothing here reads the stamp: the
# readiness probe wants a 200 from /api/v1/version, not a particular version.
cd /workspace/webapi
GOWORK=off go build -buildvcs=false -tags embed_frontend -o /tmp/htcondor-api ./cmd/htcondor-api

cd /workspace
# The listen address is a flag, not a config knob -- there is no
# HTTP_API_PORT parameter, so setting one would be silently ignored.
# Without this the server logs to $(LOG)/HttpApiLog and a startup failure is
# invisible: the process prints three lines, redirects the standard logger
# into the structured one, and then dies silently as far as `docker logs` is
# concerned. That cost an hour of debugging; do not remove it.
export _condor_HTTP_API_LOG=stdout
export _condor_HTTP_API_USER_HEADER="X-Test-User"
export _condor_HTTP_API_USER_HEADER_TRUST_ANY="true"
export _condor_TRUST_DOMAIN="$TRUST_DOMAIN"
export _condor_UID_DOMAIN="$TRUST_DOMAIN"
export _condor_SEC_PASSWORD_DIRECTORY="$KEYDIR"

echo "starting htcondor-api on :$PORT"
# Bind all interfaces: the workflow reaches this through a published port, so
# binding loopback inside the container would be unreachable from the runner.
/tmp/htcondor-api -listen ":$PORT" &
API_PID=$!

# /healthz, not /api/v1/*: the API endpoints require authentication, so an
# unauthenticated probe against one answers 401 forever and the wait times
# out against a server that is in fact healthy.
for i in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$API_PID" 2>/dev/null; then echo "htcondor-api exited early"; exit 1; fi
  sleep 1
done
curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 || {
  echo "api never answered /healthz"; exit 1; }

# Prove the authenticated path works too, so a header/trust misconfiguration
# fails here with a clear message instead of as an opaque 401 in every test.
if ! curl -fsS -H "X-Test-User: ${E2E_USER:-e2e@$TRUST_DOMAIN}" \
      "http://127.0.0.1:$PORT/api/v1/whoami" >/dev/null 2>&1; then
  echo "api is up but header auth was refused; check HTTP_API_USER_HEADER settings"
  exit 1
fi

echo "E2E-READY"
wait "$API_PID"
