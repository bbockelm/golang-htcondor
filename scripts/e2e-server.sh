#!/bin/bash
# Bring up the API server for the browser tests, in demo mode.
#
# `-demo` is a shipped mode, not test scaffolding. It starts a personal
# HTCondor, enables the built-in IDP, generates a CA and server cert so
# the session cookie's Secure flag is honoured, and wires the server up
# as an OAuth2 client of its own IDP. That last part is what lets the
# browser tests log in for real.
#
# The alternative -- the user-header auth this script used to configure
# -- cannot drive the Web UI at all. GET /api/v1/auth/me resolves the
# browser session cookie ONLY, by deliberate design; it does not consult
# the header. So the SPA saw itself as logged out, redirected to /login,
# and every page-level assertion in the full suite was made against
#
#   {"error":"Unauthorized","message":"Authentication required but no
#    OAuth2 provider configured","code":401}
#
# which "body is visible" and "no page errors" both happily accept.
#
# Prints E2E-READY on stdout once the server answers, and the admin
# credentials line demo mode emits, which the tests scrape to log in.
set -euo pipefail

PORT=${E2E_PORT:-8080}

echo "building htcondor-api"
# -buildvcs=false: the workspace is bind-mounted and may be a git
# worktree, whose .git is a file pointing outside the container. The Go
# toolchain fails the build outright when it cannot read VCS state, and
# nothing here reads the stamp.
cd /workspace/webapi
GOWORK=off go build -buildvcs=false -tags embed_frontend -o /tmp/htcondor-api ./cmd/htcondor-api

# Run from /tmp: demo mode creates its own state directory and does not
# want to write into the bind-mounted workspace.
cd /tmp
echo "starting htcondor-api -demo on :$PORT"
/tmp/htcondor-api -demo -listen ":$PORT" &
API_PID=$!

# Demo mode serves HTTPS with the cert it just generated, so probe with
# -k. /healthz needs no authentication; an API endpoint would answer 401
# forever and time out against a server that is in fact healthy.
for i in $(seq 1 120); do
  if curl -fsSk "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$API_PID" 2>/dev/null; then echo "htcondor-api exited early"; exit 1; fi
  sleep 2
done
curl -fsSk "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 || {
  echo "api never answered /healthz"; exit 1; }

# Prove the login flow is wired before the tests depend on it: /login
# must redirect into the IDP rather than answering 401. Failing here
# names the problem, instead of leaving every browser test to fail on a
# JSON error document.
code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$PORT/login")
if [ "$code" != "302" ]; then
  echo "login did not redirect (got $code); the IDP is not wired up"
  exit 1
fi

echo "E2E-READY"
wait "$API_PID"
