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

# Everything this script writes goes in a private directory, not a fixed
# /tmp name. Two harnesses on one host would otherwise fight over the
# same binary and log; on a shared host a predictable name is also
# somewhere another user can squat or point a symlink. mktemp -d is
# 0700 and unguessable.
RUNDIR=$(mktemp -d "${TMPDIR:-/tmp}/htcondor-e2e.XXXXXXXX")
API_BIN="$RUNDIR/htcondor-api"
echo "E2E-RUNDIR $RUNDIR"

echo "building htcondor-api"
# -buildvcs=false: the workspace is bind-mounted and may be a git
# worktree, whose .git is a file pointing outside the container. The Go
# toolchain fails the build outright when it cannot read VCS state, and
# nothing here reads the stamp.
cd /workspace/webapi
GOWORK=off go build -buildvcs=false -tags embed_frontend -o "$API_BIN" ./cmd/htcondor-api

# Run from the private run directory: demo mode creates its own state
# directory beneath the working directory and must not write into the
# bind-mounted workspace.
cd "$RUNDIR"
# A site app, so the browser tests can exercise the whole path a lab's
# app takes: the group gate, the mount-point injection, the switcher at
# /site/ and the link in the sidebar.
#
# Deployed as a DIRECTORY bundle rather than a zip because the container
# is not guaranteed to have a zip tool, and nothing here needs one: the
# zip-specific half (decompress-to-unlinked-file, seekable entries) is
# covered by Go tests that build archives in process. What the browser
# needs to reach is the same either way.
#
# groups: ["*"] -- every authenticated user -- because demo mode's two
# accounts have different groups ("admin" and none) and this app is not
# what the authorization tests are for.
SITE_APPS_DIR="$RUNDIR/webapps"
mkdir -p "$SITE_APPS_DIR/e2eapp/web/assets"
cat > "$SITE_APPS_DIR/e2eapp/app.yaml" <<'YAML'
name: E2E Example App
description: A site app deployed by the browser-test harness
YAML
cat > "$SITE_APPS_DIR/e2eapp.yaml" <<'YAML'
groups: ["*"]
home: false
YAML
cat > "$SITE_APPS_DIR/e2eapp/web/index.html" <<'HTML'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>E2E Example App</title></head>
<body><h1 data-testid="app-heading">E2E Example App</h1>
<p data-testid="app-base"></p>
<script src="./assets/app.js"></script></body></html>
HTML
cat > "$SITE_APPS_DIR/e2eapp/web/assets/app.js" <<'JS'
// Proves the bundle learned where it is mounted, and that a nested
// asset resolves against the injected <base> rather than the site root.
document.querySelector('[data-testid="app-base"]').textContent =
  (window.__HTCONDOR_APP__ && window.__HTCONDOR_APP__.base) || 'MISSING';
JS
# A second app, so the overlay bar has somewhere to point. With only
# one app and no app-only mode the shell deliberately renders nothing,
# which would make "the bar is absent" indistinguishable from "the bar
# is broken".
mkdir -p "$SITE_APPS_DIR/e2eother/web"
cat > "$SITE_APPS_DIR/e2eother/app.yaml" <<'YAML'
name: E2E Other App
description: A second app, so the overlay has a destination
YAML
cat > "$SITE_APPS_DIR/e2eother.yaml" <<'YAML'
groups: ["*"]
YAML
cat > "$SITE_APPS_DIR/e2eother/web/index.html" <<'HTML'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>E2E Other App</title></head>
<body><h1 data-testid="other-heading">E2E Other App</h1></body></html>
HTML

# A third that declines the overlay, so the opt-out is covered by
# something other than reading the code.
mkdir -p "$SITE_APPS_DIR/e2ebare/web"
cat > "$SITE_APPS_DIR/e2ebare/app.yaml" <<'YAML'
name: E2E Bare App
YAML
cat > "$SITE_APPS_DIR/e2ebare.yaml" <<'YAML'
groups: ["*"]
YAML
cat > "$SITE_APPS_DIR/e2ebare/web/index.html" <<'HTML'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="htcondor-shell" content="none">
<title>E2E Bare App</title></head>
<body><h1 data-testid="bare-heading">E2E Bare App</h1></body></html>
HTML

export _CONDOR_HTTP_API_SITE_APPS_DIR="$SITE_APPS_DIR"
# Short, so a test can redeploy a bundle and see it without waiting a
# minute. Production defaults to a minute.
export _CONDOR_HTTP_API_SITE_APPS_RELOAD_INTERVAL="2s"
echo "site apps directory: $SITE_APPS_DIR"

echo "starting htcondor-api -demo on :$PORT"
"$API_BIN" -demo -listen ":$PORT" &
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
