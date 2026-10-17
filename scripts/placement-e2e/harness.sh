#!/bin/bash
# Bring up, or tear down, the pool the placement onboarding browser test
# runs against: a personal HTCondor with a condor_placementd, and
# htcondor-api serving the embedded web UI in front of it with the built-in
# IdP.
#
#   harness.sh up    RUNDIR   start everything; writes RUNDIR/env
#   harness.sh down  RUNDIR   stop everything started by "up"
#   harness.sh logs  RUNDIR   print the tail of every daemon log
#
# Inputs for "up" (environment):
#   HTCONDOR_PREFIX   HTCondor install with bin/ and sbin/ (required)
#   API_BIN           htcondor-api built with -tags embed_frontend (required)
#   E2E_PORT          port htcondor-api listens on (default: a free one)
#
# The pool runs as the invoking user, not root. A non-root schedd runs
# every job as that user, whatever its Owner, so an AP account handed out
# by the placementd needs no Unix account here -- the same situation as an
# AP whose placement accounts all run under one generic OS user.
#
# Everything lives under RUNDIR, which "up" creates and must not exist.
# RUNDIR/env is shell syntax exporting what the tests need: CONDOR_CONFIG,
# PATH, the base URL, the server log the admin password is printed to, and
# the second IdP user's password.
set -euo pipefail

die() { echo "harness: $*" >&2; exit 1; }

# wait_for DESCRIPTION SECONDS COMMAND...: run COMMAND until it succeeds.
wait_for() {
	local what=$1 secs=$2; shift 2
	local deadline=$((SECONDS + secs))
	until "$@" >/dev/null 2>&1; do
		if ((SECONDS >= deadline)); then
			echo "harness: timed out after ${secs}s waiting for $what" >&2
			return 1
		fi
		sleep 1
	done
}

free_port() {
	python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# The UID_DOMAIN accounts are named in, and the TRUST_DOMAIN tokens are
# issued for. Not a resolvable name; nothing looks it up.
DOMAIN=placement-e2e.test

write_condor_config() {
	local rundir=$1 me
	me=$(id -un)
	cat > "$rundir/condor_config" <<EOF
# Personal HTCondor for the placement onboarding test.
RELEASE_DIR = $HTCONDOR_PREFIX
LOCAL_DIR = $rundir/condor
LOG = \$(LOCAL_DIR)/log
SPOOL = \$(LOCAL_DIR)/spool
EXECUTE = \$(LOCAL_DIR)/execute
LOCK = \$(LOCAL_DIR)/lock
RUN = \$(LOCAL_DIR)/run
SEC_PASSWORD_DIRECTORY = \$(LOCAL_DIR)/passwords.d
SEC_TOKEN_SYSTEM_DIRECTORY = \$(LOCAL_DIR)/tokens.d
LOCAL_CONFIG_FILE =
LOCAL_CONFIG_DIR =
MAIL = /bin/true
SENDMAIL = /bin/true

DAEMON_LIST = MASTER COLLECTOR NEGOTIATOR SCHEDD STARTD PLACEMENTD

# A fixed port rather than :0, because htcondor-api reads COLLECTOR_HOST
# and does not consult COLLECTOR_ADDRESS_FILE.
CONDOR_HOST = 127.0.0.1
COLLECTOR_HOST = \$(CONDOR_HOST):$COLLECTOR_PORT
SHARED_PORT_PORT = $COLLECTOR_PORT
NETWORK_INTERFACE = 127.0.0.1
COLLECTOR_ADDRESS_FILE = \$(LOG)/.collector_address
SCHEDD_ADDRESS_FILE = \$(SPOOL)/.schedd_address
PLACEMENTD_ADDRESS_FILE = \$(LOG)/.placementd_address

UID_DOMAIN = $DOMAIN
FILESYSTEM_DOMAIN = $DOMAIN
TRUST_DOMAIN = $DOMAIN

# Short cycles: a job should start within seconds of being submitted.
UPDATE_INTERVAL = 2
NEGOTIATOR_INTERVAL = 2
NEGOTIATOR_MIN_INTERVAL = 2
NEGOTIATOR_CYCLE_DELAY = 2
SCHEDD_INTERVAL = 5
STARTER_UPDATE_INTERVAL = 2
STARTER_INITIAL_UPDATE_INTERVAL = 2
SHADOW_QUEUE_UPDATE_INTERVAL = 2
RUNBENCHMARKS = 0
NUM_CPUS = 2
MEMORY = 2048
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
KILL = FALSE
STARTER_ALLOW_RUNAS_OWNER = False

# Authentication everywhere. The daemons, and htcondor-api, are this
# user over FS; everybody else needs a token.
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS, IDTOKENS
SEC_DEFAULT_ENCRYPTION = REQUIRED
SEC_DEFAULT_INTEGRITY = REQUIRED
SEC_CLIENT_AUTHENTICATION_METHODS = FS, IDTOKENS

# Placement tokens are capability tokens: the JWT carries no subject, and
# the daemons look the token up in TOKENS_DATABASE.
SEC_USE_TOKENS_DATABASE = True
SEC_ACCEPT_CAPABILITY_TOKENS = True

ALLOW_READ = *
ALLOW_WRITE = *
ALLOW_DAEMON = $me@$DOMAIN
ALLOW_NEGOTIATOR = $me@$DOMAIN
# The placementd, which creates the schedd's user records as it mints, and
# htcondor-api, which edits the placementd's database: both this user.
ALLOW_ADMINISTRATOR = $me@$DOMAIN
# An account the placementd never minted for has no user record, and the
# schedd turns it away.
ALLOW_SUBMIT_FROM_KNOWN_USERS_ONLY = True

PLACEMENTD_MAPFILE = $rundir/placementd_mapfile
PLACEMENTD_AUTHORIZATIONS_MAPFILE = $rundir/placementd_authorizations
PLACEMENTD_DEBUG = D_FULLDEBUG D_AUDIT D_SECURITY
SCHEDD_DEBUG = D_FULLDEBUG D_AUDIT D_SECURITY

# htcondor-api
HTTP_API_LISTEN_ADDR = 127.0.0.1:$E2E_PORT
# Otherwise it serves through condor_shared_port and ignores the address
# above.
HTTP_API_USE_SHARED_PORT = False
HTTP_API_BASE_URL = https://localhost:$E2E_PORT
HTTP_API_IDP_ISSUER = https://localhost:$E2E_PORT
HTTP_API_TLS_CERT = $rundir/tls/server.crt
HTTP_API_TLS_KEY = $rundir/tls/server.key
HTTP_API_TLS_CA_CERT = $rundir/tls/ca.crt
HTTP_API_ENABLE_IDP = true
HTTP_API_DB_PATH = $rundir/api/htcondor-api.db
HTTP_API_LOG = \$(LOG)/HttpApiLog
# A sign-in the placementd maps is a full session as that AP account; one
# it does not map gets a placement-only session.
HTTP_API_IDENTITY_MAP = placementd
# The built-in IdP puts its admin user in the "admin" group.
HTTP_API_WEBUI_ADMIN_GROUP = admin
EOF
}

# The map file: the IdP's admin user is mapped to an AP account, which is
# what lets it sign in at all under HTTP_API_IDENTITY_MAP = placementd.
# Its two projects are the ones the onboarding wizard can grant.
write_mapfiles() {
	local rundir=$1
	cat > "$rundir/placementd_mapfile" <<EOF
# identity account authorizations expiry projects
admin apadmin READ,WRITE 0 Staff,Physics
EOF
	cat > "$rundir/placementd_authorizations" <<EOF
READ|Read|normal|View jobs
WRITE|Write|warning|Submit and manage jobs
EOF
}

write_tls() {
	local dir=$1/tls
	mkdir -p "$dir"
	openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=placement-e2e CA" \
		-keyout "$dir/ca.key" -out "$dir/ca.crt" \
		-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
		>/dev/null 2>&1
	openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
		-keyout "$dir/server.key" -out "$dir/server.csr" >/dev/null 2>&1
	printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$dir/ext"
	openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
		-days 2 -extfile "$dir/ext" -out "$dir/server.crt" >/dev/null 2>&1
	chmod 600 "$dir"/*.key
}

pool_has_all_daemons() {
	local types
	types=$(condor_status -any -af MyType 2>/dev/null | sort -u | tr '\n' ' ')
	for t in DaemonMaster Collector Negotiator Scheduler Machine PlacementD; do
		[[ " $types " == *" $t "* ]] || return 1
	done
}

placementd_api_v2() {
	[ "$(condor_status -any -const 'MyType == "PlacementD"' -af PlacementdApiVersion 2>/dev/null)" = 2 ]
}

api_healthy() {
	curl -fsS --cacert "$RUNDIR/tls/ca.crt" "https://localhost:$E2E_PORT/healthz"
}

# /login must hand the browser to the IdP; anything else means SSO is not
# wired and every browser step would fail on an error document instead.
api_login_redirects() {
	[ "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$RUNDIR/tls/ca.crt" "https://localhost:$E2E_PORT/login")" = 302 ]
}

# add_idp_user NAME PASSWORD: an IdP account with no AP account behind it.
#
# The built-in IdP has no user API; it keeps users in the application
# database, bcrypt-hashed, and seeds only "admin" outside demo mode. The
# row is written once the server has created the schema.
add_idp_user() {
	local name=$1 pw=$2 hash
	hash=$(htpasswd -nbB -C 10 "$name" "$pw" | cut -d: -f2-)
	[ -n "$hash" ] || die "htpasswd produced no hash"
	python3 -I - "$RUNDIR/api/htcondor-api.db" "$name" "$hash" <<'EOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1], timeout=30)
db.execute("INSERT INTO idp_users (username, password_hash, state) VALUES (?, ?, 'active')",
           (sys.argv[2], sys.argv[3]))
db.commit()
db.close()
EOF
}

up() {
	[ -n "${HTCONDOR_PREFIX:-}" ] || die "HTCONDOR_PREFIX is not set"
	[ -x "$HTCONDOR_PREFIX/sbin/condor_placementd" ] || die "no condor_placementd under $HTCONDOR_PREFIX"
	[ -x "${API_BIN:-}" ] || die "API_BIN is not an executable"
	command -v htpasswd >/dev/null || die "htpasswd is needed to hash the IdP user's password"
	[ ! -e "$RUNDIR" ] || die "$RUNDIR exists"
	E2E_PORT=${E2E_PORT:-$(free_port)}
	COLLECTOR_PORT=$(free_port)

	mkdir -p "$RUNDIR"/condor/{log,spool,execute,lock,run} "$RUNDIR/api" "$RUNDIR/out"
	chmod 700 "$RUNDIR"
	write_condor_config "$RUNDIR"
	write_mapfiles "$RUNDIR"
	write_tls "$RUNDIR"

	export CONDOR_CONFIG=$RUNDIR/condor_config
	export PATH=$HTCONDOR_PREFIX/bin:$HTCONDOR_PREFIX/sbin:$PATH

	echo "harness: starting condor_master"
	condor_master -f > "$RUNDIR/condor/log/master.out" 2>&1 &
	echo $! > "$RUNDIR/master.pid"
	wait_for "every daemon to advertise" 120 pool_has_all_daemons || { logs; exit 1; }
	wait_for "the placementd to advertise API version 2" 30 placementd_api_v2 || { logs; exit 1; }
	condor_status -any -af MyType Name

	# Started after the placementd is up, so it finds it at startup rather
	# than on a later request.
	echo "harness: starting htcondor-api on port $E2E_PORT"
	(cd "$RUNDIR/api" && exec "$API_BIN") > "$RUNDIR/api/stdout.log" 2>&1 &
	echo $! > "$RUNDIR/api.pid"
	wait_for "htcondor-api to answer /healthz" 120 api_healthy || { logs; exit 1; }
	wait_for "/login to redirect to the IdP" 30 api_login_redirects || { logs; exit 1; }
	grep -q '^Password:' "$RUNDIR/api/stdout.log" || { logs; die "htcondor-api printed no IdP admin password"; }

	local newbie_pw
	newbie_pw=$(python3 -I -c 'import secrets; print(secrets.token_urlsafe(18))')
	add_idp_user newbie "$newbie_pw"

	{
		printf 'export CONDOR_CONFIG=%q\n' "$CONDOR_CONFIG"
		printf 'export PATH=%q\n' "$PATH"
		printf 'export E2E_RUNDIR=%q\n' "$RUNDIR"
		printf 'export E2E_PORT=%q\n' "$E2E_PORT"
		printf 'export PLACEMENT_E2E_BASE_URL=%q\n' "https://localhost:$E2E_PORT"
		printf 'export E2E_SERVER_LOG=%q\n' "$RUNDIR/api/stdout.log"
		printf 'export E2E_CA_CERT=%q\n' "$RUNDIR/tls/ca.crt"
		printf 'export E2E_NEWBIE_PASSWORD=%q\n' "$newbie_pw"
		printf 'export E2E_UID_DOMAIN=%q\n' "$DOMAIN"
	} > "$RUNDIR/env"
	chmod 600 "$RUNDIR/env"
	echo "harness: ready; source $RUNDIR/env"
}

stop_pid() {
	local file=$1 pid
	[ -f "$file" ] || return 0
	pid=$(cat "$file")
	kill -TERM "$pid" 2>/dev/null || return 0
	for _ in $(seq 1 30); do
		kill -0 "$pid" 2>/dev/null || return 0
		sleep 1
	done
	kill -KILL "$pid" 2>/dev/null || true
}

down() {
	stop_pid "$RUNDIR/api.pid"
	stop_pid "$RUNDIR/master.pid"
}

logs() {
	local f
	for f in "$RUNDIR"/condor/log/*Log "$RUNDIR"/condor/log/master.out "$RUNDIR"/api/stdout.log; do
		[ -f "$f" ] || continue
		echo "===== $f"
		tail -n 80 "$f"
	done
}

[ $# -eq 2 ] || die "usage: $0 up|down|logs RUNDIR"
RUNDIR=$2
case $1 in
	up) up ;;
	down) down ;;
	logs) logs ;;
	*) die "unknown command $1" ;;
esac
