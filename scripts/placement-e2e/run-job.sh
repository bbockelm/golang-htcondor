#!/bin/bash
# Submit a short job with nothing but a placement token, wait for it, and
# check that it ran as the token's account and project.
#
#   run-job.sh TOKEN_FILE WORKDIR ACCOUNT PROJECT
#
# ACCOUNT is the full account the token was minted for (name@UID_DOMAIN).
# Needs CONDOR_CONFIG and PATH from the harness's env file. WORKDIR must
# not exist; the job's submit file, log and output are left there.
#
# The tools authenticate with IDTOKENS only, from a token directory holding
# just this token. The password and system token directories point
# nowhere, so neither FS nor a token minted from the pool key can stand in
# for it.
set -euo pipefail

[ $# -eq 4 ] || { echo "usage: $0 TOKEN_FILE WORKDIR ACCOUNT PROJECT" >&2; exit 2; }
token=$1 workdir=$2 account=$3 project=$4
owner=${account%%@*}

fail() { echo "run-job: $*" >&2; exit 1; }

[ -s "$token" ] || fail "no token at $token"
[ ! -e "$workdir" ] || fail "$workdir exists"
mkdir -p "$workdir/tokens.d"
chmod 700 "$workdir/tokens.d"
cp "$token" "$workdir/tokens.d/placement.token"
chmod 600 "$workdir/tokens.d/placement.token"

export _CONDOR_SEC_CLIENT_AUTHENTICATION_METHODS=IDTOKENS
export _CONDOR_SEC_TOKEN_DIRECTORY=$workdir/tokens.d
export _CONDOR_SEC_TOKEN_SYSTEM_DIRECTORY=/nonexistent
export _CONDOR_SEC_PASSWORD_DIRECTORY=/nonexistent
export _CONDOR_SEC_PASSWORD_FILE=/nonexistent

# Who the schedd says the token is, before anything depends on it.
mapping=$(condor_ping -type SCHEDD -verbose WRITE 2>&1 || true)
echo "$mapping" | grep -E 'Remote Mapping|Authorized|Authentication' || true
echo "$mapping" | grep -q "Remote Mapping: *$account\$" ||
	fail "the schedd did not map the token to $account:"$'\n'"$mapping"

cd "$workdir"
label=$(basename "$workdir")
cat > job.sh <<EOF
#!/bin/sh
echo "placement-e2e $label ran"
EOF
chmod 755 job.sh
# Kept in the queue for a few minutes after it completes, so the wait below
# reads its final state from the schedd, as this token, rather than from
# the history file.
cat > job.sub <<'EOF'
executable = job.sh
output = job.out
error = job.err
log = job.log
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
request_cpus = 1
request_memory = 64M
request_disk = 1M
leave_in_queue = JobStatus == 4 && (time() - CompletionDate) < 600
queue
EOF

out=$(condor_submit -terse job.sub 2>&1) || fail "condor_submit failed: $out"
cluster=$(echo "$out" | sed -n 's/^\([0-9]*\)\.0 - .*/\1/p' | head -1)
[ -n "$cluster" ] || fail "could not read a cluster id from: $out"
echo "run-job: submitted $cluster.0"

deadline=$((SECONDS + 180))
last=""
while :; do
	status=$(condor_q "$cluster.0" -af JobStatus 2>/dev/null || true)
	if [ "$status" != "$last" ]; then
		echo "run-job: $cluster.0 status ${status:-gone}"
		last=$status
	fi
	case $status in
	4) break ;;
	5) fail "$cluster.0 was held: $(condor_q "$cluster.0" -af HoldReason)" ;;
	3) fail "$cluster.0 was removed" ;;
	"") fail "$cluster.0 is no longer in the queue" ;;
	esac
	if ((SECONDS >= deadline)); then
		condor_q "$cluster.0" -better-analyze 2>&1 | tail -30 || true
		fail "$cluster.0 did not complete within 180s (status $status)"
	fi
	sleep 1
done

read -r job_owner job_user job_project exit_code < <(condor_q "$cluster.0" -af Owner User ProjectName ExitCode)
echo "run-job: Owner=$job_owner User=$job_user ProjectName=$job_project ExitCode=$exit_code"
[ "$job_owner" = "$owner" ] || fail "job Owner is $job_owner, expected $owner"
[ "$job_user" = "$account" ] || fail "job User is $job_user, expected $account"
[ "$job_project" = "$project" ] || fail "job ProjectName is $job_project, expected $project"
[ "$exit_code" = 0 ] || fail "job exited $exit_code: $(cat job.err 2>/dev/null)"
grep -qx "placement-e2e $label ran" job.out || fail "unexpected output: $(cat job.out 2>/dev/null)"
echo "run-job: OK $cluster.0 ran as $job_user in $job_project"
