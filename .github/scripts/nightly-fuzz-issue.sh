#!/usr/bin/env bash
#
# Report a failed nightly differential fuzz run as a GitHub issue.
#
# Deduplication: one open issue carries the label named by FUZZ_LABEL
# ("nightly-fuzz"). If such an issue is open, this script comments on the
# most recently created one; otherwise it opens a new one. So a failure that persists
# night after night grows one thread instead of a pile of issues.
#
# When the failure clears nothing happens: the issue stays open and a
# human closes it. Closing it while the failure persists means the next
# run opens a fresh issue.
#
# Every body carries FUZZ_MARKER as an HTML comment, so these issues are
# findable by body search even if the label is removed.
#
# Environment:
#   GH_TOKEN         token with issues: write
#   GH_REPO          owner/name
#   FAILED_TARGETS   space-separated: build, config, submit
#   HTCONDOR_REF     the ref the oracle was built from
#   HTCONDOR_SHA     the commit that ref resolved to
#   RUN_URL          link to the workflow run
#   FUZZ_LOG_DIR     directory holding differential-fuzz-<target>.log
#   FUZZ_LABEL       dedup label (default: nightly-fuzz)
set -euo pipefail

: "${GH_TOKEN:?set GH_TOKEN}"
: "${GH_REPO:?set GH_REPO}"
: "${FAILED_TARGETS:?set FAILED_TARGETS}"

label="${FUZZ_LABEL:-nightly-fuzz}"
marker="<!-- nightly-differential-fuzz -->"
logdir="${FUZZ_LOG_DIR:-.}"
ref="${HTCONDOR_REF:-unknown}"
sha="${HTCONDOR_SHA:-unknown}"
run_url="${RUN_URL:-unknown}"

body="$(mktemp)"
trap 'rm -f "$body"' EXIT

{
	echo "$marker"
	echo
	echo "The nightly differential fuzz run failed."
	echo
	echo "| | |"
	echo "|---|---|"
	echo "| Failing targets | \`$FAILED_TARGETS\` |"
	echo "| HTCondor ref | \`$ref\` |"
	echo "| HTCondor commit | [\`$sha\`](https://github.com/htcondor/htcondor/commit/$sha) |"
	echo "| Run | $run_url |"
	echo
	echo "The oracle is built from a moving branch, so a divergence reported here can be a change in HTCondor rather than a bug in the Go parser."
	echo "Reproduce against the commit above before treating it as ours: check that commit out, then point \`HTCONDOR_SRC\` at it and run \`.github/scripts/build-condor-utils.sh\` (\`HTCONDOR_REF\` is cloned with \`git clone --branch\`, which takes no bare commit)."
} >"$body"

# Reproducers go/test writes are new files under <pkg>/testdata/fuzz/; the
# committed corpus is tracked, so untracked is exactly the new ones.
# (a read loop rather than mapfile, which bash 3.2 on macOS does not have)
repro=()
while IFS= read -r f; do
	[ -n "$f" ] && repro+=("$f")
done < <(git ls-files --others --exclude-standard -- fuzz |
	grep '/testdata/fuzz/' || true)
if [ "${#repro[@]}" -gt 0 ]; then
	{
		echo
		echo "## New reproducers"
		echo
		for f in "${repro[@]}"; do
			echo "\`$f\`"
			echo
			echo '```'
			head -c 2000 "$f"
			echo
			echo '```'
			echo
		done
	} >>"$body"
fi

{
	echo
	echo "## Log excerpts"
} >>"$body"

for t in $FAILED_TARGETS; do
	log="$logdir/differential-fuzz-$t.log"
	{
		echo
		echo "### $t"
		echo
		if [ -f "$log" ]; then
			echo '```'
			tail -n 120 "$log" | head -c 12000
			echo
			echo '```'
		else
			echo "No log; see the run."
		fi
	} >>"$body"
done

{
	echo
	echo "Full logs and any \`testdata/fuzz\` reproducer are attached to the run as artifacts."
} >>"$body"

# The label is the dedup key, so it has to exist before it can be queried
# or applied.
gh label create "$label" \
	--color B60205 \
	--description "Opened by the nightly differential fuzz workflow" >/dev/null 2>&1 || true

existing="$(gh issue list --state open --label "$label" \
	--limit 1 --json number --jq '.[0].number // empty')"

if [ -n "$existing" ]; then
	echo "commenting on existing issue #$existing"
	gh issue comment "$existing" --body-file "$body"
else
	echo "opening a new issue"
	gh issue create \
		--title "Nightly differential fuzz failure (HTCondor $ref)" \
		--label "$label" \
		--body-file "$body"
fi
