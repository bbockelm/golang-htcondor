#!/usr/bin/env bash
#
# The webapi tests that exist only in a release build: the embed_frontend
# side of httpserver/webui and the embed_condor_docs side of condordocs.
# Run from the repo root after `npm run build` has produced
# webapi/frontend/out.
#
# Without the tags, TestIconIsServed skips and the TestEmbedded_* tests are
# not even compiled, so no CI job exercised the assets a release ships.
# With the tags but without the staged files, the build fails or the tests
# skip -- and a skip is indistinguishable from a pass in the check list.
# So this asserts that every test it exists for actually PASSED.
set -euo pipefail

# Same ref Dockerfile.release clones by default; release-container.yml
# passes no override, so this is the docs the release image embeds.
HTCONDOR_GIT_URL=${HTCONDOR_GIT_URL:-https://github.com/htcondor/htcondor.git}
HTCONDOR_GIT_REF=${HTCONDOR_GIT_REF:-main}

work=${RUNNER_TEMP:-$(mktemp -d)}
src="$work/htcondor"

# The frontend export goes where embed.go's //go:embed all:dist reads it,
# as `make build-prod` does. rm first: cp -r into an existing dist nests
# the export at dist/out and the SPA handler finds no index.html.
rm -rf webapi/httpserver/webui/dist
cp -r webapi/frontend/out webapi/httpserver/webui/dist

# Only docs/ of the HTCondor tree: a blobless, sparse, depth-1 clone fetches
# the files staged below rather than the whole C++ source and its history.
rm -rf "$src"
git clone --quiet --depth 1 --filter=blob:none --sparse \
	--branch "$HTCONDOR_GIT_REF" "$HTCONDOR_GIT_URL" "$src"
git -C "$src" sparse-checkout set docs
echo "HTCondor docs at $HTCONDOR_GIT_REF ($(git -C "$src" rev-parse --short HEAD))"

make stage-condor-docs CONDOR_DOCS_SRC="$src/docs"

# -run selects only the tests that need the assets. The packages' other
# tests already run untagged in the Test job, and one of them
# (TestSearch_NotEmbeddedReturnsSentinel) correctly skips when the docs ARE
# embedded -- which would trip the no-skip check below for the wrong reason.
log="$work/embedded-assets-tests.log"
(cd webapi && GOWORK=off go test -count=1 -v \
	-tags "embed_frontend embed_condor_docs" \
	-run '^(TestIconIsServed|TestEmbedded_.*)$' \
	./httpserver/webui/ ./condordocs/) 2>&1 | tee "$log"

# Past here go test exited 0 (pipefail). Now check it ran what it is for.
failed=0

if grep -q -- '--- SKIP' "$log"; then
	echo "::error::a test SKIPPED in the embedded-assets build; the assets were not embedded"
	grep -- '--- SKIP' "$log"
	failed=1
fi

# Every TestEmbedded_* is read from the source, so a test added there is
# held to the same requirement without editing this list.
expected=(TestIconIsServed)
while IFS= read -r name; do
	expected+=("$name")
done < <(sed -n 's/^func \(TestEmbedded_[A-Za-z0-9_]*\)(.*/\1/p' \
	webapi/condordocs/embedded_integration_test.go)

if [ "${#expected[@]}" -lt 2 ]; then
	echo "::error::found no TestEmbedded_* tests in webapi/condordocs/embedded_integration_test.go"
	failed=1
fi

for name in "${expected[@]}"; do
	if ! grep -q -- "--- PASS: $name " "$log"; then
		echo "::error::$name did not PASS"
		failed=1
	fi
done

if [ "$failed" -ne 0 ]; then
	exit 1
fi
echo "All ${#expected[@]} embedded-asset tests passed: ${expected[*]}"
