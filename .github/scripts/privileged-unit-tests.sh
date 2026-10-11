#!/usr/bin/env bash
#
# The unit tests that need root, run as root: every Test function in a
# *_privileged_test.go file of the core and webapi modules.
#
# These skip with "requires root" everywhere else. The unit-test job runs
# as an ordinary user, and the root job ran only integration tests and
# droppriv/, so the root path of these tests was executed by no job at
# all -- among them the re-elevation that lets a dropped daemon read the
# root-only pool signing key and TLS key, and output-sandbox ownership
# after a drop:
#
#   === SKIP: . TestGenerateJWTReadsARootOnlySigningKeyAfterDrop
#   === SKIP: httpserver TestServeTLSReadsARootOnlyKeyAfterDrop
#   === SKIP: sandbox TestExtractOutputSandbox_PrivilegedOwnership
#
# Only those tests, not the packages they live in. Several tests in the
# same packages deliberately skip when run as root (they check that an
# unprivileged read is refused), and run whole as root the core suite
# fails outright, having been written for an ordinary user.
#
# droppriv/ is left out: integration-tests-privileged-port.sh runs that
# whole package as root already.
#
# See integration-tests-webapi.sh for why this lives in a file rather
# than inline in the workflow.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# The modules whose privileged tests are run here, as directories
# relative to the repo root.
MODULES=(. webapi)

# Every non-generated *_test.go in the tree. node_modules and the Go
# caches hold other people's tests; testdata is never compiled.
all_test_files() {
  find . \( -name .git -o -name .gocache -o -name node_modules -o -name testdata \) -prune \
    -o -type f -name '*_test.go' -print | sed 's|^\./||' | sort
}

# The directory of the go.mod that owns a file, relative to the repo root.
module_of() {
  local dir
  dir=$(dirname "$1")
  while [ "$dir" != "." ] && [ ! -f "$dir/go.mod" ]; do
    dir=$(dirname "$dir")
  done
  echo "$dir"
}

# True if the file is behind the integration build tag. Those run in the
# integration jobs, the root ones in the steps before this one, and this
# script compiles without the tag, so it could not select them anyway.
is_integration() {
  sed '/^package /q' "$1" | grep -Eq '^//go:build.*(^|[^![:alnum:]_])integration([^[:alnum:]_]|$)'
}

in_modules() {
  local m
  for m in "${MODULES[@]}"; do
    [ "$m" = "$1" ] && return 0
  done
  return 1
}

# Files holding the canonical root skip: a uid check against 0 with a
# t.Skip within the next few lines.
#
#   if os.Geteuid() != 0 {
#       t.Skip("test requires root privileges")
#   }
root_skip_files() {
  # shellcheck disable=SC2016 # awk program, not shell
  all_test_files | grep -v '^droppriv/' | tr '\n' '\0' | xargs -0 awk '
    FNR == 1 { armed = 0 }
    /Gete?uid\(\)[[:space:]]*!=[[:space:]]*0/ { armed = 4 }
    armed > 0 {
      if ($0 ~ /\.Skip(f|Now)?\(/) { print FILENAME; armed = 0; next }
      armed--
    }
  ' | sort -u
}

# --- Guard: a root-gated unit test must be one this script runs.
#
# Selection is by file name, so a root-only test written into an
# ordinary _test.go file -- as the sandbox one was -- would skip in the
# unprivileged job and never be selected here, and nothing would say so.
misnamed=()
unrun=()
while read -r f; do
  [ -n "$f" ] || continue
  is_integration "$f" && continue
  case "$f" in
    *_privileged_test.go) ;;
    *) misnamed+=("$f"); continue ;;
  esac
  in_modules "$(module_of "$f")" || unrun+=("$f")
done < <(root_skip_files)

if [ ${#misnamed[@]} -gt 0 ]; then
  echo "These test files skip unless run as root but are not named *_privileged_test.go:" >&2
  printf '  %s\n' "${misnamed[@]}" >&2
  echo "Move the root-only tests into a *_privileged_test.go file in the same package," >&2
  echo "or they run in no job at all." >&2
fi
if [ ${#unrun[@]} -gt 0 ]; then
  echo "These privileged tests are in a module not listed in MODULES:" >&2
  printf '  %s\n' "${unrun[@]}" >&2
  echo "Add the module to MODULES, or they run in no job at all." >&2
fi
if [ ${#misnamed[@]} -gt 0 ] || [ ${#unrun[@]} -gt 0 ]; then
  exit 1
fi

# --- Run them, one go test per package.
out=$(mktemp)
trap 'rm -f "$out"' EXIT

selected=0
failed=()
for mod in "${MODULES[@]}"; do
  while read -r pkgdir; do
    [ -n "$pkgdir" ] || continue
    names=()
    for f in "$pkgdir"/*_privileged_test.go; do
      is_integration "$f" && continue
      while read -r name; do
        [ -n "$name" ] && names+=("$name")
      done < <(sed -nE 's/^func (Test[[:alnum:]_]*)\(t \*testing\.T\).*/\1/p' "$f")
    done
    [ ${#names[@]} -gt 0 ] || continue
    selected=$((selected + ${#names[@]}))

    # The package path as go test wants it, from inside the module.
    if [ "$pkgdir" = "$mod" ]; then
      target=./
    elif [ "$mod" = . ]; then
      target=./$pkgdir/
    else
      target=./${pkgdir#"$mod"/}/
    fi
    pattern="^($(IFS='|'; echo "${names[*]}"))\$"
    echo "=== module $mod: $target -run '$pattern'"

    if ! (cd "$mod" && GOWORK=off gotestsum --format standard-verbose -- \
        -count=1 -v -timeout=5m -run "$pattern" "$target") 2>&1 | tee "$out"; then
      failed+=("module $mod $target: go test failed")
    fi

    # A skip as root means the root path never executed, which is the
    # one thing this step exists to do -- and gotestsum counts a skip as
    # a success. So each selected test must report PASS by name.
    for name in "${names[@]}"; do
      if grep -q "^--- SKIP: $name " "$out"; then
        failed+=("$name skipped as root")
      elif ! grep -q "^--- PASS: $name " "$out"; then
        failed+=("$name did not pass")
      fi
    done
  done < <(all_test_files | grep '_privileged_test\.go$' | grep -v '^droppriv/' \
    | while read -r f; do [ "$(module_of "$f")" = "$mod" ] && dirname "$f"; done | sort -u)
done

# Zero selected would be a green step that ran nothing.
if [ "$selected" -eq 0 ]; then
  echo "No privileged unit tests were selected; the discovery above is broken." >&2
  exit 1
fi

if [ ${#failed[@]} -gt 0 ]; then
  echo "Privileged unit tests failed:" >&2
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi

echo "All $selected privileged unit tests passed as root."
