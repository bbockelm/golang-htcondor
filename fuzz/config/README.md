# Differential config fuzzer (Go vs HTCondor C++)

Compares the native Go config parser against HTCondor's reference C++ parser
(`libcondor_utils`) to find divergences in parsing and `$(...)` macro
expansion. Same idea as the golang-classads libclassad fuzzer.

**Scope (mode #1):** a *pure* parse+expand differential — both engines parse
with no `param_info.in` defaults (Go: `ConfigOptions{SkipDefaults: true}`; C++:
a fresh `MACRO_SET` with a NULL defaults table and production option flags:
`COLON_IS_META_ONLY | SMART_COM_IN_CONT | KEEP_DEFAULTS`). A fixed reference
environment (`RefEnv` in `engine.go` — time constants, `FULL_HOSTNAME`,
`DETECTED_*`, …) is prepended to every input so realistic sources resolve, and
is stripped from the compared output. Comparing the `param_info.in` defaults
table itself is a separate axis (mode #2), handled by a defaults-sync script.

## Layout

- `oracle/` — cgo bridge to `libcondor_utils` (`shim.cc`/`shim.h`), behind the
  `libcondor_utils` build tag, with a `stub.go` so the tree builds/vets without it.
- `engine.go` — Go side + `RefEnv` + canonical output.
- `canon.go` — normalizes tables (case-insensitive keys, sorted).
- `differential_test.go` — seed corpus + `FuzzConfigParseExpand` + known-divergence tracking.
- `FINDINGS.md` — divergences found so far.

## Building / running

The oracle needs HTCondor headers + `libcondor_utils`. On a local build tree,
`hack/config-fuzz-env.sh` derives the CGO flags (and embeds rpaths so the test
binary finds the dylib without `DYLD_LIBRARY_PATH`, which macOS SIP strips):

```sh
source hack/config-fuzz-env.sh          # override HTCONDOR_SRC / HTCONDOR_BUILD if needed

# seed parity + known-divergence check
go test -tags libcondor_utils ./fuzz/config/ -run TestConfigSeeds

# coverage-guided fuzzing
go test -tags libcondor_utils -run x -fuzz FuzzConfigParseExpand ./fuzz/config/
```

Without the tag, the package builds against `stub.go` and the tests skip — so
`go build ./...` / `go vet ./...` / non-fuzz CI stay green everywhere.
