# Differential config fuzzer (Go vs HTCondor C++)

Compares the native Go config parser against HTCondor's reference C++ parser
(`libcondor_utils`) to find divergences in parsing and `$(...)` macro
expansion. Same idea as the golang-classads libclassad fuzzer.

**Scope (mode #1):** a *pure* parse+expand differential — both engines parse
with no `param_info.in` defaults (Go: `ConfigOptions{SkipDefaults: true}`; C++:
a fresh `MACRO_SET` with a NULL defaults table and production option flags:
`COLON_IS_META_ONLY | SMART_COM_IN_CONT | KEEP_DEFAULTS`). The C++ side reads
the input as a config file: `Parse_macros` over an in-memory
`MacroStreamMemoryFile`, the same reader (trimming, `\` continuation) that
`process_config_source` runs on a `FILE*`, and expands values with the
`expand_macro` that `param()` uses, under old ClassAd semantics as production
`config()` sets them. (Not `Parse_config_string`: that is the more lenient
parser for metaknob bodies.) A fixed reference
environment (`RefEnv` in `engine.go` — time constants, `FULL_HOSTNAME`,
`DETECTED_*`, …) is prepended to every input so realistic sources resolve, and
is stripped from the compared output. Comparing the `param_info.in` defaults
table itself is a separate axis (mode #2), handled by a defaults-sync script.

**No host access:** `include` and `include command` would read a host file or
run a command. The shim refuses every include form
(`CONFIG_OPT_NO_INCLUDE_FILE`) and the Go side parses with
`ConfigOptions{NoInclude: true}`, so for both every include is a parse error
(`TestGoSideNeverRunsInclude`).

**Not compared:** inputs with a NUL byte, and inputs on which the Go side
reports that HTCondor has no defined result (`config.ErrMacroLoop`,
`config.ErrHTCondorUndefined`): reference cycles HTCondor never finishes
expanding, and constructs on which it crashes or reads out of bounds. The Go
engine runs first, so the oracle never sees them. See
`design_notes/CONFIG_FUZZ_FINDINGS.md`.

## Layout

- `oracle/` — cgo bridge to `libcondor_utils` (`shim.cc`/`shim.h`), behind the
  `libcondor_utils` build tag, with a `stub.go` so the tree builds/vets without it.
- `engine.go` — Go side + `RefEnv` + canonical output.
- `canon.go` — normalizes tables (case-insensitive keys, sorted).
- `differential_test.go` — seed corpus + `FuzzConfigParseExpand` + known-divergence tracking.
- `design_notes/CONFIG_FUZZ_FINDINGS.md` — divergences found so far.

## Building / running

The oracle needs HTCondor's internal headers (`condor_common.h` includes the
cmake-generated `config.h`; `condor_config.h` ships in no package), so it is
built against a configured HTCondor source tree, not an installed HTCondor.
`hack/config-fuzz-env.sh` derives the CGO flags from that tree's
`compile_commands.json` and takes the newest `libcondor_utils_*` from
`release_dir/lib` (after `ninja install`) or else from `src/condor_utils` and
`src/classad` (after `ninja condor_utils`). It embeds rpaths so the test binary
finds the libraries without `DYLD_LIBRARY_PATH`, which macOS SIP strips, and
sets `LD_LIBRARY_PATH`, which Linux needs because `libcondor_utils`'s own
RUNPATH decides where its `libclassad` dependency is found:

```sh
source hack/config-fuzz-env.sh          # override HTCONDOR_SRC / HTCONDOR_BUILD if needed

# seed parity + known-divergence check
go test -tags libcondor_utils ./fuzz/config/ -run TestConfigSeeds

# coverage-guided fuzzing
go test -tags libcondor_utils -run x -fuzz FuzzConfigParseExpand ./fuzz/config/
```

On macOS use `hack/config-fuzz.sh [fuzztime]` for fuzzing: it runs the compiled
test binary directly so `DYLD_LIBRARY_PATH` survives.

## CI

`.github/workflows/config-fuzz.yml` runs on changes to `config/`, `fuzz/config/`
and these scripts, weekly, and on demand. It builds `condor_utils` from the
HTCondor release named in `HTCONDOR_REF` (`.github/scripts/build-condor-utils.sh`,
ccache-cached), runs the seed table and committed corpus (failing if
`TestConfigSeeds` skipped, i.e. the oracle was not linked), then fuzzes for 2m
(`fuzztime` input on dispatch). A failing input is uploaded as the
`config-fuzz-failing-inputs` artifact; drop it into
`fuzz/config/testdata/fuzz/FuzzConfigParseExpand/` to reproduce.

Without the tag, the package builds against `stub.go` and the tests skip — so
`go build ./...` / `go vet ./...` / non-fuzz CI stay green everywhere.
