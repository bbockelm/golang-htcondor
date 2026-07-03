# Differential config-parser findings (Go vs HTCondor C++)

The differential fuzzer (`FuzzConfigParseExpand`) compares the Go config parser
(`config.NewFromReaderWithOptions(..., SkipDefaults)`) against HTCondor's
reference C++ parser (`libcondor_utils`, via `oracle/`). Both parse the same
source with **no `param_info.in` defaults** (mode #1) and a fixed reference
environment (`RefEnv`) so realistic sources resolve identically.

These divergences were surfaced by the seed corpus alone. Each is encoded as a
"known divergence" in `differential_test.go`; the test asserts it *still*
diverges, so if the Go side is fixed the test flips and tells us to promote the
case to parity. Verdicts below are provisional — HTCondor's C++ is the ground
truth (it is what production reads), so a divergence generally means the Go side
should change unless we deliberately want an extension.

| # | Input (after RefEnv) | Go | C++ (truth) | Likely verdict |
|---|---|---|---|---|
| 1 | `D = a$(DOLLAR)b` | `ab` | `a$b` | **Go bug** — `$(DOLLAR)` is HTCondor's literal-`$` escape; Go expands it to empty. |
| 2 | `K = v   # trailing` | `v` | `v   # trailing` | **Go bug** — `#` only starts a *full-line* comment; a `#` inside a value is literal. Go strips trailing `#…`. |
| 3 | `DN = $DIRNAME(/a/b/c)` | `/a/b/` | `` (empty) | Go **extension** — HTCondor has no `$DIRNAME` (it uses `$Fp(...)`); Go added it. Either drop it or accept as intentional. |
| 4 | `BN = $BASENAME(/a/b/c)` | `c` | `` (empty) | Go **extension** — same as above; HTCondor uses `$Fn(...)`. |
| 5 | `I = $INT(0x10)` | `$INT(0x10)` (unexpanded) | `0` | **Divergence** — Go leaves `$INT(hex)` literal; HTCondor evaluates it (to `0` here). `$INT` argument handling differs. |
| 6 | `NAME = MINUTE` / `VAL = $($(NAME))` | `60` | `$(MINUTE)` (literal) | **Divergence** — Go re-expands the *result* of an inner macro; HTCondor does a single pass and leaves `$(MINUTE)`. |
| 7 | `FOO = 1` / `foo = 2` / `USE = $(Foo)` | accepted | **rejected** | **Divergence** — case-insensitive redefinition: HTCondor rejects the source, Go accepts. |
| 8 | `LONG = a \` (continuation lines indented) | accepted | **rejected** | **Divergence** — leading whitespace on continuation lines: Go accepts, HTCondor rejects. Needs narrowing (which exact form). |
| 9 | `C : colonval` | **rejected** | accepted | **Divergence** — colon line: Go errors, HTCondor accepts it (colon is meta-only, non-error). |
| 10 | `if 1 > 0` … `endif` | accepted | **rejected** | **Divergence** — Go evaluates a numeric comparison in `if`; HTCondor's `if` grammar rejects `1 > 0`. |

## Notes / next steps

- Findings 1, 2 are the clearest bugs (silent wrong values in real configs).
- Findings 3, 4 are Go-only functions — decide extension vs. fidelity.
- Findings 6–10 are parser/grammar edge cases; each needs a minimized repro
  (the fuzzer will produce more variants) and a decision on which side is right
  per the HTCondor manual.
- The fuzzer will find more once a structured generator is added
  (`gen/`) — these seeds only scratch the surface.
