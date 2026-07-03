# Differential config-parser findings (Go vs HTCondor C++)

The differential fuzzer (`FuzzConfigParseExpand`) compares the Go config parser
(`config.NewFromReaderWithOptions(..., SkipDefaults)`) against HTCondor's
reference C++ parser (`libcondor_utils`, via `oracle/`). Both parse the same
source with **no `param_info.in` defaults** (mode #1) and a fixed reference
environment (`RefEnv`).

Each divergence is encoded as a "known divergence" in `differential_test.go`;
the test asserts it *still* diverges, so a fix flips the test and tells us to
promote the case to parity. HTCondor's C++ is the ground truth.

| # | Input (after RefEnv) | Go | C++ (truth) | Status |
|---|---|---|---|---|
| 1 | `D = a$(DOLLAR)b` | ~~`ab`~~ → `a$b` | `a$b` | **FIXED** — `$(DOLLAR)` now expands to a literal `$` (functions.go). |
| 2 | `K = v   # trailing` | ~~`v`~~ → `v   # trailing` | `v   # trailing` | **FIXED** — `#` inside a value is literal; only a full-line `#` is a comment (lexer.go). |
| 3 | `DN = $DIRNAME(/a/b/c)` | `/a/b/` | `` (empty) | **Intentional extension** — Go adds `$DIRNAME` (HTCondor uses `$Fp`). Kept. |
| 4 | `BN = $BASENAME(/a/b/c)` | `c` | `` (empty) | **Intentional extension** — Go adds `$BASENAME` (HTCondor uses `$Fn`). Kept. |
| 5 | `I = $INT(0x10)` | `$INT(0x10)` (literal) | `0` | **Documented** — `$INT` evaluates its arg as a **ClassAd expression** (`0x10`→`0`) and `EXCEPT`s (hard-aborts) on non-integers like `5x3`. Not replicating the abort; the `0x10`→`0` value depends on ClassAd parsing. |
| 6 | `NAME = MINUTE` / `VAL = $($(NAME))` | `60` | `$(MINUTE)` | **Intentional extension** — Go re-expands an inner macro's result; HTCondor is single-pass. Kept. |
| 7 | `FOO = 1` / `foo = 2` / `USE = $(Foo)` | accepted | rejected | Open (exotic) — it's the reserved `use` keyword (`USE = …` → *"use needs a keyword before :"*), not case redefinition. |
| 8 | `LONG = a \` (continuation) | joined | (rejected) | **FIXED (oracle bug)** — `Parse_config_string` doesn't join `\`-continuations; the real reader (`getline_implementation`) does. The shim now joins/trims lines the same way, so continuations parse. Go was already correct. |
| 9 | `C : colonval` | ~~rejected~~ → `C=colonval` | `C=colonval` | **FIXED** — colon is now an assignment operator in the lexer (a statement-start plain identifier followed by `:` reads the value like `=`). |
| 10 | `if 1 > 0` … `endif` | accepted (default) / rejected (compat) | rejected | **FIXED via mode** — HTCondor's `if` accepts only bare bool / `defined X` / `version <op> x`; it rejects **all** comparisons (`>`,`<`,`==`,`!=`) **and** `&&`/`||`. Go keeps its richer `if` by default (extension) and rejects it under `ConfigOptions{HTCondorCompat:true}`, which the fuzzer uses. |

## Next

Fixed: `$(DOLLAR)` (#1), inline-`#` (#2), colon assignment (#9), and the continuation
oracle bug (#8). Handled by mode: rich `if` (#10) — default keeps it, compat rejects
it, fuzzer runs in compat. Extensions kept: `$DIRNAME`/`$BASENAME` (#3–4) and nested
re-expansion (#6). Documented, not chased: `$INT` (#5).

Remaining open:
- **#7 `use` keyword** — Go treats `use` as an ordinary name when followed by `=`;
  HTCondor reserves it. Exotic; low priority.
- **#5 `$INT`** — Go leaves non-integer `$INT(...)` literal; HTCondor evaluates via
  ClassAd and aborts on failure. Not worth replicating the abort.
