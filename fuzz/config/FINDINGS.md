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
| 5 | `I = $INT(0x10)` | `$INT(0x10)` (literal) | `0` | Open — Go leaves `$INT(hex)` literal; HTCondor evaluates it (to `0`). C++'s `0` is itself odd; low priority. |
| 6 | `NAME = MINUTE` / `VAL = $($(NAME))` | `60` | `$(MINUTE)` | Open — Go re-expands an inner macro's result; HTCondor is single-pass. Needs an algorithm change (don't re-scan substituted text). |
| 7 | `FOO = 1` / `foo = 2` / `USE = $(Foo)` | accepted | rejected | Open — likely the reserved `use` keyword (`USE = …`), not case redefinition. Needs a narrower repro before "fixing". |
| 8 | `LONG = a \` (indented continuation) | accepted | rejected | Open — leading whitespace on continuation lines. Narrow which form HTCondor rejects. |
| 9 | `C : colonval` | rejected | accepted | Open — colon is meta-only; HTCondor accepts the line as a non-error, Go errors. |
| 10 | `if 1 > 0` … `endif` | accepted | rejected | Open — Go evaluates a numeric `if` comparison; HTCondor's `if` grammar rejects it. |

## Next

Open items 5–10 are parser/grammar or expansion-semantics decisions; each wants
a minimized repro (the fuzzer will produce more) and a check against the
HTCondor manual on which side is right. Items 6, 7, 9, 10 in particular need
care — "matching C++" could mean making Go *reject* things it currently accepts,
so confirm intent before changing the grammar.
