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
| 8 | `LONG = a \` (continuation) | accepted | rejected | Open (**investigate**) — HTCondor rejected *every* continuation form probed, which is surprising; don't change Go until understood. |
| 9 | `C : colonval` | rejected | `C=colonval` | Open — colon **is** an assignment operator in HTCondor; Go rejects it. Needs lexer/grammar work. |
| 10 | `if 1 > 0` … `endif` | accepted | rejected | Open (**decision**) — HTCondor's `if` accepts only bare bool / `defined X` / `version <op> x`; it rejects **all** comparisons (`>`,`<`,`==`,`!=`) **and** `&&`/`||`. Go implements the richer set (deliberate, tested). Strict-match vs keep-as-extension is a product call. |

## Next

Fixed: `$(DOLLAR)` (#1) and inline-`#` (#2). Extensions kept: `$DIRNAME`/`$BASENAME`
(#3–4) and nested re-expansion (#6). Documented: `$INT` (#5).

Still open and each bigger than a bug fix:
- **#10 `if` grammar** — matching HTCondor removes Go's comparison + logical-operator
  support in `if` (and their tests). Needs a product decision.
- **#9 colon** — add colon as an assignment operator (lexer/grammar).
- **#8 continuation** — first understand *why* HTCondor rejects the probed forms.
- **#7 `use` keyword** — exotic; low priority.
