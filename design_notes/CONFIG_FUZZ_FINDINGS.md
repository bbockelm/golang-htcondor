# Differential config-parser findings (Go vs HTCondor C++)

The differential fuzzer (`FuzzConfigParseExpand`) compares the Go config parser
(`config.NewFromReaderWithOptions(..., SkipDefaults)`) against HTCondor's
reference C++ parser (`libcondor_utils`, via `oracle/`). Both parse the same
source with **no `param_info.in` defaults** (mode #1) and a fixed reference
environment (`RefEnv`).

The oracle reads the input the way HTCondor reads a config **file**:
`Parse_macros` over a `MacroStreamMemoryFile`, which shares
`getline_implementation` (trimming, `\` continuation) with the `FILE*` stream
`process_config_source` uses. Until October 2026 it called
`Parse_config_string` instead. That is the parser for metaknob bodies: it does
not join continuations, and it takes whitespace as an operator, so it accepted
lines such as `foo bar` that every config file rejects. Findings #8 and #12
below were artifacts of that, and #7 was misdescribed.

Every `include` form is kept off both sides: the shim passes
`CONFIG_OPT_NO_INCLUDE_FILE` (production passes 0), and the harness does not run
either engine on an input whose Go parse contains an include directive
(`ReadsHost`), so a fuzz input never reads a host file or runs a command.

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
| 7 | `FOO = 1` / `foo = 2` / `USE = $(Foo)` | sets `ROLE` (runs a `use` directive) | `USE=2` | Open (Go bug) — a config file treats `use` as the metaknob keyword only before `:`; `USE = …` is an ordinary assignment (condor 25.14.1: `USE = foo` / `X = $(USE)` → `X = foo`). Go's lexer always takes `use` as the keyword. The old oracle reported a rejection (*"use needs a keyword before :"*), which was `Parse_config_string`'s prefix check, not the file reader. |
| 8 | `LONG = a \` (continuation) | joined | (rejected) | **FIXED (oracle bug)** — `Parse_config_string` doesn't join `\`-continuations; the real reader (`getline_implementation`) does. The shim first replicated the joining by hand; it now reads through `Parse_macros`, which joins natively. Go was already correct. |
| 9 | `C : colonval` | ~~rejected~~ → `C=colonval` | `C=colonval` | **FIXED** — colon is now an assignment operator in the lexer (a statement-start plain identifier followed by `:` reads the value like `=`). |
| 10 | `if 1 > 0` … `endif` | accepted (default) / rejected (compat) | rejected | **FIXED via mode** — HTCondor's `if` accepts only bare bool / `defined X` / `version <op> x`; it rejects **all** comparisons (`>`,`<`,`==`,`!=`) **and** `&&`/`||`. Go keeps its richer `if` by default (extension) and rejects it under `ConfigOptions{HTCondorCompat:true}`, which the fuzzer uses. |

## Next

Fixed: `$(DOLLAR)` (#1), inline-`#` (#2), colon assignment (#9), and the continuation
oracle bug (#8). Handled by mode: rich `if` (#10) — default keeps it, compat rejects
it, fuzzer runs in compat. Extensions kept: `$DIRNAME`/`$BASENAME` (#3–4) and nested
re-expansion (#6). Documented, not chased: `$INT` (#5).

## Coverage-guided fuzzing (via hack/config-fuzz.sh)

The fuzzer runs the Go side in `HTCondorCompat` mode so intentional extensions
don't create noise. It found these within seconds each:

| # | Input | Go | C++ (truth) | Status |
|---|---|---|---|---|
| 11 | `0` (bare non-assignment line) | ~~accepted~~ → rejected | rejected | **FIXED** — lenient `Parse` silently dropped unparseable lines; compat now uses `ParseStrict`, and a spurious EOF error was fixed in `Lex` so real errors surface cleanly. |
| 12 | `foo bar` (two tokens, whitespace) | rejected | rejected | **Parity (was an oracle artifact)** — only `Parse_config_string` (metaknob bodies) takes whitespace as an operator. A config file with `foo bar` or `0 00` fails: condor 25.14.1 reports *"Configuration Error Line 1"*. The fuzzer's `0 00` corpus entry is kept as a regression. |

## Found after the oracle moved to the file reader (October 2026)

Each was checked against condor 25.14.1 (`CONDOR_CONFIG=<file> condor_config_val`)
and is a known-divergence seed in `differential_test.go`. #13 and #14 surface
within a second of fuzzing, #15–#18 within minutes once those are set aside
(#19 came from probing), so the CI fuzz step fails until they are fixed.

| # | Input | Go | C++ (truth) | Status |
|---|---|---|---|---|
| 13 | `foo bar = baz` | rejected | `foo=baz` | Open — words between the name and the operator are ignored by the file reader (`0 0=` sets `0` to empty). |
| 14 | `0 = 1` | rejected | `0=1` | Open — a name is any run of identifier characters (`is_valid_param_name`); Go's lexer requires a letter or `_` first. |
| 15 | `T = v ` with no final newline | `v` | `v ` | Open — the reader keeps trailing whitespace on a last line that lacks a newline. |
| 16 | `B = \xff` | `B=U+FFFD` | `B=\xff` | Open — HTCondor keeps bytes; Go's rune lexer replaces invalid UTF-8. |
| 17 | `H@=end` … `@end` | accepted (here-doc) | rejected | Open — the name scan stops only at whitespace, `=` or `:`, so the name is `H@` (*"Illegal Identifier: <H@>"*); a here-doc needs whitespace before `@=`. |
| 18 | `S = $(s)` | `$(s)` | (empty) | Open — a self-reference expands to the previous value, empty when there is none (`A = x$(A)y` → `xy`). |
| 19 | `E = $ENV(UNSET:dflt)` | (empty) | `dflt` | Open — Go looks up the literal `UNSET:dflt` and ignores the default. |

Remaining open:
- **#13–#19** above.
- **#7 `use` keyword** — Go takes `USE = …` as a `use` directive; HTCondor
  assigns it as an ordinary name.
- **#5 `$INT`** — Go leaves non-integer `$INT(...)` literal; HTCondor evaluates via
  ClassAd and aborts on failure. Not worth replicating the abort.
