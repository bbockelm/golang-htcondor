# Differential config-parser findings (Go vs HTCondor C++)

The differential fuzzer (`FuzzConfigParseExpand`) compares the Go config parser
(`config.NewFromReaderWithOptions(..., SkipDefaults, HTCondorCompat)`) against
HTCondor's reference C++ parser (`libcondor_utils`, via `oracle/`). Both parse
the same source with **no `param_info.in` defaults** (mode #1) and a fixed
reference environment (`RefEnv`). HTCondor's C++ is the ground truth; every
expectation below was also checked against condor 25.14.1
(`CONDOR_CONFIG=<file> condor_config_val NAME`).

## What the oracle runs

- **Reader:** `Parse_macros` over a `MacroStreamMemoryFile`, which shares
  `getline_implementation` (trimming, `\` continuation) with the `FILE*`
  stream `process_config_source` uses. Until October 2026 it called
  `Parse_config_string`, the more lenient parser for metaknob bodies, which
  accepted lines such as `foo bar` that every config file rejects.
- **Expansion:** the `char*` overload of `expand_macro`, which `param()` uses.
  It first used the `std::string` overload, which differs: it has no
  `$DIRNAME`/`$BASENAME`, does not re-expand the result of an expansion, and
  reads `$SUBSTR`'s first argument differently. Findings #3, #4 and #6 below
  were artifacts of that.
- **ClassAd semantics:** old ClassAd semantics, which production `config()`
  turns on (`ClassAdReconfig`, unless `STRICT_CLASSAD_EVALUATION`). Without
  them `$INT(0x10)` lexes as 0 (finding #5); with them it is not a number.
- **No host access:** the shim passes `CONFIG_OPT_NO_INCLUDE_FILE` and the Go
  side `ConfigOptions{NoInclude: true}`, so every `include` form is a parse
  error on both sides and nothing is read or run
  (`TestGoSideNeverRunsInclude`).

## Not compared

`divergence()` skips an input, rather than comparing it, when:

- it holds a NUL byte (the oracle takes a C string);
- the Go side reports `config.ErrMacroLoop`: an expansion that does not
  terminate. HTCondor loops forever on `A = $(B)` / `B = $(A)` and overflows
  its stack on `A = $SUBSTR(B,0)` / `B = $(A)` (condor_config_val: timeout,
  SIGSEGV);
- the Go side reports `config.ErrHTCondorUndefined`: a construct on which
  HTCondor's own code has no defined result. condor 25.14.1:

  | Input | HTCondor |
  |---|---|
  | `A = $F("")` | strcpy_quoted takes the length to -1: SIGSEGV / heap corruption |
  | `A = $Fdd(a/b)` (more d's than directories) | pops an empty vector: assertion abort |
  | a line ending in `+` after a name and space (`A B+`) | `strchr(",;\|&*", '\0')` matches the terminator, and the parser reads the bytes after the line (the oracle returned a value left over from an earlier line) |
  | `$REAL(x,fmt)` whose output fills the 55-byte buffer with no `.` | `strcat(buf, ".0")` overflows: fortify abort |
  | `$INT`/`$REAL`/`$STRING` formats that read an argument HTCondor does not pass (`%LA`, `%2$d`, `%*d`, a second conversion, `%lc` of a non-ASCII value) | undefined vararg reads |

Each divergence that remains is a known-divergence seed in
`differential_test.go`; the test asserts it still diverges, so a fix flips it
and says to promote the case to parity.

## Findings

| # | Input | Go before | HTCondor | Status |
|---|---|---|---|---|
| 1 | `D = a$(DOLLAR)b` | `ab` | `a$b` | FIXED |
| 2 | `K = v   # trailing` | `v` | `v   # trailing` | FIXED |
| 3 | `DN = $DIRNAME(/a/b/c)` | `/a/b/` | `/a/b/` | Parity (was an oracle artifact, see above) |
| 4 | `BN = $BASENAME(/a/b/c)` | `c` | `c` | Parity (oracle artifact) |
| 5 | `I = $INT(0x10)` | `$INT(0x10)` | `` (not a number) | FIXED (and the oracle's `0` was new-ClassAd semantics) |
| 6 | `NAME = MINUTE` / `VAL = $($(NAME))` | `60` | `60` | Parity (oracle artifact) |
| 7 | `USE = $(Foo)` | ran a `use` directive, set `ROLE` | ordinary assignment | FIXED: `use` is a keyword only before `:` |
| 8 | `LONG = a \` continuation | joined | joined | Oracle bug, fixed earlier |
| 9 | `C : colonval` | rejected | `C=colonval` | FIXED |
| 10 | `if 1 > 0` | accepted | rejected | Default mode keeps the richer `if` (extension); compat rejects |
| 11 | `0` (no operator) | dropped silently | rejected | FIXED: a bad line fails the source, in every mode |
| 12 | `foo bar` | rejected | rejected | Parity (the old oracle accepted it) |
| 13 | `foo bar = baz` | rejected | `foo=baz` | FIXED: words before the operator are ignored |
| 14 | `0 = 1` | dropped silently (default) / rejected (compat) | `0=1` | FIXED: a name is any run of identifier characters (`[A-Za-z0-9_./]`) |
| 15 | `T = v ` with no final newline | `v` | `v ` | FIXED: the reader returns a last line without a newline untrimmed |
| 16 | `B = \xff` | U+FFFD | `\xff` | FIXED: bytes are kept |
| 17 | `H@=end` … `@end` | here-doc | rejected (Illegal Identifier `H@`) | FIXED |
| 18 | `S = $(s)` | `$(s)` | `` | FIXED: a self-reference expands to the previous value |
| 19 | `E = $ENV(UNSET:dflt)` | `` | `dflt` (`UNDEFINED` with no default) | FIXED |
| 20 | `A = x\` / `y` | `x y` | `xy` | FIXED: continuation joins without a space |
| 21 | `A = x \` / `# c` | `x` | `x c` | FIXED: a `#` line inside a continuation contributes its last character |
| 22 | `A += 2`, `L +,= b` | rejected | appended | FIXED |
| 23 | `$SUBSTR(hello,1,3)`, `$CHOICE(0, only)` | `ell`, `only` | `` , `` | FIXED: their first argument is a macro name |
| 24 | `$INT($(NUM))` | `42` | `)` | FIXED: a special function's body ends at the first `)` |
| 25 | `$EVAL(X * Y)` with X, Y config values | `200` | `undefined` | FIXED: the expression is evaluated in an empty ad |
| 26 | `#!` line inside `@=` | kept | dropped | FIXED: a `#` line is a comment there too |
| 27 | `$REAL(1,%A% )`, `$INT(7,%d%5.2lz)`, ... | Go fmt | glibc printf | FIXED: formats follow glibc (one length modifier, unknown conversions echoed in glibc's normalized form, output ends at a cut-short spec) |

## Open: ClassAd library divergences

`$INT`, `$REAL`, `$STRING` and `$EVAL` evaluate their argument as a ClassAd
expression. The Go side uses github.com/PelicanPlatform/classad; where it
differs from libclassad (old semantics) the config values differ. Found so far
(each a known-divergence seed; condor 25.14.1 values):

| Input | HTCondor | Go |
|---|---|---|
| `$INT(0//)` | `0` (`//` is a comment) | `` (parse error) |
| `$INT(!-00)` | `1` (`-00` lexes as a negative real) | `` (`00` rejected) |
| `$REAL(10000000000000000000%1)` | `0` (out-of-range literal becomes 0) | `` |
| `$INT("\x7f\xb4" > "\x7f\x84")` | `1` (bytes compared) | `0` (invalid UTF-8 normalized to U+FFFD) |
| `$INT(0;)` | `` (trailing `;` rejected) | worked around in `parseConfigExpr` |

The coverage-guided fuzzer reaches these within seconds, so the CI fuzz step
fails until the ClassAd library matches libclassad on them.
