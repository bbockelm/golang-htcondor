# HTCondor Configuration Parser

This package implements parsing and management of HTCondor configuration files in Go.

## Architecture

Configuration files are read by a port of HTCondor's own reader and macro
expansion (`config.cpp`, v25.14.1), so a file means here what it means to
condor_config_val:

1. **Reader** (`reader.go`) - `getline_implementation` and `Parse_macros`:
   logical lines (trimming, `\` continuation), then one line at a time, in
   order: `if`/`elif`/`else`/`endif`, `NAME = value`, `NAME : value`,
   `NAME += value`, `NAME @=tag` blocks, `use`, `include`, `error`,
   `warning`. A line HTCondor rejects fails the whole source.

2. **Expansion** (`expand.go`, `printf.go`) - the `expand_macro` that
   `param()` uses: `$(NAME)`, `$(NAME:default)`, `$(DOLLAR)` and the special
   functions (`$ENV`, `$INT`, `$REAL`, `$STRING`, `$EVAL`, `$SUBSTR`,
   `$CHOICE`, `$RANDOM_*`, `$DIRNAME`, `$BASENAME`, `$F...`), with glibc's
   printf behavior for their formats. A reference cycle, on which HTCondor
   loops forever, is reported as `ErrMacroLoop`; a construct on which
   HTCondor crashes as `ErrHTCondorUndefined`.

3. **Metaknobs** (`metaknob.go`) - `use CATEGORY : Knob(args)` from the
   vendored param_info table, with HTCondor's argument substitution and its
   metaknob-body parser.

4. **Lexer and parser** (`lexer.go`, `parser.y`) - a goyacc grammar that
   parses a source into statements (`Parse`, `ParseStrict`). Submit files
   use it (they carry `queue` statements and `+Attr`); config files do not.

5. **Config Manager** (`config.go`) - storage, case-insensitive lookup,
   subsystem/local-name scoping, defaults and the file chain.

The differential fuzzer in `fuzz/config` compares the reader and expansion
against libcondor_utils.

## Current Implementation Status

### ✅ Implemented Features (Complete)

1. **Basic Configuration Parsing**
   - Key-value pair parsing (`KEY = value`)
   - Comment support (`#` prefix)
   - Line continuation support (trailing `\`)
   - Empty line handling
   - Keywords can be used as variable names
   - **Heredoc syntax** (`@=TAG ... @TAG`) for multi-line values

2. **Lexer (Complete)**
   - All token types (keywords, operators, literals)
   - Identifier parsing (including subsystem.local.param format)
   - String literals with escape sequences
   - Number parsing (integer and float)
   - Macro references `$(VAR)` with nested support
   - Automatic value capture after assignment
   - Line continuation with proper whitespace handling
   - Comment skipping

3. **Parser (Complete - Fully Integrated)**
   - goyacc-based BNF grammar parser
   - Assignment statements (`KEY = value`)
   - Conditional blocks (`if`/`elif`/`else`/`endif`)
   - Include directives (`include`, `include command`, `include ifexist`)
   - Use directives (`use ROLE`)
   - Error/warning directives
   - AST generation and execution for all statement types

4. **Conditionals (Complete)**
   - `if`/`elif`/`else`/`endif` block execution
   - `defined(VAR)` function to check variable existence
   - Version comparisons: `version >= "9.0.0"`
   - Boolean expressions: `&&`, `||`, `!`
   - Comparison operators: `==`, `!=`, `<`, `>`, `<=`, `>=`
   - Truthy value evaluation: `true`, `false`, `yes`, `no`

5. **Include Directives (Complete)**
   - `include : file.conf` - Include single file
   - `include : /path/*.conf` - Glob pattern support
   - `include ifexist : file.conf` - Optional include (no error if missing)
   - `include command : script.sh` - Execute command and parse output
   - Circular include detection

6. **Function Macros (Complete)**
   - `$ENV(var)` - Environment variable expansion with defaults
   - `$INT(expr, format)` - Integer formatting (hex, octal support)
   - `$REAL(expr, format)` - Float formatting with precision
   - `$STRING(expr)` - String conversion
   - `$SUBSTR(str, offset, length)` - Substring extraction
   - `$RANDOM_INTEGER(min, max, step, sum)` - Random number generation
   - Nested function macro expansion

7. **Macro Expansion (Complete)**
   - Variable substitution using `$(VARIABLE)` syntax
   - Default values: `$(VARIABLE:default_value)`
   - Nested macro expansion
   - Self-referential macros (incremental definition)
   - Lazy evaluation (macros expanded on Get, not on Set)
   - Circular reference detection

8. **Built-in Macros (Complete)**
   - Time constants: `SECOND`, `MINUTE`, `HOUR`, `DAY`, `WEEK`
   - Host information: `HOSTNAME`, `FULL_HOSTNAME`
   - Process information: `PID`, `PPID`
   - System information: `SUBSYSTEM`

9. **Configuration Loading (Complete)**
   - Load from `io.Reader`
   - Load from environment (`_CONDOR_` prefixed variables)
   - Load from `CONDOR_CONFIG` environment variable
   - Try default locations (`/etc/condor/condor_config`, etc.)
   - Support for `CONDOR_CONFIG=ONLY_ENV`

10. **Error Handling (Complete)**
    - `error : message` - Stop parsing with error
    - `warning : message` - Print warning and continue
    - Graceful error recovery in parser
    - Detailed error messages

11. **HTCondor Parameter Defaults (Complete)**
    - Generated from HTCondor 25.3.1 `param_info.in`
    - 1231+ parameter defaults loaded automatically
    - Defaults remain unexpanded until accessed via `Get()`
    - Platform-specific defaults (Windows vs Unix)
    - `go generate` based code generation

12. **Configuration Options (Complete)**
    - `LocalName` - Set local name for this instance
    - `Subsystem` - Set subsystem (MASTER, SCHEDD, STARTD, etc.)
    - Affects variable resolution and parameter defaults

13. **Comprehensive Tests (Complete)**
    - **69 test cases** covering all functionality
    - Lexer tests (13 tests - all token types, complex values, line continuations)
    - Parser tests (5 tests - assignments, conditionals, includes)
    - Config tests (12 tests - macro expansion, loops, built-ins)
    - Conditionals tests (6 tests - all operators and expressions)
    - Executor tests (12 tests - statement execution, includes, directives)
    - Function macro tests (7 tests - all function types)
    - Heredoc tests (7 tests - multi-line values, macros, edge cases)
    - Param defaults tests (5 tests - defaults, options, platform-specific)
    - **100% test pass rate**

### 🔄 Optional/Future Features

The following features could be added based on user requirements:

1. **Additional Function Macros**
   - `$CHOICE(index, list)` - List selection
   - `$F[fpduwnxbqa](filename)` - Filename manipulation
   - Additional format options for numeric functions

2. **Advanced Configuration**
   - Configuration templates with parameters: `use ROLE : Parameter`
   - Advanced subsystem-specific variable scoping

## Usage Examples

### Basic Usage

```go
import "github.com/bbockelm/golang-htcondor/config"

// Load from environment and default locations
cfg, err := config.New()
if err != nil {
    log.Fatal(err)
}

// Get a value
value, ok := cfg.Get("COLLECTOR_HOST")
if !ok {
    log.Fatal("COLLECTOR_HOST not defined")
}
fmt.Println("Collector:", value)
```

### Load from Reader

```go
configText := `
# HTCondor configuration
COLLECTOR_HOST = cm.example.com:9618
SCHEDD_NAME = my_schedd
DAEMON_LIST = MASTER, SCHEDD
`

cfg, err := config.NewFromReader(strings.NewReader(configText))
if err != nil {
    log.Fatal(err)
}
```

### Configuration with Options

```go
// Create config for a specific subsystem with local name
cfg, err := config.NewWithOptions(config.ConfigOptions{
    Subsystem: "SCHEDD",
    LocalName: "submit-node-1",
})
if err != nil {
    log.Fatal(err)
}

// Subsystem is automatically set
subsys, _ := cfg.Get("SUBSYSTEM")  // Returns "SCHEDD"

// Local name can be used in configuration
localName, _ := cfg.Get("LOCAL_NAME")  // Returns "submit-node-1"
```

### Using Parameter Defaults

```go
// Parameter defaults from HTCondor 25.3.1 are loaded automatically
cfg, err := config.New()
if err != nil {
    log.Fatal(err)
}

// Access defaults (these contain unexpanded macros)
timeout, _ := cfg.Get("SHUTDOWN_FAST_TIMEOUT")  // Returns "300"
interval, _ := cfg.Get("PREEN_INTERVAL")  // Returns "86400"

// Set base paths for expansion
cfg.Set("SBIN", "/usr/local/condor/sbin")

// Now MASTER expands to full path
master, _ := cfg.Get("MASTER")  // Returns "/usr/local/condor/sbin/condor_master"
```

### Macro Expansion

```go
configText := `
BASE_DIR = /opt/condor
BIN_DIR = $(BASE_DIR)/bin
SBIN_DIR = $(BASE_DIR)/sbin
MASTER = $(SBIN_DIR)/condor_master
`

cfg, err := config.NewFromReader(strings.NewReader(configText))
master, _ := cfg.Get("MASTER")
// master = "/opt/condor/sbin/condor_master"
```

### Incremental Definition

```go
configText := `
DAEMON_LIST = MASTER
DAEMON_LIST = $(DAEMON_LIST), COLLECTOR
DAEMON_LIST = $(DAEMON_LIST), NEGOTIATOR
`

cfg, err := config.NewFromReader(strings.NewReader(configText))
daemons, _ := cfg.Get("DAEMON_LIST")
// daemons = "MASTER, COLLECTOR, NEGOTIATOR"
```

### Conditionals

```go
configText := `
ENABLE_IPV6 = true

if $(ENABLE_IPV6)
  NETWORK_INTERFACE = 0.0.0.0
  COLLECTOR_HOST = [::1]:9618
else
  NETWORK_INTERFACE = 127.0.0.1
  COLLECTOR_HOST = 127.0.0.1:9618
endif
`

cfg, err := config.NewFromReader(strings.NewReader(configText))
collector, _ := cfg.Get("COLLECTOR_HOST")
// collector = "[::1]:9618"
```

### Function Macros

```go
configText := `
HOME = $ENV(HOME)
LOG_DIR = $(HOME)/condor/log
PORT = $RANDOM_INTEGER(9000, 9999)
VERSION_NUM = $INT(9.0, %d)
`

cfg, err := config.NewFromReader(strings.NewReader(configText))
home, _ := cfg.Get("HOME")
// home = "/Users/username"
```

### Include Directives

```go
configText := `
# Include common configuration
include : /etc/condor/config.d/*.conf

# Include optional local config
include ifexist : /etc/condor/condor_config.local

# Execute command to get dynamic config
include command : /usr/local/bin/generate-condor-config.sh
`

cfg, err := config.NewFromReader(strings.NewReader(configText))
```

### Heredoc (Multi-line Values)

```go
configText := `
# Use heredoc for multi-line script values
STARTER_SCRIPT @=EOF
#!/bin/bash
export PATH=/opt/condor/bin:$PATH
export CONDOR_HOME=$(BASE_DIR)
exec /opt/condor/sbin/condor_starter "$@"
@EOF

BASE_DIR = /opt/condor
`

cfg, err := config.NewFromReader(strings.NewReader(configText))
script, _ := cfg.Get("STARTER_SCRIPT")
// script contains the multi-line bash script
// with $(BASE_DIR) expanded to "/opt/condor"
```

## Architecture

The implementation consists of:

- **lexer.go** - Character-by-character tokenizer with lookahead
- **parser.y** - goyacc BNF grammar definition
- **parser.go** - Generated parser from grammar
- **config.go** - Main `Config` type and core functionality
- **executor.go** - Statement execution engine (assignments, conditionals, includes)
- **conditionals.go** - Conditional expression evaluation
- **functions.go** - Function macro implementations
- **\*_test.go** - Comprehensive test suites for each component

### Loop Detection

Two types of loops are detected:

1. **Macro Loops**: Detected during macro expansion by tracking variables currently being evaluated
2. **Include Loops**: Detected by tracking filenames that have been included

## Testing

Run the test suite:

```bash
go test ./config
```

Run with verbose output:

```bash
go test -v ./config
```

Run with coverage:

```bash
go test -cover ./config
```

Current test coverage: **69 test cases, 100% pass rate**

## Code Generation

The package uses `go generate` to create `param_defaults.go` from HTCondor's `param/param_info.in`:

```bash
cd config
go generate
```

This parses all parameter definitions from HTCondor 25.3.1 and generates a Go file with 1231+ default values. The generator supports:
- Simple key=value defaults
- Heredoc-style multi-line defaults (`: @tag`)
- Platform-specific defaults (win32_default)
- Type information (string, int, bool, double, long, path)

## Parser Regeneration

If you modify the grammar in `parser.y`, regenerate the parser:

```bash
cd config
go run golang.org/x/tools/cmd/goyacc@latest -o parser.go parser.y
```

## Contributing

When adding features:

1. Add tests first (TDD approach)
2. Keep loop detection mechanisms intact
3. Document new features in this README
4. Ensure backward compatibility
5. If modifying parser.y, regenerate parser.go with goyacc

## Implementation Notes

- **Lazy Evaluation**: Macros are stored unexpanded and only evaluated when accessed via `Get()`
- **Keyword Variables**: Keywords (like `defined`, `if`, `include`) can be used as variable names
- **Line Continuation**: Backslash at end of line continues to next line, trimming trailing/leading whitespace
- **Case Sensitivity**: Variable names are case-sensitive; keywords are case-insensitive
- **Heredoc Syntax**: Use `VAR @=TAG ... @TAG` for multi-line values
  - The closing `@TAG` must be on its own line
  - Content between tags is preserved including newlines and indentation
  - Macros in heredoc values are expanded when the variable is accessed via `Get()`
