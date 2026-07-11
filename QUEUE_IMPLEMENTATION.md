# Queue Statement Implementation

This document describes the implementation of HTCondor queue statement support in the Go HTCondor library.

## Overview

The queue statement in HTCondor submit files allows you to submit multiple jobs from a single submit description. This implementation provides full support for all HTCondor queue statement forms with proper variable substitution and job ad generation.

## Supported Queue Forms

### 1. Simple Queue
```
queue          # Queue 1 job (default)
queue 5        # Queue 5 jobs
```

### 2. Queue from List
```
queue item in (apple, banana, cherry)                    # 3 jobs
queue 2 fruit in (apple, banana)                        # 4 jobs (2 per item)
queue var1, var2 in (a b, c d, e f)                     # 3 jobs with 2 variables
```

### 3. Queue from File
```
queue color from "data.txt"                              # 1 job per line
queue 3 name from "items.txt"                           # 3 jobs per line
queue var1, var2 from "params.csv"                      # Parse each line into variables
```

File format:
- One item per line
- Empty lines and lines starting with `#` are skipped
- Multiple variables can be separated by commas or whitespace

### 4. Queue Matching Files
```
queue matching "*.txt"                                   # 1 job per matching file
queue 2 matching "data*.dat"                            # 2 jobs per matching file
```

The matching form uses glob patterns to find files and queues jobs for each match.

## Implementation Details

### Architecture

The implementation consists of several components:

1. **Parser Enhancement** (`config/parser.y`):
   - Added QUEUE, FROM, IN, MATCHING tokens
   - Grammar rules for all 8 queue statement forms
   - Support for both IDENT and STRING tokens for file paths

2. **Lexer Enhancement** (`config/lexer.go`):
   - Keywords added for queue, from, in, matching
   - Lookahead logic for disambiguating keywords

3. **Iterator Pattern** (`submit_queue.go`):
   - `SubmitIterator` interface for iterating through queue items
   - Four iterator implementations:
     - `simpleIterator`: For `queue [N]`
     - `listIterator`: For `queue in (...)` forms
     - `fileIterator`: For `queue from file` forms
     - `matchingIterator`: For `queue matching pattern` forms

4. **Submit File Parser** (`submit.go`):
   - `ParseSubmitFile()` now extracts queue statements
   - Creates appropriate iterator based on queue form
   - `Submit()` method uses iterator to generate multiple job ads

5. **Variable Substitution**:
   - Queue variables are temporarily added to config during job ad creation
   - Standard HTCondor variables supported:
     - `$(item)` or custom variable names
     - `$(Process)`, `$(Cluster)`
     - `$(ItemIndex)`, `$(Step)`, `$(Row)`

### Job Ad Generation

The `Submit()` method iterates through queue items and creates a job ad for each iteration:

```go
result := sf.Submit(clusterID)
// result.NumProcs = total number of jobs
// result.ProcAds = array of ClassAds, one per job
```

Each job gets a sequential ProcId starting from 0.

## Example Usage

```go
package main

import (
    "strings"
    "github.com/bbockelm/golang-htcondor"
)

func main() {
    submit := `
universe = vanilla
executable = /bin/process
arguments = --input $(datafile)
output = output_$(datafile).txt
error = error_$(datafile).txt
queue datafile in (file1.dat, file2.dat, file3.dat)
`

    sf, err := htcondor.ParseSubmitFile(strings.NewReader(submit))
    if err != nil {
        panic(err)
    }

    result, err := sf.Submit(1000)
    if err != nil {
        panic(err)
    }

    // result.NumProcs == 3
    // result.ProcAds contains 3 job ClassAds with ProcIds 0, 1, 2
}
```

## Testing

Comprehensive test coverage is provided in `submit_queue_test.go`:

- `TestQueueSimple`: Basic queue with default count
- `TestQueueWithCount`: Queue N jobs
- `TestQueueInList`: Queue from inline list
- `TestQueueCountInList`: Queue N jobs per list item
- `TestQueueFromFile`: Queue from file
- `TestQueueCountFromFile`: Queue N jobs per file line
- `TestQueueMatching`: Queue matching glob pattern
- `TestQueueCountMatching`: Queue N jobs per matched file
- `TestQueueVariableSubstitution`: Verify variable substitution works
- `TestQueueMultipleVariablesFromFile`: Multiple variables per line
- `TestQueueNoMatches`: Handle case with no matching files

All tests pass successfully.

## Limitations

The following features are **not yet implemented**:

1. **Queue Slicing**: `queue 10 from itemlist[1:5]`
2. **Multiple Queue Statements**: Only one queue statement per submit file is supported
3. **Command-based From**: `queue from "script.sh |"` (pipe output from command)
4. **Late Materialization**: Jobs are fully materialized at submit time (not lazy)

## Future Work

1. Implement queue slicing syntax for subsetting items
2. Support multiple queue statements in a single submit file
3. Add support for command-based queue sources
4. Implement late materialization for large job counts
5. Add support for foreach variable scoping

## References

- HTCondor Manual: [condor_submit](https://htcondor.readthedocs.io/en/latest/man-pages/condor_submit.html)
- Parser Implementation: `config/parser.y`
- Iterator Implementation: `submit_queue.go`
- Test Suite: `submit_queue_test.go`
