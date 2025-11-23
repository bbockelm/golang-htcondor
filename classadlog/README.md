# ClassAd Log Reader

Package classadlog provides functionality to read and parse HTCondor's job queue log files (`job_queue.log`) and maintain an in-memory collection of ClassAds representing the current state of the schedd queue.

## Status

**Functional MVP Complete** - Related to [Issue #47](https://github.com/bbockelm/golang-htcondor/issues/47)

### Completed
- ✅ Design document (`design_notes/CLASSAD_LOG_READER_DESIGN.md`)
- ✅ Log entry types (`entry.go`)
- ✅ In-memory ClassAd collection with thread-safe access (`collection.go`)
- ✅ Log file parser (`parser.go`)
- ✅ File change prober (`prober.go`)
- ✅ Reader coordinator (`reader.go`)

### TODO
- ⏳ Comprehensive unit tests
- ⏳ Integration tests with real HTCondor log files
- ⏳ Verify log format against actual HTCondor job_queue.log files
- ⏳ Performance testing with large log files
- ⏳ Documentation improvements based on real-world usage

## Components

### entry.go
Defines the log entry operations and types:
- `OpType` enum for log operations (NewClassAd, DestroyClassAd, SetAttribute, etc.)
- `LogEntry` struct representing a single log operation

### collection.go
In-memory ClassAd storage with thread-safe access:
- `Collection` struct with RWMutex for concurrent access
- CRUD operations: NewClassAd, DestroyClassAd, SetAttribute, DeleteAttribute
- Query with constraint evaluation and projection support
- Auto-creates ClassAds when SetAttribute is called before NewClassAd (handles ordering)
- Returns copies of ClassAds to prevent external modifications

### parser.go
Reads and parses HTCondor job queue log files:
- Line-by-line log file reader with buffered I/O
- Parses all log operations (NewClassAd, DestroyClassAd, SetAttribute, DeleteAttribute, etc.)
- Maintains file offset for incremental reads
- Handles comments and empty lines
- Returns `io.EOF` when end of file reached

### prober.go
Monitors log file for changes:
- Detects file additions (new entries)
- Detects compressions/rotations (file truncated or rewritten)
- Tracks file size and modification time
- Returns `ProbeResult` indicating type of change
- `Update()` method to refresh state after successful read

### reader.go
Main coordinator that ties everything together:
- `NewReader()` creates reader for a log file
- `Poll()` checks for changes and updates state
- Handles both full reloads and incremental updates
- Thread-safe with RWMutex (multiple readers, single writer)
- `Query()` with constraint and projection support
- `GetClassAd()`, `GetAllKeys()`, `Len()` accessor methods

## Usage Example (Planned)

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/bbockelm/golang-htcondor/classadlog"
)

func main() {
    // Create reader
    reader, err := classadlog.NewReader("/var/lib/condor/spool/job_queue.log")
    if err != nil {
        panic(err)
    }
    defer reader.Close()

    // Initial load
    ctx := context.Background()
    if err := reader.Poll(ctx); err != nil {
        panic(err)
    }

    // Query for running jobs
    jobs, err := reader.Query("JobStatus == 2", []string{"ClusterId", "ProcId", "Owner"})
    if err != nil {
        panic(err)
    }

    fmt.Printf("Found %d running jobs\n", len(jobs))

    // Poll for updates periodically
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        if err := reader.Poll(ctx); err != nil {
            fmt.Printf("Poll error: %v\n", err)
            continue
        }
        fmt.Printf("Updated. Total jobs: %d\n", reader.Len())
    }
}
```

## Design

See [CLASSAD_LOG_READER_DESIGN.md](../design_notes/CLASSAD_LOG_READER_DESIGN.md) for complete design documentation.

### Key Design Decisions

1. **Read-only**: No support for writing to the log (use schedd QMGMT protocol for submissions)
2. **In-memory**: All ClassAds stored in memory for fast queries
3. **Thread-safe**: RWMutex allows concurrent reads during updates
4. **Polling**: Simple polling model rather than inotify/fsnotify
5. **Copying**: Returns copies of ClassAds to prevent external modifications

### Thread Safety

- `Poll()`: Exclusive write access (acquires write lock)
- `Query()`, `Get()`: Shared read access (acquires read lock)
- Multiple concurrent readers supported
- Only one writer at a time

## Testing

```bash
# Run tests
go test ./classadlog/

# Run with race detector
go test -race ./classadlog/

# Run with coverage
go test -cover ./classadlog/
```

## Log File Format

HTCondor's job queue log is a line-oriented transaction log with operations like:
- `NewClassAd <key> <mytype> <targettype>` - Create a ClassAd
- `SetAttribute <key> <name> = <value>` - Set an attribute
- `DeleteAttribute <key> <name>` - Delete an attribute
- `DestroyClassAd <key>` - Remove a ClassAd
- `BeginTransaction` / `EndTransaction` - Transaction boundaries
- `LogHistoricalSequenceNumber` - Metadata

Note: Exact format to be verified from actual log files or HTCondor source.

### Key Format

Keys follow the pattern `ClusterId.ProcId`:
- **Cluster ads**: `01.-1` (ClusterId starts with 0, ProcId is -1)
  - Contains shared attributes for all jobs in cluster (chaining optimization)
- **Job ads**: `1.0`, `1.1` (regular ClusterId.ProcId)
  - Job ads can chain to cluster ads for shared attributes

## Performance

### Memory
- Each ClassAd stored in memory
- Typical schedd: 10,000-100,000 jobs → 100 MB - 1 GB memory

### Query Performance
- O(n) constraint evaluation (acceptable for n < 100k jobs)
- Consider indexing for very large deployments if needed

## References

- HTCondor Source: `src/condor_utils/classad_log.*`
- Reference implementation: `reference/ClassAdLogReader.{cpp,h}`
- ClassAd Language: https://htcondor.readthedocs.io/en/latest/classad-attributes/
