# ClassAd Log Reader Design

## Status

**✅ IMPLEMENTATION COMPLETE** - MVP implementation finished on 2024-11-22

All core components have been implemented:
- ✅ Log entry types and operations (`classadlog/entry.go`)
- ✅ Thread-safe ClassAd collection (`classadlog/collection.go`)
- ✅ Log file parser (`classadlog/parser.go`)
- ✅ File change prober (`classadlog/prober.go`)
- ✅ Reader coordinator (`classadlog/reader.go`)

See `classadlog/README.md` for usage documentation.

## Overview

This document describes the design for a ClassAd log reader in Go that can tail the HTCondor job queue database (usually `job_queue.log`) and reconstruct the state of the schedd queue without querying the schedd directly.

Related to: [Issue #47 - Implement queue database parser](https://github.com/bbockelm/golang-htcondor/issues/47)

Reference implementation: HTCondor's `ClassAdLogReader.cpp` and `ClassAdLogReader.h`

## Goals

1. **Parse job queue log files**: Read and parse HTCondor's `job_queue.log` file format
2. **Maintain in-memory state**: Build and maintain a read-only collection of ClassAds representing the current queue state
3. **Support incremental updates**: Efficiently handle log additions without full reloads
4. **Detect log rotations**: Handle log compression/rotation scenarios
5. **Provide query interface**: Allow querying the in-memory ClassAd collection
6. **Thread-safe access**: Support concurrent reads of the ClassAd collection

## Background: HTCondor Job Queue Log Format

The job queue log is a transaction log containing operations:

- **NewClassAd**: Create a new ClassAd with a key (ClusterId.ProcId)
- **DestroyClassAd**: Delete a ClassAd by key
- **SetAttribute**: Set an attribute value on a ClassAd
- **DeleteAttribute**: Remove an attribute from a ClassAd
- **BeginTransaction/EndTransaction**: Transaction boundaries (can be ignored for reading)
- **LogHistoricalSequenceNumber**: Metadata (can be ignored)

### Key Format

Keys follow the pattern `ClusterId.ProcId`:
- **Cluster ads**: Keys like `01.-1` (ClusterId starts with 0, ProcId is -1)
  - Example: `01.-1` is the cluster ad for cluster 1
  - Cluster ads contain shared attributes for all jobs in the cluster (chaining optimization)
- **Job ads**: Keys like `1.0`, `1.1` (regular ClusterId.ProcId)
  - Example: `1.0` is proc 0 of cluster 1
  - Job ads can chain to cluster ads for shared attributes

### Ordering Guarantees

- No guarantee that cluster ad appears before job ads for that cluster
- No guarantee on order of SetAttribute operations after NewClassAd
- Must handle SetAttribute before NewClassAd gracefully (implementation choice: error or queue)

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                      ClassAdLogReader                        │
│  - Coordinates parsing and state management                 │
│  - Provides public API for queries                          │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ├──────────────────┐
                 │                  │
        ┌────────▼─────────┐  ┌────▼──────────────┐
        │ ClassAdLogParser │  │ ClassAdLogProber  │
        │ - Reads log file │  │ - Detects changes │
        │ - Parses entries │  │ - Handles rotation│
        └──────────────────┘  └───────────────────┘
                 │
                 │
        ┌────────▼─────────────────────────────────┐
        │       ClassAdCollection                   │
        │  - Stores ClassAds in memory             │
        │  - Provides query interface              │
        │  - Thread-safe with RWMutex              │
        └──────────────────────────────────────────┘
```

### File Organization

- `classadlog/reader.go` - Main reader logic and public API
- `classadlog/parser.go` - Log file parsing
- `classadlog/prober.go` - File monitoring and change detection
- `classadlog/collection.go` - In-memory ClassAd storage
- `classadlog/entry.go` - Log entry types and operations
- `classadlog/iterator.go` - Optional iterator interface (if needed)

## Core Types

### LogEntry

```go
package classadlog

import "github.com/PelicanPlatform/classad/classad"

// OpType represents the type of log operation
type OpType int

const (
	OpUnknown OpType = iota
	OpNewClassAd
	OpDestroyClassAd
	OpSetAttribute
	OpDeleteAttribute
	OpBeginTransaction
	OpEndTransaction
	OpLogHistoricalSequenceNumber
)

// LogEntry represents a single operation in the job queue log
type LogEntry struct {
	OpType     OpType
	Key        string // ClusterId.ProcId
	MyType     string // For NewClassAd
	TargetType string // For NewClassAd
	Name       string // For Set/DeleteAttribute
	Value      string // For SetAttribute (unparsed)
}
```

### Reader

```go
// Reader provides access to the job queue state by tailing the log file
type Reader struct {
	filename   string
	parser     *Parser
	prober     *Prober
	collection *Collection
	mu         sync.RWMutex // Protects collection during updates
}

// NewReader creates a new ClassAd log reader
func NewReader(filename string) (*Reader, error)

// Poll checks for changes and updates the in-memory state
// Returns error if unable to read or parse the log
func (r *Reader) Poll(ctx context.Context) error

// Query returns ClassAds matching the constraint
// Projection specifies which attributes to include (nil = all)
func (r *Reader) Query(constraint string, projection []string) ([]*classad.ClassAd, error)

// GetClassAd returns a single ClassAd by key
func (r *Reader) GetClassAd(key string) (*classad.ClassAd, error)

// GetAllKeys returns all ClassAd keys in the collection
func (r *Reader) GetAllKeys() []string

// Close closes the reader and releases resources
func (r *Reader) Close() error
```

### Parser

```go
// Parser reads and parses the job queue log file
type Parser struct {
	filename   string
	file       *os.File
	nextOffset int64
	lastEntry  *LogEntry
}

// NewParser creates a new log parser
func NewParser(filename string) *Parser

// Open opens the log file
func (p *Parser) Open() error

// Close closes the log file
func (p *Parser) Close() error

// ReadEntry reads the next log entry from the file
// Returns io.EOF when end of file is reached
func (p *Parser) ReadEntry() (*LogEntry, error)

// SetNextOffset sets the file offset for the next read
func (p *Parser) SetNextOffset(offset int64)

// GetNextOffset returns the current file offset
func (p *Parser) GetNextOffset() int64
```

### Prober

```go
// ProbeResult indicates what changed in the log file
type ProbeResult int

const (
	ProbeNoChange ProbeResult = iota
	ProbeAddition             // New entries added
	ProbeCompressed           // Log was compressed/rotated - need full reload
	ProbeError                // Recoverable error
	ProbeFatalError           // Unrecoverable error
)

// Prober monitors the log file for changes
type Prober struct {
	lastSize         int64
	lastModTime      time.Time
	lastSeqNumber    int64
	lastCreationTime time.Time
}

// NewProber creates a new log file prober
func NewProber() *Prober

// Probe checks if the log file has changed
func (p *Prober) Probe(filename string, currentOffset int64) (ProbeResult, error)

// Update updates the prober's state after successful read
func (p *Prober) Update(filename string, offset int64)
```

### Collection

```go
// Collection stores ClassAds in memory with thread-safe access
type Collection struct {
	ads map[string]*classad.ClassAd
	mu  sync.RWMutex
}

// NewCollection creates a new ClassAd collection
func NewCollection() *Collection

// Reset clears all ClassAds from the collection
func (c *Collection) Reset()

// NewClassAd creates a new ClassAd with the given key
func (c *Collection) NewClassAd(key, myType, targetType string) error

// DestroyClassAd removes a ClassAd from the collection
func (c *Collection) DestroyClassAd(key string) error

// SetAttribute sets an attribute on a ClassAd
// Creates the ClassAd if it doesn't exist (handles ordering issues)
func (c *Collection) SetAttribute(key, name, value string) error

// DeleteAttribute removes an attribute from a ClassAd
func (c *Collection) DeleteAttribute(key, name string) error

// Get returns a copy of a ClassAd by key (thread-safe)
func (c *Collection) Get(key string) (*classad.ClassAd, error)

// Query returns ClassAds matching the constraint
func (c *Collection) Query(constraint string, projection []string) ([]*classad.ClassAd, error)

// GetAllKeys returns all keys in the collection
func (c *Collection) GetAllKeys() []string

// Len returns the number of ClassAds in the collection
func (c *Collection) Len() int
```

## Implementation Strategy

### Phase 1: Basic Parser (Minimal Viable Product)

1. **Implement LogEntry and OpType** (`entry.go`)
   - Define operation types
   - Parse log entry format (text-based, line-oriented)

2. **Implement Parser** (`parser.go`)
   - Open/close file operations
   - Read log entries sequentially
   - Parse each operation type
   - Handle file offsets

3. **Implement Collection** (`collection.go`)
   - In-memory map storage
   - CRUD operations for ClassAds
   - Thread-safe access with RWMutex
   - Handle attribute parsing (using classad package)

4. **Implement Reader - Basic** (`reader.go`)
   - Initial load (bulk read)
   - Apply log entries to collection
   - Simple query interface

5. **Tests**
   - Unit tests for parser
   - Unit tests for collection operations
   - Integration test with sample log file

### Phase 2: Incremental Updates

1. **Implement Prober** (`prober.go`)
   - File stat monitoring
   - Detect size/mtime changes
   - Detect log rotation/compression

2. **Enhance Reader** (`reader.go`)
   - Poll() method for incremental updates
   - Handle ProbeResult types
   - Optimize incremental reads

3. **Tests**
   - Test incremental updates
   - Test log rotation handling
   - Benchmark performance

### Phase 3: Advanced Features

1. **Query optimization**
   - Efficient constraint evaluation
   - Projection support
   - Index common query patterns (optional)

2. **Iterator interface** (`iterator.go`)
   - If needed for streaming large result sets

3. **Monitoring/Metrics**
   - Track parse errors
   - Track collection size
   - Performance metrics

## Log File Format Details

Based on HTCondor's implementation, the log file format appears to be:

```
# Log entries are line-oriented with operation codes
# Example format (exact format to be determined from HTCondor source):

NewClassAd <key> <mytype> <targettype>
SetAttribute <key> <name> = <value>
DeleteAttribute <key> <name>
DestroyClassAd <key>
BeginTransaction
EndTransaction
```

**Note**: The exact format needs to be verified by examining HTCondor's `ClassAdLogParser` implementation or by inspecting actual `job_queue.log` files.

## Thread Safety

### Reader Access Patterns

- **Poll()**: Exclusive write access (acquires write lock)
- **Query()/GetClassAd()**: Shared read access (acquires read lock)
- **Collection**: Internal RWMutex for thread-safe operations

### Concurrency Model

```
Goroutine 1: Poll() periodically (e.g., every 5 seconds)
Goroutines 2-N: Query() / GetClassAd() as needed
```

The RWMutex allows multiple concurrent readers while ensuring exclusive access during updates.

## Error Handling

### Recoverable Errors
- File temporarily unavailable → retry on next Poll()
- Parse error on single entry → log warning, skip entry
- Unknown operation type → log warning, skip entry

### Unrecoverable Errors
- Malformed log file → return error from Poll()
- Out of memory → return error
- File permissions denied → return error from NewReader()

### Log Rotation
- Detected via Prober → trigger full Reset() and bulk reload

## Performance Considerations

### Memory Usage
- Each ClassAd stored in memory
- Typical schedd: 10,000-100,000 jobs
- Estimate: ~10 KB per job → 100 MB - 1 GB memory
- Consider memory limits for very large schedds

### Parse Performance
- Incremental updates should be fast (< 100ms for typical changes)
- Bulk reload may take seconds for large logs
- File I/O is typically the bottleneck

### Query Performance
- Constraint evaluation on every ClassAd
- O(n) for simple queries (acceptable for n < 100k)
- Consider indexing for specific attributes if needed

## Usage Examples

### Basic Usage

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

### Integration with HTTP API

```go
// In httpserver package
type Server struct {
    logReader *classadlog.Reader
    // ... other fields
}

func (s *Server) handleQueryJobs(w http.ResponseWriter, r *http.Request) {
    constraint := r.URL.Query().Get("constraint")
    projection := r.URL.Query()["projection"]

    jobs, err := s.logReader.Query(constraint, projection)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(jobs)
}

// Background goroutine to poll for updates
func (s *Server) pollLogUpdates(ctx context.Context) {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            if err := s.logReader.Poll(ctx); err != nil {
                log.Printf("Failed to poll log: %v", err)
            }
        }
    }
}
```

## Testing Strategy

### Unit Tests
- Parse individual log entry types
- Collection CRUD operations
- Prober file change detection
- Thread-safety of Collection

### Integration Tests
1. Create sample job_queue.log file
2. Parse and verify ClassAd state
3. Append entries and verify incremental updates
4. Rotate log and verify full reload

### Test Data
- Include realistic job_queue.log samples in `testdata/`
- Cover various job states and attributes
- Include cluster ads with chaining

## Future Enhancements

1. **Write Support**: Currently read-only, could add write operations
2. **Persistence**: Optional disk-backed storage for very large queues
3. **Indexing**: Build indexes on common attributes (Owner, JobStatus)
4. **Change Notifications**: Pub/sub for ClassAd changes
5. **Filtering**: Allow filtering at read time to reduce memory
6. **Compression**: Support reading compressed log files directly

## References

- HTCondor Source: `src/condor_utils/classad_log.*`
- HTCondor Manual: Job Queue Log format
- ClassAd Language: https://htcondor.readthedocs.io/en/latest/classad-attributes/
- Issue #47: https://github.com/bbockelm/golang-htcondor/issues/47

## Open Questions

1. **Exact log format**: Need to verify the precise text format of log entries
2. **Transaction handling**: Should we buffer operations between BeginTransaction/EndTransaction?
3. **Cluster ad chaining**: Do we need to implement ClassAd chaining/inheritance?
4. **Memory limits**: Should we implement limits on collection size?
5. **Consistency**: What guarantees do we provide during updates?

## Decision Log

- **2024-11-22**: Initial design created based on ClassAdLogReader reference
- Use read-only approach (no write support initially)
- Store complete ClassAds in memory (no lazy loading)
- RWMutex for thread-safety
- Polling model (not inotify/fsnotify) for simplicity
