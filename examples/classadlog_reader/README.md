# ClassAd Log Reader Example

This example demonstrates how to use the `classadlog` package to read and monitor HTCondor job queue logs.

## Overview

The program reads HTCondor's `job_queue.log` file, which contains a transaction log of all job queue operations (job submissions, attribute changes, job removals, etc.). It can run in two modes:

1. **One-shot mode**: Read the log once, display current state, and exit
2. **Continuous monitoring**: Poll the log file periodically for updates

## Usage

```bash
# Build the example
go build

# Read log once and display summary
./classadlog_reader -log /var/lib/condor/spool/job_queue.log -once

# Continuous monitoring (default: poll every 5 seconds)
./classadlog_reader -log /var/lib/condor/spool/job_queue.log

# Custom poll interval
./classadlog_reader -log /var/lib/condor/spool/job_queue.log -interval 10s

# Filter jobs with a constraint
./classadlog_reader -log /var/lib/condor/spool/job_queue.log -constraint 'Owner == "alice"'

# Filter by job status (1=Idle, 2=Running, 4=Completed, 5=Held)
./classadlog_reader -log /var/lib/condor/spool/job_queue.log -constraint 'JobStatus == 2'
```

## Command-Line Flags

- `-log` - Path to job_queue.log file (default: `/var/lib/condor/spool/job_queue.log`)
- `-interval` - Poll interval for updates (default: `5s`)
- `-constraint` - ClassAd constraint for filtering jobs (default: empty = all jobs)
- `-once` - Read once and exit instead of continuous polling (default: `false`)

## Output

The program displays:
- Total number of jobs in the queue
- Number of jobs matching the constraint (if specified)
- Job counts by status (Idle, Running, Completed, Held, etc.)
- Job counts by owner

Example output:
```
Reading HTCondor job queue log: /var/lib/condor/spool/job_queue.log

[15:04:05] Total jobs in queue: 42

Jobs by status:
  Idle: 15
  Running: 20
  Completed: 5
  Held: 2

Jobs by owner:
  alice: 25
  bob: 12
  charlie: 5

Polling every 5s for updates... (press Ctrl+C to exit)
```

## How It Works

1. **Initialization**: Creates a `classadlog.Reader` instance for the log file
2. **Initial Poll**: Calls `reader.Poll(ctx)` to read the entire log and build in-memory state
3. **Query**: Uses `reader.Query(constraint, projection)` to retrieve jobs matching criteria
4. **Continuous Updates**: Periodically calls `reader.Poll(ctx)` to detect and apply incremental changes
5. **Summary**: Computes statistics from the ClassAd collection

The `classadlog` package automatically handles:
- Reading the transaction log format
- Applying operations (NewClassAd, SetAttribute, DestroyClassAd, etc.)
- Maintaining thread-safe in-memory collection
- Detecting file changes vs. log rotations
- Incremental updates (only reads new entries on subsequent polls)

## Finding the Log File

The default log location is `/var/lib/condor/spool/job_queue.log`, but your HTCondor installation may use a different path. To find it:

```bash
# Query HTCondor config
condor_config_val SPOOL

# The log is typically at $(SPOOL)/job_queue.log
```

## Requirements

- HTCondor schedd running (to generate the log file)
- Read access to the job_queue.log file
- The log file can be large; the program efficiently handles incremental updates

## See Also

- [classadlog package documentation](../../classadlog/README.md)
- [ClassAd Log Reader Design](../../design_notes/CLASSAD_LOG_READER_DESIGN.md)
- [HTCondor job_queue.log format](../../design_notes/CLASSAD_LOG_READER_DESIGN.md#log-format)
