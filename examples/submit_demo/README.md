# Submit Demo

This example demonstrates how to use the high-level `Schedd.Submit()` API to submit jobs to HTCondor.

## Usage

The new `Schedd.Submit()` method accepts submit file content as a string and returns the cluster ID:

```go
schedd := htcondor.NewSchedd("local", "localhost", 9618)

submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 10
output = test.out
error = test.err
log = test.log
queue
`

clusterID, err := schedd.Submit(ctx, submitFile)
if err != nil {
    log.Fatalf("Failed to submit job: %v", err)
}

fmt.Printf("Submitted job cluster %s\n", clusterID)
```

## Features

- **Simple API**: Just pass submit file content as a string
- **Automatic parsing**: Parses HTCondor submit file format
- **Full queue support**: Supports `queue`, `queue N`, and `queue var from (...)` syntax
- **Transaction handling**: Automatically handles QMGMT protocol and transaction management
- **Error handling**: Automatically aborts transaction on failure

## Examples

### Single Job
```go
submitFile := `
executable = /bin/echo
arguments = "Hello World"
queue
`
```

### Multiple Procs
```go
submitFile := `
executable = /bin/sleep
arguments = $(Process)
queue 5
`
```

### Queue with Variables
```go
submitFile := `
executable = /bin/echo
arguments = "Hello $(name)"
queue name in (Alice, Bob, Charlie)
`
```

## Running the Example

1. Ensure HTCondor is running locally or adjust the host/port
2. Build and run:
   ```bash
   go run main.go
   ```

## Authentication

The example uses FS (filesystem) authentication by default, which is suitable for local HTCondor installations. The authenticated user is automatically determined from the connection negotiation.
