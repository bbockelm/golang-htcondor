# Schedd Address Update Example

This example demonstrates the automatic schedd address update feature in the HTTP server.

## Overview

The HTTP server can automatically update the schedd address when:
1. The schedd address is discovered from the collector (not provided explicitly)
2. The collector is available for periodic queries

When these conditions are met, the server queries the collector approximately every 60 seconds to check for address changes.

## Usage

### Explicit Address (No Updates)

When you provide an explicit schedd address, the server uses it as-is and does not check for updates:

```go
server, err := httpserver.NewServer(httpserver.Config{
    ListenAddr: ":8080",
    ScheddName: "my-schedd",
    ScheddAddr: "127.0.0.1:9618", // Fixed address
})
```

### Discovered Address (Automatic Updates)

When you leave the schedd address empty, the server discovers it from the collector and automatically updates it:

```go
collector := htcondor.NewCollector("localhost")

server, err := httpserver.NewServer(httpserver.Config{
    ListenAddr: ":8081",
    ScheddName: "my-schedd",
    ScheddAddr: "", // Will be discovered
    Collector:  collector,
})
```

## Implementation Details

- **Update Interval**: ~60 seconds
- **Thread Safety**: All schedd access is protected by a read-write mutex
- **Graceful Shutdown**: The update goroutine stops cleanly when the server shuts down
- **Logging**: Address changes are logged with old and new addresses

## Running the Example

```bash
go run main.go
```

Note: This example requires a running HTCondor collector to work properly. If no collector is available, it will demonstrate the concept but discovery will fail.

## When to Use

Use automatic address updates when:
- Your schedd may move to different addresses (e.g., due to restarts)
- You're running in a dynamic environment (e.g., Kubernetes, cloud)
- You want resilience against schedd address changes

Use explicit addresses when:
- The schedd address is stable and won't change
- You want to avoid periodic collector queries
- You're running in a static environment
