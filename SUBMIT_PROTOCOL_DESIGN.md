# HTCondor Job Submission Protocol Implementation

## Overview

This document describes the initial skeleton implementation of the HTCondor job submission protocol (QMGMT) in the golang-htcondor library. The implementation follows the structure of the official condor_submit tool but is currently incomplete and requires additional work on the CEDAR protocol and authentication layers.

## Files Created

### 1. `schedd_submit.go`

Defines the `QmgmtConnection` type and methods for interacting with a schedd's queue management interface. This is a skeleton implementation with detailed protocol documentation.

**Key Types:**
- `QmgmtConnection`: Represents a connection to the schedd's queue management protocol
- `SetAttributeFlags`: Controls behavior when setting job attributes

**Key Methods:**
- `NewQmgmtConnection()`: Establishes a queue management connection (stub)
- `BeginTransaction()`: Starts a queue management transaction
- `CommitTransaction()`: Commits a transaction
- `AbortTransaction()`: Aborts a transaction
- `NewCluster()`: Allocates a new cluster ID
- `NewProc()`: Allocates a new proc ID within a cluster
- `SetAttribute()`: Sets an attribute on a job or cluster
- `SendJobAttributes()`: Sends all attributes from a ClassAd to the schedd

**Protocol Constants:**
```go
const (
    CONDOR_NewCluster                  = 500
    CONDOR_NewProc                     = 501
    CONDOR_DestroyCluster              = 505
    CONDOR_SetAttribute                = 503
    CONDOR_SetAttributeWithFlags       = 519
    CONDOR_BeginTransaction            = 506
    CONDOR_CommitTransactionNoFlags    = 507
    CONDOR_AbortTransaction            = 508
    CONDOR_GetCapabilities             = 520
    CONDOR_CloseSocket                 = 509
)
```

### 2. `schedd_submit_test.go`

Integration test for job submission that is currently skipped due to missing authentication infrastructure.

**Test: `TestScheddSubmitIntegration`**
- Creates a mini HTCondor environment
- Demonstrates the intended job submission flow
- Currently skipped with clear message about missing dependencies

## QMGMT Protocol

The Queue Management (QMGMT) protocol is used for job submission and modification. It operates over a CEDAR connection after security handshake.

### Protocol Flow for Job Submission

1. Establish TCP connection to schedd
2. Perform `DC_AUTHENTICATE` handshake
3. Send `QMGMT_WRITE_CMD` (1112) to enter queue management mode
4. Send `CONDOR_BeginTransaction` (500)
5. Send `CONDOR_NewCluster` (500) → receives cluster ID
6. Send `CONDOR_NewProc` (501, cluster_id) → receives proc ID
7. Send `CONDOR_SetAttribute` (503, cluster, proc, attr, value) for each attribute
   - Or `CONDOR_SetAttributeWithFlags` (519) with flags
   - Can use `SetAttribute_NoAck` flag to avoid waiting for each ACK
8. Repeat steps 6-7 for additional procs in the cluster
9. Send `CONDOR_CommitTransactionNoFlags` (507)
10. Send `CONDOR_CloseSocket` (509)

### Wire Format

Each QMGMT command follows this format:
```
[Command ID: int32]
[Parameters: varies by command]
[End of Message marker]
```

Response format:
```
[Status Code: int32]  // 0 = success, negative = error
[Error Code: int32]   // if status < 0
[Result Data: varies] // if status >= 0
[End of Message marker]
```

### Example Flow

```
Client -> Schedd: CONDOR_BeginTransaction
Schedd -> Client: status=0

Client -> Schedd: CONDOR_NewCluster
Schedd -> Client: status=ClusterID (e.g., 1001)

Client -> Schedd: CONDOR_NewProc(1001)
Schedd -> Client: status=ProcID (e.g., 0)

Client -> Schedd: CONDOR_SetAttribute(1001, 0, "Cmd", "/bin/sleep")
Schedd -> Client: status=0

Client -> Schedd: CONDOR_SetAttribute(1001, 0, "Args", "60")
Schedd -> Client: status=0

[... more attributes ...]

Client -> Schedd: CONDOR_CommitTransactionNoFlags
Schedd -> Client: status=0
```

## Comparison with Collector Query Protocol

The schedd submit protocol is significantly different from collector queries:

| Aspect | Collector Queries | Schedd Submission |
|--------|------------------|-------------------|
| State | Stateless, single request-response | Stateful, multi-command session |
| Transactions | No transactions | Requires transactions |
| ClassAd Handling | Sends complete ClassAd in query | Sends attributes one-by-one via SetAttribute |
| Authentication | Not required for basic queries | Always required for queue management |
| Commands | Query commands (QUERY_STARTD_ADS, etc.) | QMGMT protocol commands |

## Missing Dependencies

The current implementation is a skeleton that requires the following to be completed:

### 1. CEDAR Protocol Integration

- **ReliSock implementation** for persistent connections
- **Message framing** and encoding/decoding
- **Command sending** and response parsing
- **End-of-message handling**

### 2. Security/Authentication

- **DC_AUTHENTICATE handshake** implementation
- Support for at least one auth method:
  - **FS_REMOTE** (simplest, no credentials needed)
  - **SSL** (requires certificates)
  - **TOKEN** (requires token infrastructure)
- **Session establishment** and encryption setup
- **Security policy negotiation**

### 3. QMGMT Protocol Implementation

- Implement actual wire protocol for each command
- Handle error responses
- Implement parameter encoding for each command type
- Add support for batching and `NoAck` flag

### 4. Integration with Submit Hash

- Refactor `SubmitHash.makeJobAd()` to optionally submit jobs live
- Add option to submit jobs as they are generated vs. returning ClassAds
- Handle queue statements that generate multiple jobs
- Proper transaction management for multi-job submissions

## Reference Materials

### Code References (Included Attachments)

1. **reference/submit.cpp** - Main condor_submit implementation
   - Shows complete job submission flow
   - Demonstrates transaction management
   - Shows attribute ordering and handling

2. **reference/submit_protocol.cpp** - ActualScheddQ implementation
   - Shows how to interact with schedd queue management
   - Implements connection lifecycle
   - Handles capabilities negotiation

3. **reference/qmgmt_send_stubs.cpp** - QMGMT protocol client implementation
   - Wire protocol for each command
   - Response parsing
   - Error handling

### HTCondor Documentation

- **condor_commands.h** - Command constant definitions
- **qmgmt_protocol.h** - QMGMT protocol constants
- **classad_oldnew.cpp** - ClassAd wire format

## Implementation Priority

### High Priority
1. **FS_REMOTE authentication** - Simplest auth method, no tokens/certs needed
2. **Basic QMGMT protocol** - Begin/Commit/NewCluster/NewProc/SetAttribute
3. **ReliSock implementation** - Persistent connections for QMGMT
4. **Integration test enablement** - Remove skip once auth works

### Medium Priority
1. **SetAttribute batching** - Use NoAck flag for performance
2. **Error handling** - Proper error codes and messages
3. **Capabilities negotiation** - Feature discovery
4. **Submit hash integration** - Live job submission from submit files

### Low Priority
1. **Advanced features** - Late materialization, jobsets
2. **Additional auth methods** - SSL, TOKEN
3. **Optimization** - Connection pooling, attribute caching

## Current Status

✅ **Completed:**
- Protocol skeleton and interface definition
- Integration test structure with clear skip message
- Comprehensive protocol documentation
- Command constant definitions

❌ **Not Implemented:**
- CEDAR protocol wire format
- Authentication handshake
- Actual QMGMT command implementation
- ReliSock for persistent connections

## Next Steps

1. **Study the cedar package** to understand what's available
   - Check for ReliSock or similar
   - Look at message framing capabilities
   - Review authentication support

2. **Implement FS_REMOTE authentication**
   - Simplest auth method for testing
   - No external credentials needed
   - Works with local mini HTCondor setup

3. **Implement basic QMGMT commands**
   - Start with BeginTransaction/CommitTransaction
   - Add NewCluster/NewProc
   - Implement SetAttribute

4. **Enable integration test**
   - Remove skip statement
   - Verify end-to-end job submission
   - Add assertions to verify job was created

## Usage Example (Once Implemented)

```go
ctx := context.Background()

// Connect to schedd
qmgmt, err := NewQmgmtConnection(ctx, "localhost", 9618)
if err != nil {
    log.Fatal(err)
}
defer qmgmt.Close()

// Create job ad
jobAd := classad.New()
_ = jobAd.Set("Cmd", "/bin/sleep")
_ = jobAd.Set("Args", "60")
_ = jobAd.Set("Universe", 5) // Vanilla
_ = jobAd.Set("Owner", "testuser")

// Submit job
if err := qmgmt.BeginTransaction(ctx); err != nil {
    log.Fatal(err)
}

clusterID, err := qmgmt.NewCluster(ctx)
if err != nil {
    qmgmt.AbortTransaction(ctx)
    log.Fatal(err)
}

procID, err := qmgmt.NewProc(ctx, clusterID)
if err != nil {
    qmgmt.AbortTransaction(ctx)
    log.Fatal(err)
}

if err := qmgmt.SendJobAttributes(ctx, clusterID, procID, jobAd); err != nil {
    qmgmt.AbortTransaction(ctx)
    log.Fatal(err)
}

if err := qmgmt.CommitTransaction(ctx); err != nil {
    log.Fatal(err)
}

fmt.Printf("Submitted job %d.%d\n", clusterID, procID)
```

## Testing Strategy

1. **Unit tests** - Test individual protocol command encoding/decoding
2. **Integration tests** - Test against real HTCondor daemons
3. **Compatibility tests** - Verify against different HTCondor versions (25.0.0+)
4. **Error handling tests** - Test transaction abort, connection failures, etc.

## Compatibility Notes

- Target HTCondor 25.0.0 and later (modern code paths)
- Stub or error out backward compatibility for older versions
- Focus on standard universe (vanilla) initially
- Extended universe support can be added later

## Conclusion

This implementation provides a well-documented skeleton for HTCondor job submission. The structure is based on the official condor_submit tool and follows HTCondor's QMGMT protocol. While the current implementation is not functional due to missing CEDAR protocol and authentication layers, it provides a clear roadmap for completion and comprehensive documentation for future developers.

The integration test framework is in place and ready to be enabled once the underlying protocol implementation is complete.
