# Ping API Implementation Notes

## Current Status

The Ping API currently implements a basic authentication-only check using DC_AUTHENTICATE.
It successfully performs a security handshake and returns authentication information (method, user, session ID, encryption status).

## Required Enhancement: DC_SEC_QUERY with Authorization Checking

To implement the real `condor_ping` API that checks authorization for specific permission levels, we need to use the DC_SEC_QUERY command.

### HTCondor Protocol Flow

From analysis of reference C++ code (`ping.cpp`, `daemon_command.cpp`):

1. Client calls `startSubCommand(DC_SEC_QUERY, permission_level, ...)`
2. The permission level (e.g., DC_NOP_READ, DC_NOP_WRITE) is sent as a **subcommand** parameter during the authentication handshake
3. Server performs both authentication AND authorization check
4. Server responds with a ClassAd containing `SecAuthorizationSucceeded` boolean attribute

### Cedar Library Limitation

The current `cedar` library's `ClientHandshake()` function does not support specifying a subcommand parameter.

**Current cedar signature:**
```go
func (a *Authenticator) ClientHandshake(ctx context.Context) (*NegotiationResult, error)
```

**Required enhancement:**
```go
func (a *Authenticator) ClientHandshakeWithCommand(ctx context.Context, command, subcommand int) (*NegotiationResult, error)
```

Or alternatively, update the existing method to accept optional parameters:
```go
func (a *Authenticator) ClientHandshake(ctx context.Context, opts ...HandshakeOption) (*NegotiationResult, error)

// Where HandshakeOption could include:
type HandshakeOption func(*handshakeConfig)

func WithCommand(cmd, subcmd int) HandshakeOption {
    return func(c *handshakeConfig) {
        c.command = cmd
        c.subcommand = subcmd
    }
}
```

### Implementation Path

1. **Short term (current)**: Keep the basic DC_AUTHENTICATE ping for connection health checks
2. **Medium term**: Enhance cedar library to support subcommands in authentication handshake
3. **Long term**: Update Ping API to use DC_SEC_QUERY with permission checking

### PingResult Enhancement

Once cedar supports subcommands, the PingResult should include:

```go
type PingResult struct {
    // ... existing fields ...
    // Authorized indicates whether the client is authorized for the requested permission level
    Authorized bool
    // Permission is the permission level that was checked (e.g., "READ", "WRITE")
    Permission string
}
```

### Reference Files

- `reference/ping.cpp` (lines 830-865): Shows `startSubCommand()` usage
- `reference/daemon_command.cpp` (lines 1390-1420, 1850-1880): DC_SEC_QUERY server-side handling
- `reference/condor_secman.cpp`: Security handshake protocol details

### Permission Level Mapping

DC_SEC_QUERY uses DC_NOP_* commands as subcommands to specify the permission level:

```go
const (
    DC_NOP_READ               = 60021
    DC_NOP_WRITE              = 60022
    DC_NOP_NEGOTIATOR         = 60023
    DC_NOP_ADMINISTRATOR      = 60024
    DC_NOP_CONFIG             = 60025
    DC_NOP_DAEMON             = 60026
    DC_NOP_ADVERTISE_STARTD   = 60027
    DC_NOP_ADVERTISE_SCHEDD   = 60028
    DC_NOP_ADVERTISE_MASTER   = 60029
)
```

## Action Items

- [ ] File issue/PR in cedar repository to add subcommand support to ClientHandshake
- [ ] Once cedar updated, implement full DC_SEC_QUERY ping with authorization checking
- [ ] Add integration tests for permission-based authorization
- [ ] Update documentation to explain authorization checking capabilities
