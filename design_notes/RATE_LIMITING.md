# Rate Limiting for HTCondor Queries

## Overview

The golang-htcondor library includes built-in rate limiting capabilities to protect HTCondor schedd and collector daemons from being overwhelmed by excessive queries. Rate limiting is configured via HTCondor configuration parameters and supports both global and per-user limits.

## Configuration

Rate limiting is configured using the following HTCondor configuration parameters:

### Schedd Query Rate Limits

- **`SCHEDD_QUERY_RATE_LIMIT`** (float, default: 0 = unlimited)
  - Maximum number of schedd queries per second from all users combined
  - Example: `SCHEDD_QUERY_RATE_LIMIT = 10` allows 10 queries/second globally

- **`SCHEDD_QUERY_PER_USER_RATE_LIMIT`** (float, default: 0 = unlimited)
  - Maximum number of schedd queries per second per authenticated user
  - Example: `SCHEDD_QUERY_PER_USER_RATE_LIMIT = 5` allows 5 queries/second per user

### Collector Query Rate Limits

- **`COLLECTOR_QUERY_RATE_LIMIT`** (float, default: 0 = unlimited)
  - Maximum number of collector queries per second from all users combined
  - Example: `COLLECTOR_QUERY_RATE_LIMIT = 20` allows 20 queries/second globally

- **`COLLECTOR_QUERY_PER_USER_RATE_LIMIT`** (float, default: 0 = unlimited)
  - Maximum number of collector queries per second per authenticated user
  - Example: `COLLECTOR_QUERY_PER_USER_RATE_LIMIT = 10` allows 10 queries/second per user

### Configuration Notes

- A value of 0 (zero) or unset means unlimited (no rate limiting)
- Negative values are treated as unlimited
- Decimal values are supported (e.g., `0.5` = one query every 2 seconds)
- Rate limits are enforced using a token bucket algorithm with burst allowance

## How It Works

### Rate Limiting Algorithm

The rate limiter uses the token bucket algorithm from `golang.org/x/time/rate`:

1. **Tokens** are added to the bucket at the configured rate (queries per second)
2. **Burst size** is automatically set to 2x the rate to allow short bursts
3. Each query consumes one token
4. If no tokens are available, the query either:
   - Waits until a token becomes available (using `Wait`)
   - Fails immediately (using `Allow`)

### User Identification

- **Authenticated queries**: Username is extracted from the cedar security handshake
- **Unauthenticated queries**: Treated as user `"unauthenticated"`
- **Context-provided username**: Can be set explicitly via `WithAuthenticatedUser(ctx, username)`

### Rate Limit Hierarchy

Rate limits are checked in this order:

1. **Global limit**: Applied to all queries regardless of user
2. **Per-user limit**: Applied to queries from a specific user

Both limits must pass for a query to proceed. For example:
- Global limit: 10 qps
- Per-user limit: 5 qps
- Result: Each user can do 5 qps, but all users combined cannot exceed 10 qps

## Usage Examples

### Basic Configuration

Add to your HTCondor configuration file (e.g., `/etc/condor/condor_config.local`):

```
# Limit schedd queries
SCHEDD_QUERY_RATE_LIMIT = 10
SCHEDD_QUERY_PER_USER_RATE_LIMIT = 5

# Limit collector queries
COLLECTOR_QUERY_RATE_LIMIT = 20
COLLECTOR_QUERY_PER_USER_RATE_LIMIT = 10
```

### Programmatic Usage

The rate limiter is automatically loaded from HTCondor configuration and applied to all queries:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/bbockelm/golang-htcondor"
)

func main() {
    // Rate limits are automatically loaded from HTCondor config
    // No explicit initialization needed
    
    schedd := htcondor.NewSchedd("schedd_name", "schedd.example.com:9618")
    
    ctx := context.Background()
    
    // Query will be rate-limited according to configuration
    jobs, err := schedd.Query(ctx, "true", []string{"ClusterId", "ProcId"})
    if err != nil {
        log.Fatalf("Query failed: %v", err)
    }
    
    fmt.Printf("Found %d jobs\n", len(jobs))
}
```

### Providing User Context

To explicitly set the authenticated user for rate limiting:

```go
import (
    "context"
    "github.com/bbockelm/golang-htcondor"
)

func queryAsUser(username string) error {
    // Create context with authenticated user
    ctx := htcondor.WithAuthenticatedUser(context.Background(), username)
    
    schedd := htcondor.NewSchedd("schedd_name", "schedd.example.com:9618")
    
    // This query will be rate-limited for the specified user
    _, err := schedd.Query(ctx, "true", nil)
    return err
}
```

### Custom Rate Limiter

For applications that need custom rate limiting behavior:

```go
import (
    "github.com/bbockelm/golang-htcondor/config"
    "github.com/bbockelm/golang-htcondor/ratelimit"
)

func setupCustomRateLimiter() {
    // Create custom configuration
    cfg := config.NewEmpty()
    cfg.Set("SCHEDD_QUERY_RATE_LIMIT", "15")
    cfg.Set("SCHEDD_QUERY_PER_USER_RATE_LIMIT", "8")
    
    // Create rate limiter from config
    manager := ratelimit.ConfigFromHTCondor(cfg)
    
    // Check if a user is allowed to query
    username := "alice"
    if err := manager.AllowSchedd(username); err != nil {
        // Rate limit exceeded
        return
    }
    
    // Or wait for rate limit to clear
    ctx := context.Background()
    if err := manager.WaitSchedd(ctx, username); err != nil {
        // Context cancelled or error
        return
    }
}
```

## Rate Limiting Behavior

### Burst Handling

The rate limiter allows short bursts of queries:

- **Burst size** = 2 × rate limit
- Example: With a rate limit of 10 qps, up to 20 queries can be made immediately
- After the burst, queries proceed at the configured rate

### Waiting vs Rejecting

The library uses the **Wait** strategy by default:

- Queries that exceed the rate limit will **block** until tokens are available
- This provides backpressure and prevents overwhelming the backend
- Context cancellation is respected - query fails if context is cancelled while waiting

### Error Messages

When rate limits are exceeded:

```
rate limit exceeded: global rate limit exceeded
rate limit exceeded: rate limit exceeded for user alice
rate limit exceeded: rate limit wait cancelled for user alice: context deadline exceeded
```

## Monitoring and Statistics

Get statistics about current rate limiter state:

```go
import "github.com/bbockelm/golang-htcondor/ratelimit"

func getRateLimitStats() {
    // Assuming you have access to the manager
    var manager *ratelimit.Manager
    
    scheddStats := manager.GetScheddStats()
    fmt.Printf("Schedd rate limiter:\n")
    fmt.Printf("  Global rate: %.2f qps\n", scheddStats.GlobalRate)
    fmt.Printf("  Per-user rate: %.2f qps\n", scheddStats.PerUserRate)
    fmt.Printf("  Active users: %d\n", scheddStats.UserCount)
    fmt.Printf("  Available tokens: %.2f\n", scheddStats.GlobalTokens)
    
    collectorStats := manager.GetCollectorStats()
    fmt.Printf("Collector rate limiter:\n")
    fmt.Printf("  Global rate: %.2f qps\n", collectorStats.GlobalRate)
    fmt.Printf("  Per-user rate: %.2f qps\n", collectorStats.PerUserRate)
    fmt.Printf("  Active users: %d\n", collectorStats.UserCount)
}
```

## Best Practices

### Choosing Rate Limits

1. **Start with monitoring**: Monitor your schedd/collector query load before setting limits
2. **Set global limits first**: Start with global limits to protect the overall system
3. **Add per-user limits**: Add per-user limits to prevent individual users from monopolizing resources
4. **Leave headroom**: Set limits below the maximum capacity of your daemons
5. **Test thoroughly**: Test rate limits in a staging environment before production

### Recommended Starting Values

For a typical HTCondor installation:

```
# Conservative limits for most installations
SCHEDD_QUERY_RATE_LIMIT = 10
SCHEDD_QUERY_PER_USER_RATE_LIMIT = 5
COLLECTOR_QUERY_RATE_LIMIT = 20
COLLECTOR_QUERY_PER_USER_RATE_LIMIT = 10
```

Adjust based on:
- Number of users
- Expected query frequency
- Hardware capabilities of schedd/collector hosts
- Monitoring data

### Integration with HTTP API

If using the HTTP API server (httpserver package), rate limits are automatically applied to all API queries. The authenticated username is extracted from:

1. Bearer token authentication (if configured)
2. User header (if configured and token generation is enabled)
3. Falls back to "unauthenticated" if no authentication

## Troubleshooting

### Rate Limiting Not Working

1. **Check configuration loading**:
   ```go
   cfg := htcondor.GetDefaultConfig()
   if cfg == nil {
       // Configuration not loaded
   }
   ```

2. **Verify configuration values**:
   - Ensure values are positive numbers
   - Check for typos in parameter names
   - Use `condor_config_val` to verify HTCondor sees the values

3. **Check for unlimited settings**:
   - A value of 0 means unlimited
   - Ensure you set both global and per-user limits if needed

### Queries Failing with Rate Limit Errors

1. **Check current load**: Too many concurrent users/queries
2. **Increase limits**: If legitimate load exceeds current limits
3. **Implement retry logic**: Add exponential backoff for applications
4. **Distribute load**: Spread queries across time or multiple schedds

### Performance Impact

Rate limiting has minimal performance impact:

- Token bucket operations are O(1)
- Per-user limiters are created lazily
- Concurrent access is safe with read-write locks
- No additional network calls

## Advanced Topics

### Reloading Configuration

To reload rate limits from HTCondor configuration:

```go
import "github.com/bbockelm/golang-htcondor"

// Reload configuration and rate limiters
htcondor.ReloadDefaultConfig()
```

This will:
1. Reload HTCondor configuration from disk
2. Create new rate limiters with updated settings
3. Reset all per-user rate limit counters

### Disabling Rate Limiting

To disable rate limiting, set all limits to 0:

```
SCHEDD_QUERY_RATE_LIMIT = 0
SCHEDD_QUERY_PER_USER_RATE_LIMIT = 0
COLLECTOR_QUERY_RATE_LIMIT = 0
COLLECTOR_QUERY_PER_USER_RATE_LIMIT = 0
```

Or simply don't set these parameters (they default to 0).

## Implementation Details

### Package Structure

- **`ratelimit/ratelimit.go`**: Core rate limiting implementation
- **`ratelimit/config.go`**: HTCondor configuration loading
- **`security.go`**: Global rate limiter management
- **`schedd.go`**: Schedd query rate limiting integration
- **`collector.go`**: Collector query rate limiting integration

### Thread Safety

The rate limiter is fully thread-safe:

- Token bucket operations are atomic
- Per-user limiter map uses read-write locks
- Safe for concurrent use from multiple goroutines

### Testing

- **Unit tests**: `ratelimit/ratelimit_test.go`, `ratelimit/config_test.go`
- **Integration tests**: `ratelimit_integration_test.go`
- Run tests: `go test ./ratelimit/`
- Run integration tests: `go test -v ./... -run TestScheddQueryRateLimit`

## See Also

- [HTCondor Configuration](https://htcondor.readthedocs.io/en/latest/admin-manual/configuration-macros.html)
- [golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate)
- [Token Bucket Algorithm](https://en.wikipedia.org/wiki/Token_bucket)
