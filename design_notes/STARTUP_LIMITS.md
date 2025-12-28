# HTCondor Startup Limits

Startup limits allow you to control the rate at which jobs matching specific criteria can start in an HTCondor schedd. This is useful for:

- **Rate limiting expensive resources** (GPU jobs, high-memory jobs)
- **Managing cluster load** during peak times
- **Preventing resource exhaustion** from sudden job surges
- **Monitoring job patterns** without enforcement
- **Variable cost allocation** (e.g., large jobs count as multiple small jobs)

## Features

- **Expression-based matching**: Use ClassAd expressions to target specific job types
- **Token bucket algorithm**: Allows bursts while maintaining average rate
- **Variable cost**: Jobs can consume different numbers of tokens based on their attributes
- **Temporary burst capacity**: Allow temporary spikes beyond the base rate
- **Statistics tracking**: Monitor allowed, skipped, and ignored jobs
- **Expiring limits**: Automatically remove limits after a specified time
- **Unlimited monitoring**: Set rate to 0 to track statistics without enforcement

## Quick Start

```go
import "github.com/bbockelm/golang-htcondor"

// Create a schedd connection
schedd := htcondor.NewSchedd("", "schedd.example.com:9618")

// Create a GPU job rate limit: max 10 GPU jobs per minute
req := &htcondor.StartupLimitRequest{
    Tag:        "gpu_limit",
    Name:       "GPU Job Rate Limit",
    Expression: "RequestGpus > 0",
    RateCount:  10,
    RateWindow: 60,
    Expiration: 3600, // expires in 1 hour
}

uuid, err := schedd.CreateStartupLimit(ctx, req)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Created limit with UUID: %s\n", uuid)

// Query all limits
limits, err := schedd.QueryStartupLimits(ctx, "", "")
if err != nil {
    log.Fatal(err)
}
for _, limit := range limits {
    fmt.Printf("%s: %d jobs allowed, %d skipped\n",
        limit.Name, limit.JobsAllowed, limit.JobsSkipped)
}
```

## API Reference

### CreateStartupLimit

Creates or updates a startup rate limit in the schedd.

```go
func (s *Schedd) CreateStartupLimit(ctx context.Context, req *StartupLimitRequest) (string, error)
```

**Parameters:**
- `ctx`: Context (can include security config via `WithSecurityConfig`)
- `req`: Startup limit parameters

**Returns:**
- UUID of the created/updated limit
- Error if the operation fails

**StartupLimitRequest fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `UUID` | string | No | If provided, updates existing limit instead of creating new one |
| `Tag` | string | **Yes** | Unique identifier for this limit type |
| `Name` | string | No | Human-friendly display name (defaults to UUID) |
| `Expression` | string | **Yes** | ClassAd expression to match jobs (e.g., `"RequestGpus > 0"`) |
| `CostExpression` | string | No | Expression for variable cost (default: `"1"`) |
| `RateCount` | int | **Yes** | Maximum jobs (or cost units) per window (0 = unlimited monitoring) |
| `RateWindow` | int | **Yes** | Time window in seconds |
| `Burst` | int | No | Extra capacity allowed below zero (default: 0) |
| `MaxBurstCost` | int | No | Cap on single job's cost (default: unlimited) |
| `Expiration` | int | No | Seconds until limit expires (default: from config) |

### QueryStartupLimits

Queries startup rate limits from the schedd.

```go
func (s *Schedd) QueryStartupLimits(ctx context.Context, uuid, tag string) ([]*StartupLimit, error)
```

**Parameters:**
- `ctx`: Context (can include security config)
- `uuid`: Filter by UUID (empty = all limits)
- `tag`: Filter by tag (empty = all limits)

**Returns:**
- Slice of startup limits matching the query
- Error if the operation fails

**StartupLimit fields:**

| Field | Type | Description |
|-------|------|-------------|
| `UUID` | string | Unique identifier |
| `Tag` | string | Limit type identifier |
| `Name` | string | Display name |
| `Expression` | string | Job matching expression |
| `CostExpression` | string | Variable cost expression |
| `RateCount` | int | Max rate (jobs or cost units per window) |
| `RateWindow` | int | Time window in seconds |
| `Burst` | int | Extra burst capacity |
| `MaxBurstCost` | int | Cap on single job cost |
| `ExpiresAt` | int64 | Unix timestamp when limit expires |
| `JobsAllowed` | int64 | **Stat:** Number of jobs allowed to start |
| `CostAllowed` | float64 | **Stat:** Total cost allowed |
| `JobsSkipped` | int64 | **Stat:** Number of jobs skipped (waiting for tokens) |
| `MatchesIgnored` | int64 | **Stat:** Number of matches ignored (rate limit in effect) |
| `LastIgnored` | int64 | **Stat:** Unix timestamp of last ignored match |
| `IgnoredUsers` | string | **Stat:** Comma-separated list of affected users |

## Usage Examples

### Basic Rate Limiting

Limit GPU jobs to 10 per minute:

```go
req := &htcondor.StartupLimitRequest{
    Tag:        "gpu_limit",
    Expression: "RequestGpus > 0",
    RateCount:  10,
    RateWindow: 60,
}
uuid, err := schedd.CreateStartupLimit(ctx, req)
```

### Variable Cost

Charge jobs based on CPU count (100 CPU-units per minute):

```go
req := &htcondor.StartupLimitRequest{
    Tag:            "cpu_limit",
    Expression:     "RequestCpus >= 1",
    CostExpression: "RequestCpus", // 8-core job costs 8 tokens
    RateCount:      100,
    RateWindow:     60,
}
```

### Burst Capacity

Allow temporary bursts beyond the base rate:

```go
req := &htcondor.StartupLimitRequest{
    Tag:        "memory_limit",
    Expression: "RequestMemory > 16000",
    RateCount:  5,
    RateWindow: 60,
    Burst:      3, // Allow 3 extra jobs even if tokens exhausted
}
```

### Monitoring Without Enforcement

Track statistics without limiting job starts:

```go
req := &htcondor.StartupLimitRequest{
    Tag:        "monitor_vip",
    Expression: `Owner == "alice"`,
    RateCount:  0, // 0 = unlimited, monitoring only
    RateWindow: 0,
}
```

### Capping Individual Jobs

Prevent single large jobs from consuming excessive tokens:

```go
req := &htcondor.StartupLimitRequest{
    Tag:            "fair_cpu",
    Expression:     "RequestCpus >= 1",
    CostExpression: "RequestCpus",
    RateCount:      100,
    RateWindow:     60,
    MaxBurstCost:   16, // Cap single job at 16 CPUs worth of tokens
}
```

### Updating Existing Limits

Specify the UUID to update an existing limit:

```go
req := &htcondor.StartupLimitRequest{
    UUID:       "existing-uuid-here",
    Tag:        "gpu_limit",
    Expression: "RequestGpus > 0",
    RateCount:  20, // Increased from 10
    RateWindow: 60,
}
uuid, err := schedd.CreateStartupLimit(ctx, req)
```

### Querying Statistics

```go
// Get all limits
limits, err := schedd.QueryStartupLimits(ctx, "", "")

for _, limit := range limits {
    if limit.JobsSkipped > 0 {
        fmt.Printf("%s is actively limiting:\n", limit.Name)
        fmt.Printf("  Allowed: %d jobs\n", limit.JobsAllowed)
        fmt.Printf("  Skipped: %d jobs\n", limit.JobsSkipped)
        fmt.Printf("  Ignored: %d matches\n", limit.MatchesIgnored)
    }
}
```

## How It Works

### Token Bucket Algorithm

Startup limits use a token bucket algorithm:

1. **Tokens** represent permission to start jobs
2. Tokens **refill** at a constant rate (`RateCount / RateWindow`)
3. Jobs **consume** tokens when they start (1 token or cost from expression)
4. If tokens are available, the job starts immediately
5. If tokens are exhausted, the job waits for the next negotiation cycle
6. **Burst** allows the bucket to go negative temporarily

### Expression Evaluation

The `Expression` is evaluated against each job's ClassAd to determine if the limit applies:

```
"RequestGpus > 0"           # Matches jobs requesting any GPUs
"RequestMemory > 16000"     # Matches high-memory jobs
"Owner == \"alice\""        # Matches jobs from user alice
"RequestCpus > 8 && RequestGpus > 0"  # Matches large GPU jobs
```

The `CostExpression` determines how many tokens each job consumes:

```
"1"                         # Every job costs 1 token (default)
"RequestCpus"              # Job costs equal to CPU count
"RequestGpus * 10"         # GPU jobs cost 10x more
"RequestMemory / 1000"     # Cost based on memory GB
```

### Statistics and Monitoring

The schedd tracks statistics for each limit:

- **JobsAllowed**: Jobs successfully started (had tokens)
- **JobsSkipped**: Jobs delayed (waiting for tokens)
- **MatchesIgnored**: Total matches that couldn't proceed due to rate limiting
- **CostAllowed**: Total cost of allowed jobs (if using cost expression)
- **LastIgnored**: Timestamp of most recent ignored match
- **IgnoredUsers**: Which users are being affected by the limit

These statistics help you tune rate limits and understand their impact.

## HTCondor Configuration

The schedd supports these configuration parameters:

```
# Maximum expiration time for limits (default: 300 seconds)
STARTUP_LIMIT_MAX_EXPIRATION = 3600

# Ban window after ignored match (default: 60 seconds)
STARTUP_LIMIT_BAN_WINDOW = 60

# Lookahead for throughput throttling (default: 60 seconds)
STARTUP_LIMIT_LOOKAHEAD = 60
```

## Best Practices

1. **Start conservative**: Begin with higher rate limits and tighten if needed
2. **Use monitoring mode first**: Set `RateCount = 0` to observe patterns before enforcing
3. **Add burst capacity**: Small `Burst` values smooth out job submission spikes
4. **Cap large jobs**: Use `MaxBurstCost` to prevent single huge jobs from blocking everything
5. **Set reasonable expirations**: Limits should expire to prevent stale policies
6. **Monitor statistics**: Regularly check `JobsSkipped` and `MatchesIgnored` to tune limits
7. **Use meaningful tags**: Tags should indicate the resource or policy being limited
8. **Document limits**: Use the `Name` field to explain the limit's purpose

## Command Codes

The implementation uses these HTCondor command codes:

- `CREATE_STARTUP_LIMIT` = 559 (`SCHED_VERS + 159`)
- `QUERY_STARTUP_LIMITS` = 560 (`SCHED_VERS + 160`)

## See Also

- [HTCondor Manual - Job Policy Configuration](https://htcondor.readthedocs.io/)
- [Examples](examples/startup_limits_demo/)
- [Tests](schedd_startup_limits_test.go)
