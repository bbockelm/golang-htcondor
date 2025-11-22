# Query Optimization Features

This document describes the query optimization features added to lighten default queries and improve performance.

## Overview

The HTCondor Go API now supports:
- **Default result limits** (50 results by default)
- **Default projections** (returning only essential attributes)
- **Pagination support** (for large result sets)
- **Opt-in for unlimited results** (use `*` or `-1`)

## Default Limits

Both job queries and collector queries now return a maximum of **50 results by default**. This prevents accidentally overwhelming clients with thousands of results.

### REST API

```bash
# Get up to 50 jobs (default)
curl http://localhost:8080/api/v1/jobs

# Get up to 100 jobs
curl http://localhost:8080/api/v1/jobs?limit=100

# Get ALL jobs (unlimited)
curl "http://localhost:8080/api/v1/jobs?limit=*"
```

### MCP API

```json
{
  "method": "tools/call",
  "params": {
    "name": "query_jobs",
    "arguments": {
      "constraint": "Owner == \"alice\"",
      "limit": 100
    }
  }
}
```

### Go API

```go
// Using the new QueryWithOptions method
opts := &htcondor.QueryOptions{
    Limit: 100,  // or -1 for unlimited
}
jobs, pageInfo, err := schedd.QueryWithOptions(ctx, "true", opts)

// Old method still works (no limit applied)
jobs, err := schedd.Query(ctx, "true", nil)
```

## Default Projections

To reduce network traffic and processing time, queries now return a limited set of common attributes by default.

### Default Job Attributes

- `ClusterId`
- `ProcId`
- `Owner`
- `JobStatus`
- `Cmd`
- `Args`

### Default Collector Attributes

- `Name`
- `Machine`
- `MyType`
- `State`
- `Activity`
- `MyAddress`

### REST API

```bash
# Get jobs with default attributes
curl http://localhost:8080/api/v1/jobs

# Get jobs with ALL attributes
curl "http://localhost:8080/api/v1/jobs?projection=*"

# Get jobs with specific attributes
curl "http://localhost:8080/api/v1/jobs?projection=ClusterId,ProcId,Owner,JobStatus,RequestCpus"
```

### MCP API

```json
{
  "method": "tools/call",
  "params": {
    "name": "query_jobs",
    "arguments": {
      "constraint": "true",
      "projection": ["ClusterId", "ProcId", "Owner", "JobStatus"]
    }
  }
}
```

### Go API

```go
// Use default projection
opts := &htcondor.QueryOptions{}
jobs, pageInfo, err := schedd.QueryWithOptions(ctx, "true", opts)

// Get all attributes
opts := &htcondor.QueryOptions{
    Projection: []string{"*"},
}
jobs, pageInfo, err := schedd.QueryWithOptions(ctx, "true", opts)

// Get specific attributes
opts := &htcondor.QueryOptions{
    Projection: []string{"ClusterId", "ProcId", "Owner"},
}
jobs, pageInfo, err := schedd.QueryWithOptions(ctx, "true", opts)
```

## Pagination

Pagination support allows fetching large result sets in chunks. The infrastructure is in place, though HTCondor's native pagination support is limited.

### REST API

```bash
# First page (up to 50 results)
curl http://localhost:8080/api/v1/jobs

# Response includes pagination info:
# {
#   "jobs": [...],
#   "total_returned": 50,
#   "has_more": false,
#   "next_page_token": ""
# }
```

### Go API

```go
opts := &htcondor.QueryOptions{
    Limit: 50,
    PageToken: "", // empty for first page
}
jobs, pageInfo, err := schedd.QueryWithOptions(ctx, "true", opts)

fmt.Printf("Returned: %d, Has more: %v\n",
    pageInfo.TotalReturned, pageInfo.HasMoreResults)
```

## Backward Compatibility

### Deprecated Methods

The original `Query()` and `QueryAdsWithProjection()` methods are still available but marked as deprecated:

```go
// Still works, but deprecated
jobs, err := schedd.Query(ctx, "true", nil)

// Use this instead
jobs, pageInfo, err := schedd.QueryWithOptions(ctx, "true", nil)
```

### Migration Guide

**Before:**
```go
jobs, err := schedd.Query(ctx, "true", []string{"ClusterId", "ProcId"})
```

**After:**
```go
opts := &htcondor.QueryOptions{
    Projection: []string{"ClusterId", "ProcId"},
}
jobs, pageInfo, err := schedd.QueryWithOptions(ctx, "true", opts)
```

## Performance Benefits

1. **Reduced Network Traffic**: Default projections return only 6 attributes instead of all ~200+ possible attributes
2. **Faster Queries**: Limiting results to 50 by default prevents long-running queries
3. **Lower Memory Usage**: Smaller result sets consume less memory on both client and server
4. **Better Scalability**: Pagination allows handling arbitrarily large job queues

## Examples

### Get recent jobs with minimal attributes
```bash
curl "http://localhost:8080/api/v1/jobs?constraint=JobStatus==2&limit=10&projection=ClusterId,ProcId,Owner"
```

### Get all jobs with all attributes (careful!)
```bash
curl "http://localhost:8080/api/v1/jobs?limit=*&projection=*"
```

### Get collector ads for schedds
```bash
curl "http://localhost:8080/api/v1/collector/ads/schedd?limit=20"
```

## Configuration

These defaults are applied at the API level and don't require any HTCondor configuration changes. The defaults are:

- **Default Limit**: 50 results
- **Unlimited**: Use `limit=*` (REST) or `limit=-1` (Go)
- **Default Job Projection**: 6 attributes (ClusterId, ProcId, Owner, JobStatus, Cmd, Args)
- **Default Collector Projection**: 6 attributes (Name, Machine, MyType, State, Activity, MyAddress)
- **All Attributes**: Use `projection=*` (REST) or `[]string{"*"}` (Go)
