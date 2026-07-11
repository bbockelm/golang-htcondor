# Query Fetch Options Implementation

This document describes the implementation of HTCondor's query fetch options in golang-htcondor.

## Overview

Implemented query fetch options from HTCondor's `DCSchedd::makeJobsQueryAd()` to provide fine-grained control over job queries.

## Query Fetch Options

The following fetch options are now available in `QueryOptions`:

### FetchMyJobs (1 << 0)
Filters query results to only jobs owned by the authenticated user.

**Go API:**
```go
opts := &htcondor.QueryOptions{
    FetchOpts: htcondor.FetchMyJobs,
    Owner: "user@domain",
}
```

**HTTP API:** `owned_by_me=true` (default)
```bash
GET /api/v1/jobs?owned_by_me=true
GET /api/v1/jobs?owned_by_me=false  # Query all jobs
```

### FetchSummaryOnly (1 << 1)
Returns summary information instead of individual job ads.

```go
opts := &htcondor.QueryOptions{
    FetchOpts: htcondor.FetchSummaryOnly,
}
```

### FetchIncludeClusterAd (1 << 2)
Includes cluster ads in addition to proc ads.

```go
opts := &htcondor.QueryOptions{
    FetchOpts: htcondor.FetchIncludeClusterAd,
}
```

### FetchIncludeJobsetAds (1 << 3)
Includes jobset ads in the query results.

```go
opts := &htcondor.QueryOptions{
    FetchOpts: htcondor.FetchIncludeJobsetAds,
}
```

### FetchNoProcAds (1 << 4)
Excludes proc ads, only returning cluster/jobset ads.

```go
opts := &htcondor.QueryOptions{
    FetchOpts: htcondor.FetchNoProcAds,
}
```

## HTTP API Changes

### New Query Parameter: `owned_by_me`

**Default:** `true` (for security)

**Values:**
- `true` - Only return jobs owned by the authenticated user (FetchMyJobs)
- `false` - Return all jobs the user has permission to see

**Examples:**
```bash
# Query only my jobs (default)
curl http://localhost:8080/api/v1/jobs

# Query only my jobs (explicit)
curl http://localhost:8080/api/v1/jobs?owned_by_me=true

# Query all jobs (requires appropriate permissions)
curl http://localhost:8080/api/v1/jobs?owned_by_me=false&constraint=true

# Query all jobs with filter
curl http://localhost:8080/api/v1/jobs?owned_by_me=false&constraint=JobStatus==2
```

## Implementation Details

### Go Library (`query_options.go`)

Added `QueryFetchOpts` type and constants:
- `FetchNormal` (0) - Default behavior
- `FetchMyJobs` (1 << 0) - Filter by owner
- `FetchSummaryOnly` (1 << 1) - Summary results
- `FetchIncludeClusterAd` (1 << 2) - Include cluster ads
- `FetchIncludeJobsetAds` (1 << 3) - Include jobset ads
- `FetchNoProcAds` (1 << 4) - Exclude proc ads

Extended `QueryOptions` with:
- `FetchOpts QueryFetchOpts` - Fetch option flags
- `Owner string` - Job owner for FetchMyJobs

### Protocol Implementation (`schedd.go`)

Updated `createJobQueryAd()` to translate fetch options to ClassAd attributes:
- `MyJobs` expression - Implements FetchMyJobs with `(Owner == Me)` constraint
- `Me` attribute - Set to owner username
- `SummaryOnly` - Boolean flag for summary mode
- `IncludeClusterAd` - Boolean flag to include cluster ads
- `IncludeJobsetAds` - Boolean flag to include jobset ads
- `NoProcAds` - Boolean flag to exclude proc ads

### HTTP Handler (`httpserver/handlers.go`)

Added `owned_by_me` query parameter handling:
- Defaults to `true` for security (only show user's jobs)
- Extracts authenticated username from context
- Sets `FetchOpts` and `Owner` in `QueryOptions`

## Security Considerations

**Default Behavior**: `owned_by_me=true`

This default provides security-by-default:
- Users can only see their own jobs by default
- Must explicitly set `owned_by_me=false` to query all jobs
- HTCondor's ACLs still apply - users can only see jobs they have permission to see
- Authenticated username is automatically extracted from context

## Compatibility

Matches HTCondor's C++ implementation in `dc_schedd.cpp`:
- Flag values match the QueryFetchOpts enum
- ClassAd attribute names match HTCondor's protocol
- Behavior is consistent with condor_q and Python bindings

## Future Enhancements

The following fetch options from HTCondor are not yet implemented:
- `fetch_DefaultAutoCluster` - Query default autocluster
- `fetch_GroupBy` - Group results by projection

These can be added when needed.
