# HTCondor HTTP API Server

A RESTful HTTP API server for managing HTCondor jobs.

## Features

- **Job Submission**: Submit jobs via HTTP POST with HTCondor submit file
- **Job Queries**: List and retrieve job details with ClassAd constraints and projections
- **File Transfer**: Upload input files and download output files as tarballs
- **Authentication**: Bearer token authentication forwarded to HTCondor schedd
- **Demo Mode**: Built-in mini HTCondor setup for testing and development
- **OpenAPI**: Full OpenAPI 3.0 specification for API documentation

## Installation

```bash
cd cmd/htcondor-api
go build
```

## Usage

### Normal Mode (with existing HTCondor)

```bash
# Uses HTCondor configuration from environment
./htcondor-api
```

The server will:
1. Read HTCondor configuration from standard locations
2. Connect to the configured schedd
3. Listen on port 8080 (default)

### Demo Mode (standalone mini HTCondor)

```bash
# Starts mini HTCondor automatically
./htcondor-api --demo
```

Demo mode will:
1. Create a temporary directory for mini HTCondor
2. Write minimal HTCondor configuration
3. Start `condor_master` as a subprocess
4. Start the HTTP API server
5. Clean up on Ctrl+C or SIGTERM

#### User Header Authentication (Demo Mode Only)

In demo mode, you can enable automatic token generation based on a custom HTTP header:

```bash
# Enable user header authentication
./htcondor-api --demo --user-header=X-Remote-User
```

With this option:
- If the `Authorization` header is present, it's used as normal
- If no `Authorization` header is present but `X-Remote-User` is set:
  - A signing key is automatically generated
  - A JWT token is created for the username in the header
  - This token is used to authenticate with HTCondor

This is useful for testing with reverse proxies that handle authentication and pass the username via header (e.g., Apache with mod_auth, nginx with auth_request).

**Example:**
```bash
# Submit a job using user header instead of bearer token
curl -X POST http://localhost:8080/api/v1/jobs \
  -H "X-Remote-User: alice" \
  -H "Content-Type: application/json" \
  -d '{"submit_file": "executable=/bin/echo\narguments=Hello\nqueue"}'

# List jobs
curl http://localhost:8080/api/v1/jobs \
  -H "X-Remote-User: alice"
```

**Note:** This feature is only available in demo mode and is intended for development/testing. In production, use proper HTCondor TOKEN authentication.

### Custom Listen Address

```bash
./htcondor-api --listen :9000
```

## API Endpoints

### Job Management

#### Submit a Job
```bash
POST /api/v1/jobs
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "submit_file": "executable = /bin/sleep\narguments = 60\nqueue"
}
```

Response:
```json
{
  "cluster_id": 1,
  "job_ids": ["1.0"]
}
```

#### List Jobs
```bash
GET /api/v1/jobs?constraint=Owner=="user"&projection=ClusterId,ProcId,JobStatus
Authorization: Bearer <TOKEN>
```

Response:
```json
{
  "jobs": [
    {
      "ClusterId": 1,
      "ProcId": 0,
      "JobStatus": 2,
      "Owner": "user"
    }
  ]
}
```

#### Get Job Details
```bash
GET /api/v1/jobs/1.0
Authorization: Bearer <TOKEN>
```

Response:
```json
{
  "ClusterId": 1,
  "ProcId": 0,
  "JobStatus": 2,
  "Owner": "user",
  "Cmd": "/bin/sleep",
  ...
}
```

#### Remove Job (Not Yet Implemented)
```bash
DELETE /api/v1/jobs/1.0
Authorization: Bearer <TOKEN>
```

#### Edit Job (Not Yet Implemented)
```bash
PATCH /api/v1/jobs/1.0
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "JobPrio": 10
}
```

### File Transfer

#### Upload Job Input Files
```bash
PUT /api/v1/jobs/1.0/input
Authorization: Bearer <TOKEN>
Content-Type: application/x-tar

< input.tar
```

The tarball should contain the job's input files as specified in `TransferInputFiles`.

#### Download Job Output Files
```bash
GET /api/v1/jobs/1.0/output
Authorization: Bearer <TOKEN>

> output.tar
```

Returns a tarball containing the job's output files.

### Documentation

#### OpenAPI Schema
```bash
GET /openapi.json
```

Returns the full OpenAPI 3.0 specification.

## Authentication

The server uses HTCondor TOKEN authentication. The bearer token from the HTTP Authorization header is passed to the HTCondor schedd for authentication.

### Getting a Token

```bash
# Generate a token (requires HTCondor admin access)
condor_token_create -identity user@example.com > token.txt

# Use the token in API requests
curl -H "Authorization: Bearer $(cat token.txt)" \
  http://localhost:8080/api/v1/jobs
```

**Note**: Token integration is partially implemented. The token is extracted but not yet fully integrated into the schedd authentication layer. See `HTTP_API_TODO.md` for details.

## Configuration

### Normal Mode

The server reads HTCondor configuration from standard locations:
- `$CONDOR_CONFIG` environment variable
- `/etc/condor/condor_config`
- `~/.condor/user_config`

Required configuration:
- `SCHEDD_HOST`: Schedd hostname or IP
- `SCHEDD_PORT`: Schedd port (default: 9618)
- `SCHEDD_NAME`: Schedd name (optional)

### Demo Mode

Demo mode uses a minimal configuration stored in a temporary directory. The configuration includes:
- All daemons running locally (MASTER, COLLECTOR, NEGOTIATOR, SCHEDD, STARTD)
- TOKEN authentication enabled
- File transfer enabled
- Jobs kept in queue for 24 hours after completion

## Examples

See the `examples/` directory in the repository for:
- Python client examples
- Shell script examples
- Integration examples

## Development

### Project Structure

```
httpserver/
  ├── server.go       # HTTP server setup
  ├── routes.go       # Route configuration
  ├── handlers.go     # Request handlers
  ├── auth.go         # Authentication helpers
  └── openapi.go      # OpenAPI schema

cmd/htcondor-api/
  └── main.go         # Main binary with demo mode
```

### Testing

```bash
# Run with demo mode for testing
go run cmd/htcondor-api/main.go --demo

# In another terminal, test the API
curl http://localhost:8080/openapi.json
```

### Adding Features

See `HTTP_API_TODO.md` for a list of planned features and implementation notes.

## Limitations

Current limitations (see `HTTP_API_TODO.md` for full details):

1. **Authentication**: Token is extracted but not yet integrated into schedd auth
2. **Job Removal**: DELETE endpoint not implemented (requires `schedd.Act()`)
3. **Job Editing**: PATCH endpoint not implemented (requires QMGMT edit API)
4. **Job History**: No support for querying completed jobs
5. **Pagination**: No pagination for large job lists
6. **Bulk Operations**: No support for operating on multiple jobs

## License

See the repository LICENSE file for details.

## Contributing

Contributions are welcome! Please:
1. Check `HTTP_API_TODO.md` for planned features
2. Follow existing code patterns
3. Add tests for new functionality
4. Update documentation

## References

- HTCondor Documentation: https://htcondor.readthedocs.io/
- OpenAPI Specification: https://spec.openapis.org/oas/v3.0.0
- Project Repository: https://github.com/bbockelm/golang-htcondor
