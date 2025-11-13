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

### HTCondor Configuration Parameters

The HTTP API server reads configuration from HTCondor's configuration system. Configuration can be placed in `/etc/condor/config.d/` or any HTCondor configuration file.

#### HTTP Server Parameters

```bash
# Listen address (default: :8080)
HTTP_API_LISTEN_ADDR = :8443

# TLS/HTTPS configuration (optional - both required for TLS)
HTTP_API_TLS_CERT = /etc/condor/certs/server.crt
HTTP_API_TLS_KEY = /etc/condor/certs/server.key

# HTTP timeout configuration (optional, duration strings)
HTTP_API_READ_TIMEOUT = 30s      # Default: 30s
HTTP_API_WRITE_TIMEOUT = 30s     # Default: 30s
HTTP_API_IDLE_TIMEOUT = 2m       # Default: 120s

# User header for authentication (optional)
HTTP_API_USER_HEADER = X-Forwarded-User

# JWT signing key path (optional, demo mode only)
HTTP_API_SIGNING_KEY = /etc/condor/keys/jwt_signing.key
```

#### Schedd Configuration

```bash
# Schedd configuration (required for normal mode)
SCHEDD_NAME = local
SCHEDD_HOST = 127.0.0.1
SCHEDD_PORT = 9618
```

### Configuration Examples

#### Basic HTTP Server

Create `/etc/condor/config.d/99-http-api.config`:

```bash
HTTP_API_LISTEN_ADDR = :8080
```

Start the server:

```bash
./htcondor-api --mode=normal
```

#### HTTPS Server with TLS

Create `/etc/condor/config.d/99-http-api.config`:

```bash
HTTP_API_LISTEN_ADDR = :8443
HTTP_API_TLS_CERT = /etc/condor/certs/server.crt
HTTP_API_TLS_KEY = /etc/condor/certs/server.key
HTTP_API_READ_TIMEOUT = 45s
HTTP_API_WRITE_TIMEOUT = 45s
HTTP_API_IDLE_TIMEOUT = 5m
```

Generate self-signed certificates (for testing):

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

Start the server:

```bash
./htcondor-api --mode=normal
```

The server will listen on port 8443 with HTTPS.

#### Behind Reverse Proxy

If running behind a reverse proxy that sets authentication headers:

```bash
HTTP_API_LISTEN_ADDR = 127.0.0.1:8080
HTTP_API_USER_HEADER = X-Forwarded-User
HTTP_API_READ_TIMEOUT = 60s
HTTP_API_WRITE_TIMEOUT = 60s
```

### Command Line Options

Command-line flags override HTCondor configuration:

```bash
# Override listen address
./htcondor-api --mode=normal --listen=:9090

# Override user header
./htcondor-api --mode=normal --user-header=X-Auth-User
```

### Demo Mode

Demo mode uses a minimal configuration stored in a temporary directory. The configuration includes:
- All daemons running locally (MASTER, COLLECTOR, NEGOTIATOR, SCHEDD, STARTD)
- TOKEN authentication enabled
- File transfer enabled
- Jobs kept in queue for 24 hours after completion

```bash
# Start in demo mode
./htcondor-api --demo

# Demo mode with custom listen address
./htcondor-api --demo --listen=:9090
```

For complete configuration examples, see `examples/http_api_config/`.

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

## Current Status

The HTTP API server implements the following features (see `HTTP_API_TODO.md` for complete details):

✅ **Completed:**
- Bearer token authentication integrated with HTCondor schedd
- Job submission via HTTP POST
- Job queries with constraint and projection support
- Individual job removal (DELETE /api/v1/jobs/{id})
- Individual job editing (PATCH /api/v1/jobs/{id})
- Bulk job operations (DELETE/PATCH /api/v1/jobs with constraints)
- File transfer (upload input, download output)
- Configuration via HTCondor config system
- TLS/HTTPS support
- Configurable HTTP timeouts

⏳ **Pending:**
- Job history support (querying completed jobs)
- Job status monitoring (SSE/WebSocket for real-time updates)
- Enhanced demo mode (auto-generated tokens, test jobs)
- Metrics and monitoring (Prometheus endpoint)

See `HTTP_API_TODO.md` for detailed implementation notes and examples.

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
