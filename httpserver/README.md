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

#### Prometheus Metrics
```bash
GET /metrics
```

Returns Prometheus-formatted metrics about the HTCondor pool and the server process. Available when a collector is configured.

**Example metrics:**
- `htcondor_pool_machines_total` - Total machines in the pool
- `htcondor_pool_cpus_total` - Total CPU cores
- `htcondor_pool_cpus_used` - Used CPU cores
- `htcondor_pool_memory_mb_total` - Total memory in MB
- `htcondor_pool_jobs_total` - Total jobs
- `process_resident_memory_bytes` - Server memory usage
- `process_goroutines` - Active goroutines

See [../metricsd/README.md](../metricsd/README.md) for complete metrics documentation.

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

#### MCP OAuth2 Configuration

Model Context Protocol (MCP) endpoints require OAuth2 authentication. Enable MCP support with:

```bash
# Enable MCP endpoints (default: false)
HTTP_API_ENABLE_MCP = true

# OAuth2 database path for storing clients and tokens
# Default: $(LOCAL_DIR)/oauth2.db or /var/lib/condor/oauth2.db
HTTP_API_OAUTH2_DB_PATH = /var/lib/condor/oauth2.db

# OAuth2 issuer URL (default: https://$(FULL_HOSTNAME) with non-standard port appended)
# If not explicitly set, the server will append the listen port if it's non-standard (not 443)
HTTP_API_OAUTH2_ISSUER = https://htcondor.example.com

# OIDC/SSO Configuration (optional, for external identity provider)

# Option 1: Use OIDC Discovery (recommended)
# The server will automatically discover auth and token endpoints from the provider
HTTP_API_OAUTH2_IDP = https://idp.example.com

# Option 2: Specify endpoints explicitly
# HTTP_API_OAUTH2_AUTH_URL = https://idp.example.com/auth/realms/master/protocol/openid-connect/auth
# HTTP_API_OAUTH2_TOKEN_URL = https://idp.example.com/auth/realms/master/protocol/openid-connect/token

# OAuth2 client credentials for SSO provider (e.g., Keycloak, Okta, Google)
HTTP_API_OAUTH2_CLIENT_ID = htcondor-api-client

# Client secret is read from a file (not directly in config for security)
# HTCondor configuration is considered public, so secrets must be in separate files
HTTP_API_OAUTH2_CLIENT_SECRET_FILE = /etc/condor/secrets/oauth2_client_secret

# Redirect URL for OAuth2 callback (default: derived from issuer + /oauth2/callback)
# Only set this if you need a different callback URL
# HTTP_API_OAUTH2_REDIRECT_URL = https://htcondor.example.com/oauth2/callback
```

**OIDC Discovery:**

When `HTTP_API_OAUTH2_IDP` is set, the server will fetch the OIDC configuration from:
```
<IDP_URL>/.well-known/openid-configuration
```

This automatically discovers the authorization and token endpoints, making configuration easier and more maintainable. If discovery fails or you prefer explicit configuration, use `HTTP_API_OAUTH2_AUTH_URL` and `HTTP_API_OAUTH2_TOKEN_URL` instead.

**Client Secret File:**

Create a file with your OAuth2 client secret:
```bash
echo "your-secret-here" > /etc/condor/secrets/oauth2_client_secret
chmod 600 /etc/condor/secrets/oauth2_client_secret
chown condor:condor /etc/condor/secrets/oauth2_client_secret
```

**User Header Authentication:**

If `HTTP_API_USER_HEADER` is configured (e.g., from a reverse proxy), the user identity is taken from that header instead of the OAuth2 token subject. This allows integration with existing authentication systems:

```bash
# User identity from reverse proxy header
HTTP_API_USER_HEADER = X-Remote-User

# When both are configured:
# - User identity comes from the header (e.g., X-Remote-User: alice)
# - OAuth2 is still used for authorization and scoping
# - HTCondor tokens are generated for the header-provided username
```

This is useful when running behind Apache with authentication modules, nginx with auth_request, or similar setups where user authentication is handled upstream.

**OIDC/SSO Integration:**

When OIDC/SSO parameters are configured, the HTTP API server can:
1. Redirect users to your identity provider for authentication
2. Handle OAuth2 authorization code flow
3. Exchange authorization codes for access tokens
4. Generate HTCondor tokens based on authenticated identity (or user header if configured)
5. Enable MCP clients to authenticate through your existing SSO infrastructure

**Example OIDC Providers:**

All major OIDC providers support automatic discovery. Set `HTTP_API_OAUTH2_IDP` to the issuer URL, and the server will automatically discover the endpoints:

- **Keycloak**: Popular open-source identity and access management solution
  - IDP URL: `https://keycloak.example.com/auth/realms/{realm}`
  - Or explicit - Auth URL: `https://keycloak.example.com/auth/realms/{realm}/protocol/openid-connect/auth`
  - Token URL: `https://keycloak.example.com/auth/realms/{realm}/protocol/openid-connect/token`

- **Okta**: Enterprise identity service
  - IDP URL: `https://{domain}.okta.com/oauth2/default`
  - Or explicit - Auth URL: `https://{domain}.okta.com/oauth2/default/v1/authorize`
  - Token URL: `https://{domain}.okta.com/oauth2/default/v1/token`

- **Google**: Google OAuth2
  - IDP URL: `https://accounts.google.com`
  - Or explicit - Auth URL: `https://accounts.google.com/o/oauth2/v2/auth`
  - Token URL: `https://oauth2.googleapis.com/token`

- **GitHub**: GitHub OAuth2 (does not support OIDC discovery, use explicit URLs)
  - Auth URL: `https://github.com/login/oauth/authorize`
  - Token URL: `https://github.com/login/oauth/access_token`

- **Azure AD**: Microsoft Azure Active Directory
  - IDP URL: `https://login.microsoftonline.com/{tenant}/v2.0`
  - Or explicit - Auth URL: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`
  - Token URL: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`

**Setting up OIDC Provider (Example with Keycloak):**

1. Create a new client in your OIDC provider with:
   - Client ID: `htcondor-api-client`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`
   - Valid Redirect URIs: `https://htcondor.example.com/oauth2/callback`
   - Web Origins: `https://htcondor.example.com`

2. Configure scopes: `openid`, `profile`, `email`

3. Note the client secret from the credentials tab

4. Add the configuration to HTCondor config file

For complete MCP documentation including OAuth2 flows, see the MCP integration test in `httpserver/mcp_integration_test.go`.

#### Schedd Configuration

```bash
# Schedd configuration (required for normal mode)
SCHEDD_NAME = local
SCHEDD_HOST = 127.0.0.1
SCHEDD_PORT = 9618
```

#### Collector Configuration (Optional - for Metrics)

```bash
# Collector configuration (optional, enables /metrics endpoint)
COLLECTOR_HOST = 127.0.0.1
COLLECTOR_PORT = 9618

# Metrics cache TTL (optional, default: 10s)
METRICS_CACHE_TTL = 10s
```

When collector configuration is provided, the HTTP server automatically:
1. Registers pool and process metrics collectors
2. Exposes metrics at `/metrics` in Prometheus format
3. Caches metrics according to configured TTL

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

#### MCP with OAuth2 and OIDC/SSO Integration

Create `/etc/condor/config.d/99-http-api-mcp.config`:

```bash
# Enable MCP endpoints
HTTP_API_ENABLE_MCP = true

# HTTPS configuration (required for production OAuth2)
HTTP_API_LISTEN_ADDR = :8443
HTTP_API_TLS_CERT = /etc/condor/certs/server.crt
HTTP_API_TLS_KEY = /etc/condor/certs/server.key

# OAuth2 provider configuration
HTTP_API_OAUTH2_DB_PATH = /var/lib/condor/oauth2.db
# Issuer is automatically constructed as https://$(FULL_HOSTNAME):8443
# since port 8443 is non-standard, or set explicitly:
# HTTP_API_OAUTH2_ISSUER = https://htcondor.example.com:8443

# OIDC/SSO provider integration using discovery (recommended)
HTTP_API_OAUTH2_IDP = https://keycloak.example.com/auth/realms/htcondor
HTTP_API_OAUTH2_CLIENT_ID = htcondor-mcp-client
HTTP_API_OAUTH2_CLIENT_SECRET_FILE = /etc/condor/secrets/oauth2_client_secret

# Redirect URL is automatically derived as $(HTTP_API_OAUTH2_ISSUER)/oauth2/callback
# Override only if needed:
# HTTP_API_OAUTH2_REDIRECT_URL = https://htcondor.example.com:8443/oauth2/callback

# HTCondor token generation for authenticated users
HTTP_API_SIGNING_KEY = /etc/condor/keys/POOL
TRUST_DOMAIN = htcondor.example.com
UID_DOMAIN = example.com

# Optional: Use user header from reverse proxy for identity
# HTTP_API_USER_HEADER = X-Remote-User
```

Create the OAuth2 client secret file:
```bash
mkdir -p /etc/condor/secrets
echo "your-keycloak-client-secret" > /etc/condor/secrets/oauth2_client_secret
chmod 600 /etc/condor/secrets/oauth2_client_secret
chown condor:condor /etc/condor/secrets/oauth2_client_secret
```

**OAuth2 Endpoints Available:**

- `GET /oauth2/authorize` - OAuth2 authorization endpoint (redirects to OIDC provider)
- `POST /oauth2/token` - OAuth2 token endpoint (exchanges auth code for access token)
- `POST /oauth2/introspect` - OAuth2 token introspection endpoint
- `POST /mcp` - MCP JSON-RPC endpoint (requires OAuth2 bearer token)

**OAuth2 Flow for MCP Clients:**

1. Client initiates OAuth2 authorization code flow at `/oauth2/authorize`
2. User is redirected to OIDC provider (e.g., Keycloak) for authentication
3. After successful authentication, user is redirected back with authorization code
4. Client exchanges authorization code for access token at `/oauth2/token`
5. Client uses access token to make MCP requests to `/mcp` endpoint

**Example MCP Request with OAuth2:**

```bash
# Step 1: Get authorization code (typically done in browser)
# User visits: https://htcondor.example.com/oauth2/authorize?client_id=htcondor-mcp-client&response_type=code&redirect_uri=https://htcondor.example.com/oauth2/callback&scope=openid

# Step 2: Exchange code for token
curl -X POST https://htcondor.example.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://htcondor.example.com/oauth2/callback&client_id=htcondor-mcp-client&client_secret=your-secret-here"

# Response:
# {
#   "access_token": "eyJhbGc...",
#   "token_type": "Bearer",
#   "expires_in": 3600
# }

# Step 3: Use access token for MCP requests
curl -X POST https://htcondor.example.com/mcp \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "job.submit",
    "params": {
      "submit_file": "executable=/bin/echo\narguments=Hello from MCP\nqueue"
    },
    "id": 1
  }'
```

For detailed MCP protocol documentation, see `mcpserver/README.md`.

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
