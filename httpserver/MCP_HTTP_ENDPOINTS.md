# MCP HTTP Endpoints

This document describes the HTTP endpoints for accessing the Model Context Protocol (MCP) server via HTTP with OAuth2 authentication.

## Overview

The HTCondor HTTP API server can expose MCP functionality via HTTP endpoints with OAuth2 authentication. This allows AI assistants like ChatGPT to interact with HTCondor to submit and manage jobs.

## Configuration

To enable MCP endpoints, configure the HTTP server with these options:

```go
server, err := httpserver.NewServer(httpserver.Config{
    ListenAddr:   ":8080",
    EnableMCP:    true,                    // Enable MCP endpoints
    OAuth2DBPath: "/path/to/oauth2.db",    // SQLite database for OAuth2 tokens
    OAuth2Issuer: "http://localhost:8080", // OAuth2 issuer URL
    // ... other config options
})
```

In demo mode, MCP is automatically enabled:

```bash
./htcondor-api --demo
```

## OAuth2 Authentication

All MCP endpoints require OAuth2 authentication using the Bearer token scheme.

### OAuth2 Endpoints

#### Authorization Endpoint

```
GET /mcp/oauth2/authorize
```

Initiates the OAuth2 authorization flow. Supports authorization code grant type.

#### Token Endpoint

```
POST /mcp/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=REDIRECT_URI&client_id=CLIENT_ID&client_secret=CLIENT_SECRET
```

Obtains an access token using authorization code flow.

**Supported Scopes:**
- `openid`, `profile`, `email` - Standard OpenID Connect scopes
- `mcp:read`, `mcp:write` - MCP-specific scopes for job management
- `condor:/READ`, `condor:/WRITE`, `condor:/ADVERTISE_STARTD`, `condor:/ADVERTISE_SCHEDD`, `condor:/ADVERTISE_MASTER` - HTCondor authorization scopes

**HTCondor IDTOKEN Support:**

When requesting one or more `condor:/*` scopes, the OAuth2 token endpoint returns an HTCondor IDTOKEN (JWT) as the access token. This IDTOKEN can be used directly with HTCondor daemons for authentication and authorization.

The condor scopes map 1-to-1 to HTCondor authorization levels. Each `condor:/FOO` scope grants the `FOO` authorization level in the resulting IDTOKEN.

Example workflow for obtaining an IDTOKEN:

1. Initiate authorization code flow with condor scopes:
```bash
# Browser redirects to:
http://localhost:8080/mcp/oauth2/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&scope=condor:/READ+condor:/WRITE&state=STATE
```

2. Exchange authorization code for IDTOKEN:
```bash
curl -X POST http://localhost:8080/mcp/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=REDIRECT_URI" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsImtpZCI6IlBPT0wiLCJ0eXAiOiJKV1QifQ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "condor:/READ condor:/WRITE",
  "refresh_token": "..."
}
```

When `condor:/*` scopes are requested, the `access_token` is an HTCondor IDTOKEN (JWT) that can be used directly with HTCondor daemons. For other scopes, the `access_token` is a standard OAuth2 token.

#### Token Introspection Endpoint

```
POST /mcp/oauth2/introspect
Content-Type: application/x-www-form-urlencoded

token=ACCESS_TOKEN
```

Introspects an access token to check its validity and get metadata.

#### Token Revocation Endpoint

```
POST /mcp/oauth2/revoke
Content-Type: application/x-www-form-urlencoded

token=ACCESS_TOKEN
```

Revokes an access token.

## MCP Protocol Endpoint

### Send MCP Message

```
POST /mcp/message
Authorization: Bearer ACCESS_TOKEN
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "METHOD_NAME",
  "params": {...}
}
```

Sends an MCP protocol message. The request body is a JSON-RPC 2.0 message.

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {...}
}
```

Or in case of error:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "Error description"
  }
}
```

## MCP Methods

### initialize

Initializes the MCP connection.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {
      "name": "client-name",
      "version": "1.0"
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {},
      "resources": {}
    },
    "serverInfo": {
      "name": "htcondor-mcp",
      "version": "0.1.0"
    }
  }
}
```

### tools/list

Lists available MCP tools.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list"
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "submit_job",
        "description": "Submit an HTCondor job using a submit file",
        "inputSchema": {...}
      },
      {
        "name": "query_jobs",
        "description": "Query HTCondor jobs with optional constraints and projections",
        "inputSchema": {...}
      },
      ...
    ]
  }
}
```

### tools/call

Calls an MCP tool.

**Request (submit_job example):**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "submit_job",
    "arguments": {
      "submit_file": "executable = /bin/echo\narguments = Hello World\nqueue"
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Successfully submitted job cluster 123 with 1 proc(s): 123.0"
      }
    ],
    "metadata": {
      "cluster_id": 123,
      "job_ids": ["123.0"]
    }
  }
}
```

**Request (query_jobs example):**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "query_jobs",
    "arguments": {
      "constraint": "ClusterId == 123",
      "projection": ["ClusterId", "ProcId", "Owner", "JobStatus"]
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Found 1 job(s) matching constraint 'ClusterId == 123':\n[{...}]"
      }
    ],
    "metadata": {
      "count": 1,
      "constraint": "ClusterId == 123"
    }
  }
}
```

### resources/list

Lists available MCP resources.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "resources/list"
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "resources": [
      {
        "uri": "condor://schedd/status",
        "name": "Schedd Status",
        "description": "Current status and information about the HTCondor schedd",
        "mimeType": "application/json"
      }
    ]
  }
}
```

### resources/read

Reads an MCP resource.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "resources/read",
  "params": {
    "uri": "condor://schedd/status"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "contents": [
      {
        "uri": "condor://schedd/status",
        "mimeType": "application/json",
        "text": "{...schedd ad...}"
      }
    ]
  }
}
```

## Available MCP Tools

The following tools are available via the MCP protocol:

1. **submit_job** - Submit an HTCondor job using a submit file
2. **query_jobs** - Query HTCondor jobs with optional constraints and projections
3. **get_job** - Get details of a specific HTCondor job by ID
4. **remove_job** - Remove (delete) a specific HTCondor job
5. **remove_jobs** - Remove multiple HTCondor jobs matching a constraint
6. **edit_job** - Edit attributes of a specific HTCondor job
7. **hold_job** - Hold a specific HTCondor job
8. **release_job** - Release a held HTCondor job

See the [MCP Server README](../mcpserver/README.md) for detailed documentation of each tool.

## User Header Authentication

If the server is configured with `UserHeader`, the OAuth2 flow will use the username from that HTTP header when generating HTCondor tokens. This allows integration with existing authentication systems.

Example with user header:
```bash
curl -X POST http://localhost:8080/mcp/oauth2/token \
  -H "X-Remote-User: alice" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=CLIENT_ID&client_secret=CLIENT_SECRET"
```

## SSO Integration

The server can be configured to use an external OAuth2 provider for user authentication:

```go
server, err := httpserver.NewServer(httpserver.Config{
    EnableMCP:          true,
    OAuth2ClientID:     "client-id",
    OAuth2ClientSecret: "client-secret",
    OAuth2AuthURL:      "https://sso.example.com/oauth2/authorize",
    OAuth2TokenURL:     "https://sso.example.com/oauth2/token",
    OAuth2RedirectURL:  "http://localhost:8080/mcp/oauth2/callback",
    // ... other config
})
```

## Security Considerations

1. **Always use HTTPS in production** to protect OAuth2 tokens and credentials
2. **Rotate client secrets regularly**
3. **Use short-lived access tokens** (default: 1 hour)
4. **Store the OAuth2 database securely** with appropriate file permissions
5. **Validate token scopes** before allowing operations
6. **Monitor OAuth2 token usage** for anomalies

## Example: ChatGPT Integration

To integrate with ChatGPT or other AI assistants:

1. Start the HTTP API server in demo mode:
   ```bash
   ./htcondor-api --demo
   ```

2. Create an OAuth2 client (programmatically via the storage API)

3. Configure the AI assistant with:
   - Base URL: `http://localhost:8080`
   - OAuth2 token endpoint: `/mcp/oauth2/token`
   - MCP endpoint: `/mcp/message`
   - Client credentials

4. The AI assistant can now interact with HTCondor via MCP protocol

## Testing

Run the integration test:

```bash
go test -tags=integration -v ./httpserver/ -run TestMCPHTTPIntegration
```

## References

- [MCP Server Documentation](../mcpserver/README.md)
- [HTTP API Documentation](../httpserver/README.md)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
