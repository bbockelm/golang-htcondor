# HTCondor MCP Server

A Model Context Protocol (MCP) server for managing HTCondor jobs. This server exposes HTCondor functionality as MCP tools that can be used by AI assistants and other MCP clients.

## Features

- **Job Submission**: Submit jobs via MCP tool with HTCondor submit file
- **Job Queries**: List and retrieve job details with ClassAd constraints and projections
- **Job Management**: Remove, edit, hold, and release jobs
- **Authentication**: Token-based authentication forwarded to HTCondor schedd
- **Demo Mode**: Built-in mini HTCondor setup for testing and development
- **MCP Protocol**: Full MCP protocol support for seamless AI integration

## What is MCP?

The Model Context Protocol (MCP) is an open standard that enables AI assistants to securely interact with external data sources and tools. MCP servers expose specific capabilities (called "tools" and "resources") that AI assistants can discover and use.

## Installation

```bash
cd cmd/htcondor-mcp
go build
```

## Usage

### Normal Mode (with existing HTCondor)

```bash
# Uses HTCondor configuration from environment
./htcondor-mcp
```

The server will:
1. Read HTCondor configuration from standard locations
2. Connect to the configured schedd
3. Listen on stdin/stdout for MCP protocol messages

### Demo Mode (standalone mini HTCondor)

```bash
# Starts mini HTCondor automatically
./htcondor-mcp --demo
```

Demo mode will:
1. Create a temporary directory for mini HTCondor
2. Write minimal HTCondor configuration
3. Start `condor_master` as a subprocess
4. Start the MCP server
5. Clean up on Ctrl+C or SIGTERM

## MCP Tools

The server provides the following MCP tools:

### submit_job

Submit an HTCondor job using a submit file.

**Input:**
- `submit_file` (string, required): HTCondor submit file content
- `token` (string, optional): Authentication token

**Example:**
```json
{
  "name": "submit_job",
  "arguments": {
    "submit_file": "executable=/bin/echo\narguments=Hello World\nqueue"
  }
}
```

### query_jobs

Query HTCondor jobs with optional constraints and projections.

**Input:**
- `constraint` (string, optional): ClassAd constraint expression (default: 'true')
- `projection` (array of strings, optional): Attributes to include in results
- `token` (string, optional): Authentication token

**Example:**
```json
{
  "name": "query_jobs",
  "arguments": {
    "constraint": "Owner == \"alice\"",
    "projection": ["ClusterId", "ProcId", "JobStatus", "Owner"]
  }
}
```

### get_job

Get details of a specific HTCondor job by ID.

**Input:**
- `job_id` (string, required): Job ID in format 'cluster.proc' (e.g., '123.0')
- `token` (string, optional): Authentication token

**Example:**
```json
{
  "name": "get_job",
  "arguments": {
    "job_id": "123.0"
  }
}
```

### remove_job

Remove (delete) a specific HTCondor job.

**Input:**
- `job_id` (string, required): Job ID in format 'cluster.proc'
- `reason` (string, optional): Reason for removal
- `token` (string, optional): Authentication token

### remove_jobs

Remove multiple HTCondor jobs matching a constraint.

**Input:**
- `constraint` (string, required): ClassAd constraint to select jobs
- `reason` (string, optional): Reason for removal
- `token` (string, optional): Authentication token

### edit_job

Edit attributes of a specific HTCondor job.

**Input:**
- `job_id` (string, required): Job ID in format 'cluster.proc'
- `attributes` (object, required): Attributes to update as key-value pairs
- `token` (string, optional): Authentication token

**Example:**
```json
{
  "name": "edit_job",
  "arguments": {
    "job_id": "123.0",
    "attributes": {
      "JobPrio": 10,
      "UserNote": "High priority job"
    }
  }
}
```

### hold_job

Hold a specific HTCondor job.

**Input:**
- `job_id` (string, required): Job ID in format 'cluster.proc'
- `reason` (string, optional): Reason for holding
- `token` (string, optional): Authentication token

### release_job

Release a held HTCondor job.

**Input:**
- `job_id` (string, required): Job ID in format 'cluster.proc'
- `reason` (string, optional): Reason for release
- `token` (string, optional): Authentication token

## MCP Resources

### condor://schedd/status

Returns the current status and information about the HTCondor schedd from the collector.

## Integration with AI Assistants

### VS Code with GitHub Copilot

Add to your `.vscode/mcp.json`:

```json
{
  "mcpServers": {
    "htcondor": {
      "command": "/path/to/htcondor-mcp",
      "args": ["--demo"]
    }
  }
}
```

### Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "htcondor": {
      "command": "/path/to/htcondor-mcp"
    }
  }
}
```

## Authentication

The MCP server supports HTCondor TOKEN authentication. Tokens can be provided in the `token` argument of each tool call.

In demo mode, the server uses a signing key for token generation. In normal mode, it uses the HTCondor configuration to locate tokens and signing keys.

## Configuration

The server reads HTCondor configuration from standard locations:
- `CONDOR_CONFIG` environment variable
- `/etc/condor/condor_config`
- `~/.condor/user_config`

Key configuration parameters:
- `SCHEDD_NAME`: Name of the schedd to connect to
- `COLLECTOR_HOST`: Collector address for schedd discovery
- `SEC_TOKEN_POOL_SIGNING_KEY_FILE`: Path to token signing key
- `TRUST_DOMAIN`: Trust domain for tokens
- `UID_DOMAIN`: UID domain for user identification

## Comparison with HTTP API

| Feature | HTTP API | MCP Server |
|---------|----------|------------|
| Protocol | REST/HTTP | MCP (JSON-RPC over stdio) |
| Transport | Network (TCP) | stdio pipes |
| Authentication | Bearer tokens | Token in tool arguments |
| Discovery | OpenAPI schema | MCP tools/resources list |
| Use Case | Web clients, curl | AI assistants, MCP clients |
| Deployment | Standalone server | Subprocess of client |

## Development

### Building

```bash
go build -o htcondor-mcp cmd/htcondor-mcp/main.go
```

### Testing

```bash
# Test in demo mode
./htcondor-mcp --demo

# Send MCP messages via stdin (initialize protocol)
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | ./htcondor-mcp
```

## License

See LICENSE file in the repository root.

## Related

- [HTCondor HTTP API Server](../httpserver/README.md)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [HTCondor Documentation](https://htcondor.readthedocs.io/)
