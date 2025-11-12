# HTCondor HTTP API - Quick Start Guide

Get the HTCondor HTTP API server running in under 5 minutes!

## Prerequisites

- Go 1.21 or later
- HTCondor installed (optional for demo mode)
- `jq` for JSON formatting (optional but recommended)

## Option 1: Demo Mode (No HTCondor Required)

The easiest way to try the API is using demo mode, which runs a mini HTCondor setup:

```bash
# 1. Build the server
cd cmd/htcondor-api
go build

# 2. Start in demo mode
./htcondor-api --demo
```

You'll see output like:
```
Starting in demo mode...
Using temporary directory: /tmp/htcondor-demo-1234567890
Starting condor_master...
Waiting for HTCondor to be ready...
HTCondor is ready!
Starting HTCondor API server on :8080
```

The server is now running at `http://localhost:8080`!

## Option 2: Use Existing HTCondor

If you have HTCondor already installed and configured:

```bash
# 1. Build the server
cd cmd/htcondor-api
go build

# 2. Start the server (uses HTCondor from environment)
./htcondor-api
```

## Test the API

### Get the OpenAPI Schema

```bash
curl http://localhost:8080/openapi.json | jq .
```

### Submit a Job

**Note:** Authentication is partially implemented. The API extracts bearer tokens but doesn't yet fully integrate them with HTCondor authentication. See `HTTP_API_TODO.md` for details.

```bash
# Create a simple job
cat > submit.json <<'EOF'
{
  "submit_file": "executable = /bin/echo\narguments = Hello World\noutput = test.out\nerror = test.err\nlog = test.log\nqueue"
}
EOF

# Submit it (replace TOKEN with your HTCondor token)
curl -X POST http://localhost:8080/api/v1/jobs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d @submit.json | jq .
```

Expected response:
```json
{
  "cluster_id": 1,
  "job_ids": ["1.0"]
}
```

### List Jobs

```bash
# List all jobs
curl http://localhost:8080/api/v1/jobs \
  -H "Authorization: Bearer $TOKEN" | jq .

# List with projection (only specific attributes)
curl "http://localhost:8080/api/v1/jobs?projection=ClusterId,ProcId,JobStatus,Owner" \
  -H "Authorization: Bearer $TOKEN" | jq .

# List with constraint
curl "http://localhost:8080/api/v1/jobs?constraint=Owner==\"$USER\"" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Get Job Details

```bash
# Get details for job 1.0
curl http://localhost:8080/api/v1/jobs/1.0 \
  -H "Authorization: Bearer $TOKEN" | jq .
```

## Using the Example Scripts

### Bash Script

```bash
cd examples
export CONDOR_TOKEN="your-token-here"
./http_api_demo.sh
```

### Python Client

```bash
cd examples
pip install requests
export CONDOR_TOKEN="your-token-here"
python http_api_client.py
```

## Getting an HTCondor Token

To use authentication (when fully implemented), generate a token:

```bash
# Generate a token (requires HTCondor admin access)
condor_token_create -identity $USER@$(hostname) > token.txt

# Use it in requests
export CONDOR_TOKEN=$(cat token.txt)
```

## Advanced Usage

### Custom Listen Address

```bash
./htcondor-api --listen :9000
```

### Working with File Transfer

#### Upload Job Input Files

```bash
# Create a tarball with input files
tar -czf input.tar.gz file1.txt file2.dat

# Upload to job
curl -X PUT http://localhost:8080/api/v1/jobs/1.0/input \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-tar" \
  --data-binary @input.tar.gz
```

#### Download Job Output Files

```bash
# Download output as tarball
curl http://localhost:8080/api/v1/jobs/1.0/output \
  -H "Authorization: Bearer $TOKEN" \
  -o output.tar

# Extract the tarball
tar -xvf output.tar
```

## Troubleshooting

### Server won't start

**Problem:** `failed to connect to schedd`
- **Demo mode:** Make sure `condor_master` is in your PATH
- **Normal mode:** Check that HTCondor is running and configured

**Problem:** Port already in use
- Use a different port: `./htcondor-api --listen :9000`

### Authentication errors

**Problem:** `401 Unauthorized`
- Token authentication is not yet fully implemented
- The API accepts tokens but doesn't forward them to HTCondor yet
- See `HTTP_API_TODO.md` for implementation status

### Job submission fails

**Problem:** Job submission returns 500 error
- Check the server logs for details
- Verify the submit file syntax is correct
- In demo mode, check condor_master is running: `ps aux | grep condor_master`

## Next Steps

- Read the [full API documentation](httpserver/README.md)
- Check the [TODO list](../HTTP_API_TODO.md) for upcoming features
- Try the [Python client example](../examples/http_api_client.py)
- Explore the [OpenAPI schema](http://localhost:8080/openapi.json)

## Stopping the Server

Press `Ctrl+C` to gracefully stop the server. In demo mode, this will also stop condor_master and clean up temporary files.

## Need Help?

- Check the [main README](../README.md) for library documentation
- See [HTTP_API_TODO.md](../HTTP_API_TODO.md) for known limitations
- Review [examples/](../examples/) for more usage patterns
