# HTTP API Integration Test

This directory contains an integration test for the HTCondor HTTP API server that tests the complete job lifecycle.

## Test Overview

The integration test (`integration_test.go`) verifies the full end-to-end workflow:

1. **Start Mini HTCondor** - Spins up a local HTCondor instance
2. **Start HTTP API Server** - Launches the API server in demo mode
3. **Submit Job** - Posts a job via HTTP API (`POST /api/v1/jobs`)
4. **Upload Input** - Uploads input files as tarball (`PUT /api/v1/jobs/{id}/input`)
5. **Poll Status** - Monitors job until completion (`GET /api/v1/jobs/{id}`)
6. **Download Output** - Retrieves result tarball (`GET /api/v1/jobs/{id}/output`)
7. **Verify Results** - Validates output file contents

## Prerequisites

The integration test requires HTCondor to be installed on your system:

```bash
# Check if HTCondor is available
which condor_master condor_schedd condor_q
```

If HTCondor is not installed, the test will be automatically skipped.

## Running the Test

### Run the integration test

```bash
# From the repository root
go test -tags=integration -v ./httpserver/

# Or with timeout
go test -tags=integration -v -timeout=5m ./httpserver/
```

### Run with verbose output

```bash
go test -tags=integration -v ./httpserver/ -test.v
```

### Expected Output

```
=== RUN   TestHTTPAPIIntegration
    integration_test.go:XX: Using temporary directory: /tmp/htcondor-http-test-XXXXX
    integration_test.go:XX: Starting condor_master...
    integration_test.go:XX: Waiting for HTCondor to be ready...
    integration_test.go:XX: HTCondor is ready!
    integration_test.go:XX: Waiting for server to start on http://127.0.0.1:18080
    integration_test.go:XX: Server is ready on http://127.0.0.1:18080
    integration_test.go:XX: Step 1: Submitting job via HTTP...
    integration_test.go:XX: Job submitted: ClusterID=1, JobID=1.0
    integration_test.go:XX: Step 2: Creating and uploading input tarball...
    integration_test.go:XX: Input tarball uploaded successfully
    integration_test.go:XX: Step 3: Polling job status until complete...
    integration_test.go:XX: Job status: 1 (1=Idle, 2=Running, 4=Completed, 5=Held)
    integration_test.go:XX: Job status: 2 (1=Idle, 2=Running, 4=Completed, 5=Held)
    integration_test.go:XX: Job status: 4 (1=Idle, 2=Running, 4=Completed, 5=Held)
    integration_test.go:XX: Job completed successfully!
    integration_test.go:XX: Step 4: Downloading output tarball...
    integration_test.go:XX: Output tarball downloaded successfully
    integration_test.go:XX: Step 5: Verifying results...
    integration_test.go:XX: ✅ Integration test passed! Full job lifecycle completed successfully.
--- PASS: TestHTTPAPIIntegration (45.23s)
PASS
```

## Test Details

### Test Job

The test submits a simple bash job that:
- Reads from `input.txt`
- Writes to `output.txt`
- Exits successfully

```bash
executable = /bin/bash
arguments = -c "echo 'Hello from HTCondor!' > output.txt && echo 'Test successful' >> output.txt"
transfer_input_files = input.txt
transfer_output_files = output.txt
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
queue
```

### Authentication

The test uses header-based authentication with auto-generated JWT tokens:
- Header: `X-Test-User: testuser`
- A signing key is automatically generated for the test
- JWT tokens are created on-the-fly for API requests

### Timeouts

The test includes several timeouts to handle slow systems:
- HTCondor startup: 30 seconds
- HTTP server startup: 10 seconds
- Job completion: 60 seconds
- HTTP requests: 30 seconds

### Cleanup

The test automatically cleans up:
- Stops condor_master gracefully
- Shuts down HTTP server
- Removes temporary directories

## Troubleshooting

### Test is skipped

If you see:
```
--- SKIP: TestHTTPAPIIntegration (0.00s)
    integration_test.go:XX: condor_master not found in PATH, skipping integration test
```

Install HTCondor or ensure it's in your PATH.

### Test times out

If the test times out:
1. Check if HTCondor daemons are starting: `ps aux | grep condor`
2. Look at HTCondor logs in the temp directory (printed in test output)
3. Increase timeout values if running on a slow system

### Job is held

If the test fails with "Job was held":
1. The test will print the HoldReason
2. Common causes:
   - `/bin/bash` not available
   - Insufficient permissions
   - File transfer issues

### Port already in use

The test uses port 18080. If it's in use:
1. Stop the conflicting process
2. Or modify `serverPort` in `integration_test.go`

## CI/CD Integration

To run integration tests in CI/CD:

```yaml
# GitHub Actions example
- name: Install HTCondor
  run: |
    # Install HTCondor for your distro
    apt-get install -y htcondor

- name: Run Integration Tests
  run: go test -tags=integration -v -timeout=10m ./httpserver/
```

## Manual Testing

You can also test the HTTP API manually with the demo mode:

```bash
# Start the API server in demo mode
cd cmd/htcondor-api
go run . --demo --user-header=X-Test-User

# In another terminal, submit a job
curl -X POST http://localhost:8080/api/v1/jobs \
  -H "X-Test-User: testuser" \
  -H "Content-Type: application/json" \
  -d '{"submit_file": "executable=/bin/echo\narguments=Hello\nqueue"}'

# Check job status
curl http://localhost:8080/api/v1/jobs/1.0 \
  -H "X-Test-User: testuser"
```

## See Also

- [HTTP API Documentation](README.md)
- [HTTP API TODO](../HTTP_API_TODO.md)
- [Integration Testing Guide](../INTEGRATION_TESTING.md)
