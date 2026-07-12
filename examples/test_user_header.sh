#!/bin/bash
# Test script for user-header authentication in demo mode

set -e

echo "=== Testing User Header Authentication in Demo Mode ==="
echo ""

# Kill any existing htcondor-api processes
pkill htcondor-api 2>/dev/null || true
sleep 1

# Start the server in demo mode with user header
echo "Starting htcondor-api in demo mode with --user-header=X-Remote-User..."
./htcondor-api --demo --user-header=X-Remote-User &
SERVER_PID=$!

# Wait for server to start
echo "Waiting for server to start..."
sleep 10

# Function to cleanup
cleanup() {
    echo ""
    echo "Cleaning up..."
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

# Test 1: Request with user header (no Authorization token)
echo ""
echo "Test 1: Submitting job with X-Remote-User header (no Bearer token)..."
SUBMIT_FILE='executable = /bin/echo
arguments = "Hello from user header test"
output = test.out
error = test.err
log = test.log
queue'

RESPONSE=$(curl -s -X POST "http://localhost:8080/api/v1/jobs" \
    -H "X-Remote-User: testuser" \
    -H "Content-Type: application/json" \
    -d "{\"submit_file\": \"${SUBMIT_FILE}\"}" 2>&1)

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "cluster_id"; then
    echo "✓ Test 1 PASSED: Job submitted successfully with user header"
else
    echo "✗ Test 1 FAILED: Job submission failed"
fi

# Test 2: List jobs with user header
echo ""
echo "Test 2: Listing jobs with X-Remote-User header..."
RESPONSE=$(curl -s "http://localhost:8080/api/v1/jobs?projection=ClusterId,Owner" \
    -H "X-Remote-User: testuser" 2>&1)

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "jobs"; then
    echo "✓ Test 2 PASSED: Jobs listed successfully with user header"
else
    echo "✗ Test 2 FAILED: Job listing failed"
fi

# Test 3: Request without authentication (should fail)
echo ""
echo "Test 3: Request without authentication (should fail)..."
RESPONSE=$(curl -s "http://localhost:8080/api/v1/jobs" 2>&1)

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "Unauthorized\|error"; then
    echo "✓ Test 3 PASSED: Request correctly rejected without authentication"
else
    echo "✗ Test 3 FAILED: Request should have been rejected"
fi

echo ""
echo "=== Tests Complete ==="
