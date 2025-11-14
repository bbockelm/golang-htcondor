#!/bin/bash
# Example script demonstrating the HTCondor HTTP API

set -e

API_URL="http://localhost:8080"
TOKEN="${CONDOR_TOKEN:-your-token-here}"
USER="${CONDOR_USER:-testuser}"

echo "=== HTCondor HTTP API Example ==="
echo ""

# Check authentication method
if [ "$TOKEN" = "your-token-here" ]; then
    echo "Using user header authentication (X-Remote-User: $USER)"
    AUTH_HEADER="X-Remote-User: $USER"
    echo ""
else
    echo "Using bearer token authentication"
    AUTH_HEADER="Authorization: Bearer $TOKEN"
    echo ""
fi

echo "1. Getting OpenAPI schema..."
curl -s "${API_URL}/openapi.json" | jq -r '.info.title, .info.version' || echo "Could not get schema"
echo ""

echo "2. Submitting a job..."
SUBMIT_FILE='executable = /bin/echo
arguments = "Hello from HTCondor HTTP API!"
output = test.out
error = test.err
log = test.log
queue'

# Properly escape the submit file for JSON
SUBMIT_FILE_JSON=$(echo "$SUBMIT_FILE" | jq -Rs .)

RESPONSE=$(curl -s -X POST "${API_URL}/api/v1/jobs" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d "{\"submit_file\": ${SUBMIT_FILE_JSON}}")

echo "Response: ${RESPONSE}"
CLUSTER_ID=$(echo "${RESPONSE}" | jq -r '.cluster_id' 2>/dev/null || echo "")
JOB_ID=$(echo "${RESPONSE}" | jq -r '.job_ids[0]' 2>/dev/null || echo "")

if [ -n "$JOB_ID" ] && [ "$JOB_ID" != "null" ]; then
    echo "Job submitted: ${JOB_ID}"
    echo ""

    echo "3. Getting job details..."
    curl -s "${API_URL}/api/v1/jobs/${JOB_ID}" \
        -H "$AUTH_HEADER" | jq '.' || echo "Could not get job details"
    echo ""

    echo "4. Listing all jobs..."
    curl -s "${API_URL}/api/v1/jobs?projection=ClusterId,ProcId,JobStatus,Owner" \
        -H "$AUTH_HEADER" | jq '.jobs[] | {ClusterId, ProcId, JobStatus, Owner}' || echo "Could not list jobs"
    echo ""

    echo "5. Listing jobs with constraint..."
    curl -s "${API_URL}/api/v1/jobs?constraint=ClusterId==${CLUSTER_ID}" \
        -H "$AUTH_HEADER" | jq '.jobs | length' | xargs echo "Found jobs:" || echo "Could not query jobs"
    echo ""
else
    echo "Job submission failed or token authentication not configured."
    echo "See HTTP_API_TODO.md for authentication implementation status."
fi

echo "=== Example Complete ==="
