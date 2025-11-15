#!/bin/bash
# Example script demonstrating the new REST API endpoints

# Configuration
API_URL="http://localhost:8080"
TOKEN="your-token-here"

echo "===================================="
echo "HTCondor REST API Examples"
echo "===================================="
echo ""

# Example 1: Hold a specific job
echo "1. Hold a specific job (123.0):"
curl -X POST "$API_URL/api/v1/jobs/123.0/hold" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Holding for maintenance"}' \
  -w "\nHTTP Status: %{http_code}\n\n"

# Example 2: Release a specific job
echo "2. Release a held job (123.0):"
curl -X POST "$API_URL/api/v1/jobs/123.0/release" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Maintenance complete"}' \
  -w "\nHTTP Status: %{http_code}\n\n"

# Example 3: Bulk hold jobs by constraint
echo "3. Hold all jobs for user 'alice':"
curl -X POST "$API_URL/api/v1/jobs/hold" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"constraint": "Owner == \"alice\"", "reason": "Bulk maintenance"}' \
  -w "\nHTTP Status: %{http_code}\n\n"

# Example 4: Bulk release held jobs
echo "4. Release all held jobs:"
curl -X POST "$API_URL/api/v1/jobs/release" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"constraint": "JobStatus == 5"}' \
  -w "\nHTTP Status: %{http_code}\n\n"

# Example 5: Query all collector ads
echo "5. Query all collector ads:"
curl "$API_URL/api/v1/collector/ads" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Example 6: Query schedd ads
echo "6. Query schedd advertisements:"
curl "$API_URL/api/v1/collector/ads/schedd" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Example 7: Query startd ads with constraint
echo "7. Query startd ads for machines with >8 CPUs:"
curl "$API_URL/api/v1/collector/ads/startd?constraint=Cpus>8" \
  -w "\nHTTP Status: %{http_code}\n\n"

# Example 8: Get specific schedd ad
echo "8. Get specific schedd by name:"
curl "$API_URL/api/v1/collector/ads/schedd/schedd@host.example.com" \
  -w "\nHTTP Status: %{http_code}\n\n"

echo "===================================="
echo "Examples complete"
echo "===================================="
