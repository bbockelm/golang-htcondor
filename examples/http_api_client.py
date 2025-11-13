#!/usr/bin/env python3
"""
Example Python client for HTCondor HTTP API

This demonstrates how to interact with the HTCondor HTTP API using Python's
requests library.

Install dependencies:
    pip install requests

Usage:
    export CONDOR_TOKEN=$(cat /path/to/token.txt)
    python http_api_client.py
"""

import os
import sys
import json
import requests
from typing import Dict, List, Optional

class HTCondorAPIClient:
    """Client for HTCondor HTTP API"""

    def __init__(self, base_url: str = "http://localhost:8080", token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.token = token or os.environ.get('CONDOR_TOKEN')

        if not self.token:
            print("Warning: No token provided. Set CONDOR_TOKEN environment variable.", file=sys.stderr)

        self.session = requests.Session()
        if self.token:
            self.session.headers.update({
                'Authorization': f'Bearer {self.token}'
            })

    def submit_job(self, submit_file: str) -> Dict:
        """Submit a job to HTCondor"""
        response = self.session.post(
            f'{self.base_url}/api/v1/jobs',
            json={'submit_file': submit_file}
        )
        response.raise_for_status()
        return response.json()

    def list_jobs(self, constraint: str = "true", projection: Optional[List[str]] = None) -> List[Dict]:
        """List jobs matching constraint"""
        params = {'constraint': constraint}
        if projection:
            params['projection'] = ','.join(projection)

        response = self.session.get(
            f'{self.base_url}/api/v1/jobs',
            params=params
        )
        response.raise_for_status()
        return response.json()['jobs']

    def get_job(self, job_id: str) -> Dict:
        """Get details for a specific job"""
        response = self.session.get(
            f'{self.base_url}/api/v1/jobs/{job_id}'
        )
        response.raise_for_status()
        return response.json()

    def upload_input(self, job_id: str, tarfile_path: str):
        """Upload job input files as tarball"""
        with open(tarfile_path, 'rb') as f:
            response = self.session.put(
                f'{self.base_url}/api/v1/jobs/{job_id}/input',
                data=f,
                headers={'Content-Type': 'application/x-tar'}
            )
        response.raise_for_status()
        return response.json()

    def download_output(self, job_id: str, output_path: str):
        """Download job output files as tarball"""
        response = self.session.get(
            f'{self.base_url}/api/v1/jobs/{job_id}/output',
            stream=True
        )
        response.raise_for_status()

        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

    def get_openapi_schema(self) -> Dict:
        """Get OpenAPI schema"""
        response = requests.get(f'{self.base_url}/openapi.json')
        response.raise_for_status()
        return response.json()


def main():
    """Example usage"""
    # Create client
    client = HTCondorAPIClient()

    print("=== HTCondor HTTP API Python Client Example ===\n")

    # Get API schema
    try:
        schema = client.get_openapi_schema()
        print(f"API: {schema['info']['title']} v{schema['info']['version']}\n")
    except Exception as e:
        print(f"Could not get schema: {e}\n")

    # Submit a job
    submit_file = """
executable = /bin/echo
arguments = "Hello from Python!"
output = test.out
error = test.err
log = test.log
queue
"""

    try:
        print("Submitting job...")
        result = client.submit_job(submit_file)
        cluster_id = result['cluster_id']
        job_ids = result['job_ids']
        print(f"Job submitted: {job_ids[0]} (cluster {cluster_id})\n")

        # Get job details
        print("Getting job details...")
        job = client.get_job(job_ids[0])
        print(f"Job Owner: {job.get('Owner', 'unknown')}")
        print(f"Job Status: {job.get('JobStatus', 'unknown')}")
        print(f"Job Cmd: {job.get('Cmd', 'unknown')}\n")

        # List jobs
        print("Listing all jobs...")
        jobs = client.list_jobs(
            projection=['ClusterId', 'ProcId', 'JobStatus', 'Owner']
        )
        print(f"Found {len(jobs)} jobs\n")

        # List jobs with constraint
        print(f"Listing jobs in cluster {cluster_id}...")
        jobs = client.list_jobs(
            constraint=f"ClusterId == {cluster_id}"
        )
        print(f"Found {len(jobs)} jobs in cluster\n")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            print(f"Authentication failed: {e}")
            print("Token authentication is not yet fully implemented.")
            print("See HTTP_API_TODO.md for details.")
        else:
            print(f"HTTP Error: {e}")
    except Exception as e:
        print(f"Error: {e}")

    print("=== Example Complete ===")


if __name__ == '__main__':
    main()
