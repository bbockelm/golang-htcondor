#!/usr/bin/env python3
"""
Example Python script demonstrating the new HTCondor REST API endpoints.

Requirements:
    pip install requests

Usage:
    python rest_api_examples.py --token YOUR_TOKEN --url http://localhost:8080
"""

import argparse
import json
import requests
from typing import Dict, Any, Optional


class HTCondorAPI:
    """Client for HTCondor REST API."""

    def __init__(self, base_url: str, token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        if token:
            self.session.headers.update({'Authorization': f'Bearer {token}'})

    def hold_job(self, job_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        """Hold a specific job."""
        url = f"{self.base_url}/api/v1/jobs/{job_id}/hold"
        data = {}
        if reason:
            data['reason'] = reason
        response = self.session.post(url, json=data)
        response.raise_for_status()
        return response.json()

    def release_job(self, job_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        """Release a held job."""
        url = f"{self.base_url}/api/v1/jobs/{job_id}/release"
        data = {}
        if reason:
            data['reason'] = reason
        response = self.session.post(url, json=data)
        response.raise_for_status()
        return response.json()

    def bulk_hold_jobs(self, constraint: str, reason: Optional[str] = None) -> Dict[str, Any]:
        """Hold multiple jobs matching a constraint."""
        url = f"{self.base_url}/api/v1/jobs/hold"
        data = {'constraint': constraint}
        if reason:
            data['reason'] = reason
        response = self.session.post(url, json=data)
        response.raise_for_status()
        return response.json()

    def bulk_release_jobs(self, constraint: str, reason: Optional[str] = None) -> Dict[str, Any]:
        """Release multiple held jobs matching a constraint."""
        url = f"{self.base_url}/api/v1/jobs/release"
        data = {'constraint': constraint}
        if reason:
            data['reason'] = reason
        response = self.session.post(url, json=data)
        response.raise_for_status()
        return response.json()

    def query_collector_ads(self, constraint: Optional[str] = None) -> Dict[str, Any]:
        """Query all collector ads."""
        url = f"{self.base_url}/api/v1/collector/ads"
        params = {}
        if constraint:
            params['constraint'] = constraint
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def query_collector_ads_by_type(
        self, ad_type: str, constraint: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query collector ads of a specific type."""
        url = f"{self.base_url}/api/v1/collector/ads/{ad_type}"
        params = {}
        if constraint:
            params['constraint'] = constraint
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def get_collector_ad(self, ad_type: str, name: str) -> Dict[str, Any]:
        """Get a specific collector ad by type and name."""
        url = f"{self.base_url}/api/v1/collector/ads/{ad_type}/{name}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()


def main():
    parser = argparse.ArgumentParser(description='HTCondor REST API Examples')
    parser.add_argument('--url', default='http://localhost:8080',
                        help='API base URL')
    parser.add_argument('--token', help='Authentication token')
    parser.add_argument('--job-id', default='123.0',
                        help='Job ID for examples')
    args = parser.parse_args()

    client = HTCondorAPI(args.url, args.token)

    print("=" * 60)
    print("HTCondor REST API Examples (Python)")
    print("=" * 60)
    print()

    # Example 1: Hold a specific job
    print("1. Hold a specific job:")
    try:
        result = client.hold_job(args.job_id, reason="Holding for maintenance")
        print(json.dumps(result, indent=2))
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
    print()

    # Example 2: Release a specific job
    print("2. Release a held job:")
    try:
        result = client.release_job(args.job_id, reason="Maintenance complete")
        print(json.dumps(result, indent=2))
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
    print()

    # Example 3: Bulk hold jobs
    print("3. Hold all jobs for user 'alice':")
    try:
        result = client.bulk_hold_jobs(
            constraint='Owner == "alice"',
            reason="Bulk maintenance"
        )
        print(json.dumps(result, indent=2))
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
    print()

    # Example 4: Bulk release jobs
    print("4. Release all held jobs:")
    try:
        result = client.bulk_release_jobs(constraint="JobStatus == 5")
        print(json.dumps(result, indent=2))
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
    print()

    # Example 5: Query all collector ads
    print("5. Query all collector ads:")
    try:
        result = client.query_collector_ads()
        print(f"Found {len(result.get('ads', []))} ads")
        if result.get('ads'):
            print("First ad:")
            print(json.dumps(result['ads'][0], indent=2))
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
    print()

    # Example 6: Query schedd ads
    print("6. Query schedd advertisements:")
    try:
        result = client.query_collector_ads_by_type("schedd")
        print(f"Found {len(result.get('ads', []))} schedd ads")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
    print()

    # Example 7: Query startd ads with constraint
    print("7. Query startd ads for machines with >8 CPUs:")
    try:
        result = client.query_collector_ads_by_type(
            "startd",
            constraint="Cpus > 8"
        )
        print(f"Found {len(result.get('ads', []))} matching ads")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
    print()

    # Example 8: Get specific schedd ad
    print("8. Get specific schedd by name:")
    try:
        result = client.get_collector_ad("schedd", "schedd@host.example.com")
        print(json.dumps(result, indent=2))
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
    print()

    print("=" * 60)
    print("Examples complete")
    print("=" * 60)


if __name__ == '__main__':
    main()
