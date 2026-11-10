#!/usr/bin/env python3
"""A minimal placement client: the standard OAuth2 device flow, then a token.

What a placement client does against htcondor-api, with nothing but the
standard library:

  1. read /.well-known/oauth-authorization-server for the endpoints;
  2. ask the device authorization endpoint, as the public client
     placement_client, for the scope "placement" (RFC 8628);
  3. print the user code and verification URL, and poll the token endpoint
     until the person approves;
  4. POST /api/v1/placement/me/token with the access token, and save the
     placement token it returns.

Progress goes to stdout one "KEY value" line at a time, flushed, so a test
driving it can read the verification URL while it polls.

Exit status: 0 with the token saved; 2 for a refusal or a protocol error,
with the reason on stderr.
"""

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CLIENT_ID = "placement_client"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def say(key, value):
    print(f"{key} {value}", flush=True)


def fail(msg):
    print(f"placement_client: {msg}", file=sys.stderr, flush=True)
    sys.exit(2)


class Client:
    def __init__(self, base_url, cafile):
        self.base = base_url.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=cafile)

    def request(self, method, url, form=None, body=None, bearer=None):
        """Returns (status, parsed JSON or None, raw text)."""
        headers = {"Accept": "application/json"}
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as resp:
                status, raw = resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read().decode()
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        return status, parsed, raw


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--cafile", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--authorizations", default="READ,WRITE")
    ap.add_argument("--scope", default="placement",
                    help="scope to ask for; empty asks for none")
    ap.add_argument("--refused-project",
                    help="first ask for this project, and require that to be refused")
    ap.add_argument("--out", required=True, help="where to save the placement token")
    ap.add_argument("--timeout", type=float, default=120,
                    help="seconds to wait for the approval")
    args = ap.parse_args()

    c = Client(args.base_url, args.cafile)

    status, meta, raw = c.request("GET", c.base + "/.well-known/oauth-authorization-server")
    if status != 200 or not isinstance(meta, dict):
        fail(f"authorization server metadata: HTTP {status}: {raw[:300]}")
    device_ep = meta.get("device_authorization_endpoint")
    token_ep = meta.get("token_endpoint")
    if not device_ep or not token_ep:
        fail(f"metadata names no device authorization or token endpoint: {raw[:300]}")
    say("DEVICE_AUTHORIZATION_ENDPOINT", device_ep)

    form = {"client_id": CLIENT_ID}
    if args.scope:
        form["scope"] = args.scope
    status, dev, raw = c.request("POST", device_ep, form=form)
    if status != 200 or not isinstance(dev, dict) or "device_code" not in dev:
        fail(f"device authorization refused: HTTP {status}: {raw[:300]}")
    say("USER_CODE", dev["user_code"])
    say("VERIFICATION_URI", dev["verification_uri"])
    if dev.get("verification_uri_complete"):
        say("VERIFICATION_URI_COMPLETE", dev["verification_uri_complete"])

    interval = float(dev.get("interval") or 5)
    deadline = time.monotonic() + min(args.timeout, float(dev.get("expires_in") or args.timeout))
    access_token = None
    while access_token is None:
        if time.monotonic() > deadline:
            fail("timed out waiting for the request to be approved")
        time.sleep(interval)
        status, tok, raw = c.request("POST", token_ep, form={
            "grant_type": DEVICE_GRANT,
            "device_code": dev["device_code"],
            "client_id": CLIENT_ID,
        })
        if status == 200 and isinstance(tok, dict) and tok.get("access_token"):
            access_token = tok["access_token"]
            say("GRANTED_SCOPE", tok.get("scope", ""))
            break
        err = tok.get("error") if isinstance(tok, dict) else None
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        fail(f"token endpoint: HTTP {status}: {raw[:300]}")

    me_token = c.base + "/api/v1/placement/me/token"
    authorizations = [a for a in args.authorizations.split(",") if a]

    if args.refused_project:
        status, _, raw = c.request("POST", me_token, bearer=access_token,
                                   body={"project": args.refused_project,
                                         "authorizations": authorizations})
        if 200 <= status < 300:
            fail(f"a token for project {args.refused_project} was issued, but should have been refused")
        say("REFUSED_PROJECT", f"{status} {raw.strip()}")

    status, issued, raw = c.request("POST", me_token, bearer=access_token,
                                    body={"project": args.project, "authorizations": authorizations})
    if status != 201 or not isinstance(issued, dict) or not issued.get("token"):
        fail(f"placement token request: HTTP {status}: {raw[:300]}")

    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(issued["token"].strip() + "\n")
    say("ACCOUNT", issued.get("ap_user_id", ""))
    say("TOKEN_SAVED", args.out)


if __name__ == "__main__":
    main()
