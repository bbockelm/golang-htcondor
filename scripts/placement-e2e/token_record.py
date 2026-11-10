#!/usr/bin/env python3
"""Print what a placement token says, as JSON.

A placement token is a capability token: the JWT carries an issuer, a jti
and "cap": true, but no subject or scope. Those -- and the project -- are
recorded in TOKENS_DATABASE when the token is minted, and the daemons read
them from there. This prints both halves:

  {"header": {...}, "payload": {...},
   "record": {"sub": ..., "scope": ..., "capability": ...},
   "extra_claims": {"project": ...}}

record is null when the database has no row for the token's jti.

Usage: token_record.py TOKEN_FILE TOKENS_DATABASE
"""

import base64
import json
import sqlite3
import sys


def b64json(part):
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        token = f.read().strip()
    header, payload, _sig = token.split(".")
    out = {"header": b64json(header), "payload": b64json(payload), "record": None, "extra_claims": {}}

    db = sqlite3.connect(f"file:{sys.argv[2]}?mode=ro", uri=True, timeout=30)
    try:
        row = db.execute(
            "SELECT token_sub, token_scope, capability FROM idtokens_minting WHERE token_jti = ?",
            (out["payload"]["jti"],)).fetchone()
        if row:
            out["record"] = {"sub": row[0], "scope": row[1], "capability": bool(row[2])}
        for claim, value in db.execute(
                "SELECT claim, value FROM idtokens_minting_extra_claims WHERE token_jti = ?",
                (out["payload"]["jti"],)):
            # Values are stored as JSON.
            try:
                out["extra_claims"][claim] = json.loads(value)
            except ValueError:
                out["extra_claims"][claim] = value
    finally:
        db.close()
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
