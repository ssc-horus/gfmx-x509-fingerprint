#!/usr/bin/env python3
"""
Add GFMX fingerprints to Suricata eve.json TLS events.

Suricata logs the server certificate and chain as base64 DER when the eve tls logger
has  custom: [..., certificate, chain]  (see suricata-gfmx.yaml). This filter reads
eve JSON lines and adds:
    tls.gfmx                fingerprint of the logged certificate
    tls.gfmx_chain          fingerprints of the chain, in order (when chain is logged)
    tls.gfmx_error          why tls.gfmx is null (only when it is)
    tls.gfmx_chain_errors   per chain entry, why it is null (only when one is)
A certificate that cannot be fingerprinted gets null and a reason, never a guess.
Other lines, including lines that are not JSON, pass through unchanged, so it can sit
in a log pipeline:

    tail -F eve.json | eve_gfmx.py > eve-gfmx.json
    eve_gfmx.py eve.json | jq 'select(.tls.gfmx | test(":28505f23:"))'

Imports the reference gfmx.py from the repository root (no other dependency).
"""
from __future__ import annotations

import base64
import json
import os
import sys
from functools import lru_cache

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
import gfmx  # noqa: E402


@lru_cache(maxsize=65536)
def fp(b64: str):
    """(fingerprint, None) or (None, reason)."""
    try:
        der = base64.b64decode(b64, validate=True)
    except ValueError:
        return None, "not base64"
    try:
        return gfmx.gfmx(der)["gfmx"], None
    except gfmx.GFMXError as e:
        return None, str(e) or "not a certificate"


def enrich(line: str) -> str:
    try:
        ev = json.loads(line)
    except ValueError:
        return line
    tls = ev.get("tls") if isinstance(ev, dict) else None
    if not isinstance(tls, dict) or not (tls.get("certificate") or tls.get("chain")):
        return line
    if tls.get("certificate"):
        tls["gfmx"], err = fp(tls["certificate"])
        if err:
            tls["gfmx_error"] = err
    if isinstance(tls.get("chain"), list):
        res = [fp(c) if isinstance(c, str) else (None, "not base64") for c in tls["chain"]]
        tls["gfmx_chain"] = [f for f, _ in res]
        if any(e for _, e in res):
            tls["gfmx_chain_errors"] = [e for _, e in res]
    return json.dumps(ev, separators=(",", ":")) + "\n"


def main() -> None:
    srcs = [open(p) for p in sys.argv[1:]] or [sys.stdin]
    for src in srcs:
        for line in src:
            sys.stdout.write(enrich(line))
            sys.stdout.flush() if src is sys.stdin else None


if __name__ == "__main__":
    main()
