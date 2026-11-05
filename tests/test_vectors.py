#!/usr/bin/env python3
"""Check gfmx.py against the conformance vectors (testdata/vectors.jsonl).

Runs under pytest or directly:  python3 tests/test_vectors.py
"""
import base64
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import gfmx  # noqa: E402


def load():
    with open(os.path.join(ROOT, "testdata", "vectors.jsonl")) as f:
        return [json.loads(line) for line in f]


def test_vectors():
    failures = []
    for v in load():
        der = base64.b64decode(v["der"])
        try:
            r = gfmx.gfmx(der)
        except gfmx.GFMXError as e:
            if not v.get("error"):
                failures.append(f"{v['name']}: unexpected error {e}")
            continue
        if v.get("error"):
            failures.append(f"{v['name']}: expected a parse error, got {r['gfmx']}")
        elif (r["gfmx"], r["raw"], r["info"]) != (v["gfmx"], v["raw"], v["info"]):
            failures.append(f"{v['name']}: got {r['gfmx']} want {v['gfmx']}")
    assert not failures, "\n".join(failures[:20])


if __name__ == "__main__":
    test_vectors()
    print(f"PASS ({len(load())} vectors)")
