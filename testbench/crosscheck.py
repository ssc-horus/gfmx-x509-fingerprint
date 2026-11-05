#!/usr/bin/env python3
"""
Differential test: run the reference (gfmx.py) and another implementation on the
same inputs and report any certificate where fingerprint, pre-hash strings, info or
parse-error status differ.

Usage: crosscheck.py OTHER_CLI INPUT...      e.g. crosscheck.py ./gfmx certs/ mutants/
OTHER_CLI must accept the reference's --json output contract.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REF = os.path.join(HERE, "..", "gfmx.py")


def run(cmd):
    out = subprocess.run(cmd + ["--json"], capture_output=True, text=True).stdout
    return {r["source"]: r for r in map(json.loads, out.splitlines())}


def main() -> int:
    other, inputs = sys.argv[1], sys.argv[2:]
    ref, oth = run([sys.executable, REF] + inputs), run([other] + inputs)
    diffs = sorted(set(ref) ^ set(oth))
    for k in sorted(set(ref) & set(oth)):
        a, b = ref[k], oth[k]
        if (a["error"] is None) != (b["error"] is None):
            diffs.append(k)
        elif a["error"] is None and (a["gfmx"], a["raw"], a["info"]) != (b["gfmx"], b["raw"], b["info"]):
            diffs.append(k)
    for k in diffs[:20]:
        print("DIFF", k, "\n  ref:", ref.get(k), "\n  oth:", oth.get(k))
    print(f"{len(ref)} certificates, {len(diffs)} differences")
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
