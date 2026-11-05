#!/usr/bin/env python3
"""
Add a gfmx column to the gfmx_der.log written by gfmx.zeek.

Reads Zeek TSV (with #fields header) or JSON logs, writes the same format with extra
'gfmx' and 'gfmx_error' fields (and drops the bulky 'der' column unless --keep-der).
A certificate that cannot be fingerprinted gets gfmx '-' (null in JSON) and the reason
in gfmx_error. Lines it cannot parse pass through unchanged.

    zeek_gfmx.py gfmx_der.log > gfmx.log
    zeek_gfmx.py --keep-der < gfmx_der.log
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
import gfmx  # noqa: E402


def fp(b64: str):
    """(fingerprint, None) or (None, reason)."""
    if not b64 or b64 == "-":
        return None, "no certificate"
    try:
        der = base64.b64decode(b64, validate=True)
    except ValueError:
        return None, "not base64"
    try:
        return gfmx.gfmx(der)["gfmx"], None
    except gfmx.GFMXError as e:
        return None, str(e) or "not a certificate"


def tsv(value) -> str:
    """Zeek TSV: '-' for unset; tabs and newlines escaped as Zeek does."""
    if value is None:
        return "-"
    return value.replace("\\", "\\x5c").replace("\t", "\\x09").replace("\n", "\\x0a")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", nargs="?")
    ap.add_argument("--keep-der", action="store_true")
    a = ap.parse_args()
    src = open(a.log) if a.log else sys.stdin
    fields = None
    for line in src:
        if line.startswith("{"):  # JSON logs
            try:
                rec = json.loads(line)
            except ValueError:
                sys.stdout.write(line)
                continue
            if not isinstance(rec, dict):
                sys.stdout.write(line)
                continue
            rec["gfmx"], rec["gfmx_error"] = fp(rec.get("der") or "")
            if not a.keep_der:
                rec.pop("der", None)
            print(json.dumps(rec))
        elif line.startswith("#fields"):
            fields = line.rstrip("\n").split("\t")[1:]
            out = [f for f in fields if a.keep_der or f != "der"] + ["gfmx", "gfmx_error"]
            print("#fields\t" + "\t".join(out))
        elif line.startswith("#types"):
            types = line.rstrip("\n").split("\t")[1:]
            kept = [t for f, t in zip(fields or [], types) if a.keep_der or f != "der"]
            print("#types\t" + "\t".join(kept + ["string", "string"]))
        elif line.startswith("#"):
            sys.stdout.write(line)
        elif fields:
            cells = line.rstrip("\n").split("\t")
            if len(cells) != len(fields):
                sys.stdout.write(line)
                continue
            row = dict(zip(fields, cells))
            vals = [row[f] for f in fields if a.keep_der or f != "der"]
            f, err = fp(row.get("der", ""))
            print("\t".join(vals + [tsv(f), tsv(err)]))
        else:
            sys.stdout.write(line)


if __name__ == "__main__":
    main()
