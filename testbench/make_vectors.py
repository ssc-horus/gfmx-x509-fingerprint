#!/usr/bin/env python3
"""
Build conformance vectors (testdata/vectors.jsonl) with the reference implementation.

Every implementation of GFMX must reproduce each vector exactly: the fingerprint,
every pre-hash string and the info field. Error vectors only require a parse error.

Usage: make_vectors.py OUT.jsonl LABEL=PATH[:N] ...
  PATH is a certificate file or folder; N limits how many are taken (evenly spaced,
  so the choice is reproducible). Duplicate certificates are dropped.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import gfmx  # noqa: E402


def main() -> None:
    out_path, specs = sys.argv[1], sys.argv[2:]
    seen, rows = set(), []
    for spec in specs:
        label, _, path = spec.partition("=")
        path, _, n = path.partition(":")
        ders = []
        for f in [p for p, _ in gfmx.expand([path])] if os.path.isdir(path) else [path]:
            for i, der in enumerate(gfmx.load_file(f)):
                ders.append((f"{label}/{os.path.basename(f)}" + (f"#{i}" if i else ""), der))
        if n:
            step = max(1, len(ders) // int(n))
            ders = ders[::step][:int(n)]
        for name, der in ders:
            h = hashlib.sha256(der).digest()
            if h in seen:
                continue
            seen.add(h)
            row = {"name": name, "der": base64.b64encode(der).decode()}
            try:
                r = gfmx.gfmx(der)
                row.update(gfmx=r["gfmx"], raw=r["raw"], info=r["info"])
            except gfmx.GFMXError:
                row["error"] = True
            rows.append(row)
    with open(out_path, "w") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"{len(rows)} vectors ({sum('error' in r for r in rows)} errors) -> {out_path}")


if __name__ == "__main__":
    main()
