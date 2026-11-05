#!/usr/bin/env python3
"""
Match the generator's truth table against the fingerprint table.

Pass condition: blueprints and fingerprints map one-to-one.
  SPLIT  one blueprint got more than one fingerprint   -> noise leaked into the fingerprint
  MERGE  one fingerprint covers more than one blueprint -> fingerprint missed a real change

Merges are "expected" when the blueprints differ only in parameters the fingerprint
deliberately does not capture (OUT_OF_SCOPE). Every one-parameter mutant is also
checked against its parent: the fingerprint must change, and the report shows which
segment changed.

Usage: match.py truth.csv fingerprints.csv   (blueprints.json is read from truth.csv's folder)
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
from collections import defaultdict

SEGMENTS = ["key", "span", "maker", "audience", "names"]
# Blueprint parameters GFMX deliberately does not capture:
#   string_policy - removed from MAKER after the test bench (hidden by random names)
#   ca_name       - name *values* are instance data
#   ca_key        - the issuer's key size (only the signature algorithm is visible)
#   validity_impl - how a tool counts a given length (365 days vs 12 calendar months,
#                   month-end convention, local time vs UTC); invisible by design
OUT_OF_SCOPE = {"string_policy", "ca_name", "ca_key", "validity_impl"}
# Mutation kinds that are out of scope. MUST_NOT_CHANGE ones also fail the run if
# the fingerprint moves (the change is invisible by design, so a move means noise).
OUT_OF_SCOPE_KINDS = {"string type policy", "validity counting (same length)"}
MUST_NOT_CHANGE = {"validity counting (same length)"}

MUTATION_KINDS = [
    (r"^key ", "key type/size"), (r"^sig_hash", "signature hash"),
    (r"^validity counting", "validity counting (same length)"), (r"^validity", "validity length"),
    (r"^nb_align", "notBefore alignment"), (r"^end_offset", "end offset (-1s)"),
    (r"^serial", "serial style"), (r"^string_policy", "string type policy"),
    (r"^subject", "subject template"), (r"^issuance", "issuance (self/CA)"),
    (r"^add extension", "extension added"), (r"^remove extension", "extension removed"),
    (r"critical ->", "extension criticality"), (r"^swap order", "extension order"),
    (r"contents changed", "extension contents"),
]


def kind_of(change: str) -> str:
    for pat, name in MUTATION_KINDS:
        if re.search(pat, change):
            return name
    return change


def elements(raw: str) -> dict:
    out = {}
    for part in raw.replace("|", ";").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
        elif part:
            out[part] = ""
    return out


def table(rows: list, cols: list) -> None:
    if not rows:
        print("(none)")
        return
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


def bp_diff(a: dict, b: dict) -> list:
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))


def main() -> None:
    truth_path, fp_path = sys.argv[1], sys.argv[2]
    truth = {r["file"]: r for r in csv.DictReader(open(truth_path))}
    fps = {r["file"]: r for r in csv.DictReader(open(fp_path))}
    bps = json.load(open(os.path.join(os.path.dirname(truth_path) or ".", "blueprints.json")))

    missing = sorted(set(truth) - set(fps))
    joined = [dict(truth[f], **fps[f]) for f in truth if f in fps]

    bp_to_fp, fp_to_bp = defaultdict(set), defaultdict(set)
    for r in joined:
        bp_to_fp[r["blueprint"]].add(r["gfmx"])
        fp_to_bp[r["gfmx"]].add(r["blueprint"])
    split_bps = {b for b, s in bp_to_fp.items() if len(s) > 1}

    merges = []
    for fpv, group in fp_to_bp.items():
        if len(group) < 2:
            continue
        g = sorted(group)
        diffs = {p for i in range(len(g)) for j in range(i + 1, len(g))
                 for p in bp_diff(bps[g[i]]["blueprint"], bps[g[j]]["blueprint"])}
        merges.append({"gfmx": fpv, "blueprints": g, "params": sorted(diffs),
                       "expected": diffs <= OUT_OF_SCOPE})
    bad_merge_fps = {m["gfmx"] for m in merges if not m["expected"]}

    # ---- per-certificate table ----
    for r in joined:
        st = []
        if r["blueprint"] in split_bps:
            st.append("SPLIT")
        if r["gfmx"] in bad_merge_fps:
            st.append("MERGE")
        r["status"] = ",".join(st) or "ok"
    joined.sort(key=lambda r: (int(r["batch"]), r["file"]))
    print("== Per certificate ==")
    table(joined, ["file", "batch", "blueprint", "gfmx", "status"])

    # ---- per-blueprint table ----
    print("\n== Per blueprint ==")
    rows = []
    for b in sorted(bp_to_fp, key=lambda b: min(int(r["batch"]) for r in joined if r["blueprint"] == b)):
        certs = [r for r in joined if r["blueprint"] == b]
        o = bps[b]["origin"] or {}
        rows.append({"blueprint": b, "certs": len(certs), "batches": len({r["batch"] for r in certs}),
                     "fingerprints": len(bp_to_fp[b]), "gfmx": " / ".join(sorted(bp_to_fp[b])),
                     "origin": f"mutant of {o['parent']}: {o['change']}" if o.get("parent") else "fresh"})
    table(rows, ["blueprint", "certs", "batches", "fingerprints", "gfmx", "origin"])

    # ---- one-parameter mutants: did the fingerprint notice? ----
    print("\n== One-parameter changes (mutant vs parent) ==")
    by_kind = defaultdict(lambda: {"tested": 0, "detected": 0, "segments": defaultdict(int)})
    for b, info in bps.items():
        o = info["origin"] or {}
        p = o.get("parent")
        if not p or b not in bp_to_fp or p not in bp_to_fp:
            continue
        if len(bp_to_fp[b]) != 1 or len(bp_to_fp[p]) != 1:
            continue  # a split is reported separately
        k = kind_of(o["change"])
        child_fp, parent_fp = next(iter(bp_to_fp[b])), next(iter(bp_to_fp[p]))
        by_kind[k]["tested"] += 1
        if child_fp != parent_fp:
            by_kind[k]["detected"] += 1
            for i, seg in enumerate(SEGMENTS):
                if child_fp.split(":")[i] != parent_fp.split(":")[i]:
                    by_kind[k]["segments"][seg.upper()] += 1
    kind_rows = []
    for k, v in sorted(by_kind.items()):
        scope = ("must not change" if k in MUST_NOT_CHANGE else
                 "out of scope" if k in OUT_OF_SCOPE_KINDS else "")
        kind_rows.append({"change": k, "tested": v["tested"], "detected": v["detected"],
                          "segment(s) that moved": ", ".join(f"{s}" for s in v["segments"]) or "-",
                          "note": scope})
    table(kind_rows, ["change", "tested", "detected", "segment(s) that moved", "note"])

    # ---- splits ----
    seg_split = defaultdict(int)
    if split_bps:
        print("\n== SPLITS (noise leaked into the fingerprint) ==")
    for b in sorted(split_bps):
        certs = [r for r in joined if r["blueprint"] == b]
        print(f"\n{b}: {len(certs)} certs -> {len(bp_to_fp[b])} fingerprints")
        for i, seg in enumerate(SEGMENTS):
            if len({r["gfmx"].split(":")[i] for r in certs}) < 2:
                continue
            seg_split[seg] += 1
            variants = defaultdict(list)
            for r in certs:
                variants[r[f"raw_{seg}"]].append(r)
            parsed = {raw: elements(raw) for raw in variants}
            keys = sorted({k for p in parsed.values() for k in p})
            moved = [k for k in keys if len({p.get(k) for p in parsed.values()}) > 1]
            print(f"  segment {seg.upper()}: element(s) that moved: {', '.join(moved)}")
            for raw, rs in variants.items():
                vals = "; ".join(f"{k}={parsed[raw].get(k, '(absent)')}" for k in moved)
                ex = rs[0]
                print(f"    {len(rs):>3} cert(s): {vals}")
                print(f"        e.g. {ex['file']}  noise: not_before={ex['noise_not_before']} "
                      f"subject='{ex['noise_subject']}' san={ex['noise_san']}")

    # ---- merges ----
    if merges:
        print("\n== MERGES (one fingerprint, several blueprints) ==")
    for m in merges:
        tag = "expected (out of scope)" if m["expected"] else "UNEXPECTED"
        print(f"\n{m['gfmx']} covers {', '.join(m['blueprints'])} -> {tag}")
        print(f"    blueprints differ in: {', '.join(m['params']) or '(nothing)'}")

    # ---- verdict ----
    print("\n== Result ==")
    print(f"certificates: {len(joined)}   blueprints: {len(bp_to_fp)}   "
          f"distinct fingerprints: {len(fp_to_bp)}")
    print(f"blueprints with one stable fingerprint: {len(bp_to_fp) - len(split_bps)}/{len(bp_to_fp)}")
    in_scope = [r for r in kind_rows if not r["note"]]
    t = sum(r["tested"] for r in in_scope)
    d = sum(r["detected"] for r in in_scope)
    print(f"one-parameter changes detected (in scope): {d}/{t}")
    nc = [r for r in kind_rows if r["note"] == "must not change"]
    moved = sum(r["detected"] for r in nc)
    if nc:
        print(f"changes that must not move the fingerprint: {sum(r['tested'] for r in nc)} tested, "
              f"{moved} moved it")
    exp = sum(1 for m in merges if m["expected"])
    print(f"unexpected merges: {len(merges) - exp}   expected (out-of-scope) merges: {exp}")
    if seg_split:
        print("splits by segment: " + ", ".join(f"{k.upper()}={v}" for k, v in seg_split.items()))
    if missing:
        print(f"WARNING: {len(missing)} generated certificates have no fingerprint row")
    ok = not split_bps and not bad_merge_fps and not missing and d == t and moved == 0
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
