#!/usr/bin/env python3
"""
Build the certificates behind the specification 1-draft.2 limit vectors (hostile/oid_arcs_*,
hostile/mtc_log_*, hostile/dsa_*) by editing existing vectors: each limit gets the value
just inside it and the value just past it.

Usage: make_limit_certs.py testdata/vectors.jsonl OUTDIR
  then: make_vectors.py NEW.jsonl hostile=OUTDIR, and append NEW.jsonl to the vectors.
"""
import base64
import json
import os
import sys


def parse(buf, off=0):
    """(tag bytes, content bytes or children list, end) for one DER element."""
    i = off + 1
    if buf[off] & 0x1F == 0x1F:
        while buf[i] & 0x80:
            i += 1
        i += 1
    tag = buf[off:i]
    lb = buf[i]
    i += 1
    if lb & 0x80:
        n = lb & 0x7F
        ln = int.from_bytes(buf[i:i + n], "big")
        i += n
    else:
        ln = lb
    content = buf[i:i + ln]
    end = i + ln
    if tag[0] & 0x20:
        kids, j = [], 0
        while j < len(content):
            k = parse(content, j)
            kids.append(list(k[:2]))
            j = k[2]
        return tag, kids, end
    return tag, content, end


def enc(node):
    tag, body = node
    if isinstance(body, list):
        body = b"".join(enc(k) for k in body)
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(nb)]) + nb
    return tag + ln + body


def int_content(v):
    return v.to_bytes(v.bit_length() // 8 + 1, "big", signed=True)


def load(vectors, name):
    for line in open(vectors):
        r = json.loads(line)
        if r["name"] == name:
            der = base64.b64decode(r["der"])
            tag, body, _ = parse(der)
            return [tag, body]
    raise SystemExit(f"no vector {name}")


def tbs_fields(cert):
    return cert[1][0][1]  # cert -> tbs -> children


def main():
    vectors, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    made = {}

    # OID arc count: 2.5.29 followed by 1s, 128 arcs (rendered) and 129 arcs ("x").
    for total in (128, 129):
        cert = load(vectors, "hostile/oid_long_arc.der")
        exts = tbs_fields(cert)[-1][1][0][1]  # [3] -> SEQUENCE -> extensions
        oid = next(e[1][0] for e in exts if len(e[1][0][1]) > 64)
        oid[1] = b"\x55\x1d" + b"\x01" * (total - 2)
        made[f"oid_arcs_{total}.der"] = enc(cert)

    # MTC serial: log number of exactly 64 bits (rendered) and 65 bits ("x").
    for name, log in (("mtc_log_64bit.der", (1 << 64) - 1), ("mtc_log_65bit.der", 1 << 64)):
        cert = load(vectors, "pq/mtc_log3.der")
        f = tbs_fields(cert)
        serial = f[1] if f[0][0][0] == 0xA0 else f[0]
        serial[1] = int_content(log << 48 | 5)
        made[name] = enc(cert)

    # DSA g and y: as long as p (still checked) and one bit longer (unverifiable).
    for which in ("g", "y"):
        for extra, label in ((0, "eq"), (1, "over")):
            cert = load(vectors, "alg/c_dsa1k.der")
            f = tbs_fields(cert)
            spki = f[6] if f[0][0][0] == 0xA0 else f[5]
            params = spki[1][0][1][1][1]  # alg -> params SEQUENCE -> p, q, g
            pbits = int.from_bytes(params[0][1], "big", signed=True).bit_length()
            v = (1 << (pbits - 1 + extra)) | 3
            if which == "g":
                params[2][1] = int_content(v)
            else:
                spki[1][1][1] = b"\x00" + enc([b"\x02", int_content(v)])
            made[f"dsa_{which}_{label}_p.der"] = enc(cert)

    for name, der in made.items():
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(der)
    print(f"{len(made)} certificates -> {out}")


if __name__ == "__main__":
    main()
