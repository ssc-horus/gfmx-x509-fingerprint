#!/usr/bin/env python3
"""
Structure-aware certificate mutator for differential testing (see crosscheck.py).

Each mutant takes a seed certificate and changes 1-3 DER elements: flips a content
byte, swaps in a tricky element (odd times, BMP/Universal strings, bad BOOLEANs,
non-minimal INTEGERs, SAN/SKI OIDs), duplicates or deletes an element, changes a tag,
re-encodes a length non-minimally or randomises contents; a few are truncated or get
a trailing byte. Lengths of the enclosing elements are re-encoded, so most mutants
still parse and exercise the deeper rules.

Usage: mutate.py OUT_DIR COUNT SEED [INPUT...]
  INPUT: certificate files or folders; default: the certificates in the vectors.
"""
import base64
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import gfmx as X  # noqa: E402

out, n, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
os.makedirs(out, exist_ok=True)
seeds = []
for path in sys.argv[4:]:
    for f in ([p for p, _ in X.expand([path])] if os.path.isdir(path) else [path]):
        seeds += X.load_file(f)
if not seeds:
    with open(os.path.join(HERE, "..", "testdata", "vectors.jsonl")) as fh:
        seeds = [base64.b64decode(json.loads(line)["der"]) for line in fh]
rnd = random.Random(seed)
def nodes(t, acc):
    acc.append(t)
    for c in t.children: nodes(c, acc)
    return acc
def enc_len(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length()+7)//8, 'big'); return bytes([0x80|len(b)]) + b
def rebuild(t, repl):
    # rebuild DER of t with node `repl[0]` replaced by bytes repl[1]
    if t is repl[0]: return repl[1]
    if not t.children: return t.raw
    body = b''.join(rebuild(c, repl) for c in t.children)
    # header: tag bytes then length; recompute length (minimal)
    tag_end = 1
    if t.raw[0] & 0x1f == 0x1f:
        while t.raw[tag_end] & 0x80: tag_end += 1
        tag_end += 1
    return t.raw[:tag_end] + enc_len(len(body)) + body
pool = [b'\x00', b'\x01', b'\xff', b'\x80', b'\x7f', b'\x30\x00', b'\x05\x00', b'\x01\x01\x00', b'\x01\x01\xff',
        b'\x02\x01\x00', b'\x02\x02\x00\x7f', b'\x17\x0d991231235959Z', b'\x18\x0f99991231235959Z',
        b'\x18\x0f20491231235959Z', b'\x17\x0b0001010000Z', b'\x18\x1120240101000000.5Z', b'\x06\x03\x55\x1d\x11',
        b'\x06\x03\x55\x1d\x0e', b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07', b'\x0c\x03abc', b'\x13\x03a_b', b'\x1e\x04\xd8\x00\x00a',
        b'\x1c\x04\x00\x00\x00a', b'\x86\x0chttp://x.y/z', b'\x86\x04ftp:', b'\xa0\x80']
for i in range(n):
    try:
        root, _ = X.parse_tlv(rnd.choice(seeds), 0)
    except Exception:
        continue
    d = None
    for _ in range(rnd.randint(1, 3)):
        ns = nodes(root, [])
        t = rnd.choice(ns); op = rnd.random()
        if op < 0.25 and len(t.content):          # flip content bytes, same length
            c = bytearray(t.content); j = rnd.randrange(len(c)); c[j] = rnd.randrange(256)
            new = t.raw[:len(t.raw)-len(t.content)] + bytes(c)
        elif op < 0.45:                            # replace node with a pool element
            new = rnd.choice(pool)
        elif op < 0.6 and len(ns) > 2:             # duplicate a sibling-ish node
            new = t.raw + rnd.choice(ns).raw
        elif op < 0.7:                             # delete node
            new = b''
        elif op < 0.8:                             # change tag byte
            new = bytes([rnd.randrange(256)]) + t.raw[1:]
        elif op < 0.9:                             # non-minimal length
            body = t.content; new = t.raw[:1] + b'\x82' + len(body).to_bytes(2, 'big') + body
        else:                                      # random content same length
            new = t.raw[:len(t.raw)-len(t.content)] + bytes(rnd.randrange(256) for _ in t.content)
        d = rebuild(root, (t, new))
        try: root, _ = X.parse_tlv(d, 0)
        except Exception: break
    if d is None: continue
    if rnd.random() < 0.05: d = d[:rnd.randrange(len(d)+1)]
    if rnd.random() < 0.03: d = d + b'\x00'
    open(os.path.join(out, f'm{seed}_{i:06d}.der'), 'wb').write(d)
