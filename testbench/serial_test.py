#!/usr/bin/env python3
"""
Serial sign/padding check: a negative or non-minimally padded serial must not move
MAKER (or any other segment), and must be reported in the unhashed info as exactly
one ser= key. The test bench cannot make these: cryptography refuses negative
serials and noise.py only draws positive ones.

Negative serials come from openssl -set_serial. OpenSSL always writes the serial
minimally, so the padded ones get the pad byte added to the TBS, which is then
re-signed with openssl dgst (the cert stays validly self-signed).

Needs the openssl CLI (3.0+).
Usage: serial_test.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import gfmx  # noqa: E402

SERIAL = "0x1122334455667788"
CASES = [  # (label, -set_serial value, pad byte, expected ser= entries in info)
    ("positive", SERIAL, None, []),
    ("negative", "-" + SERIAL, None, ["ser=neg"]),
    ("zero-padded", SERIAL, b"\x00", ["ser=pad"]),
    ("padded negative", "-" + SERIAL, b"\xff", ["ser=neg,pad"]),
]


def ossl(*args: str) -> bytes:
    return subprocess.run(["openssl", *args], check=True, capture_output=True).stdout


def tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(lb)]) + lb + content


def pad_serial(der: bytes, pad: bytes, key: str, d: str) -> bytes:
    """Prefix the serial INTEGER's content with pad and re-sign the TBS with key."""
    cert, _ = gfmx.parse_tlv(der)
    tbs, sig_alg = cert.children[0], cert.children[1]
    parts = [c.raw for c in tbs.children]
    parts[1] = tlv(0x02, pad + tbs.children[1].content)  # [0] is the version
    new_tbs = tlv(0x30, b"".join(parts))
    path = os.path.join(d, "tbs.der")
    with open(path, "wb") as f:
        f.write(new_tbs)
    sig = ossl("dgst", "-sha256", "-sign", key, path)
    return tlv(0x30, new_tbs + sig_alg.raw + tlv(0x03, b"\x00" + sig))


def main() -> None:
    fails = 0
    base = None
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "rsa.key")
        ossl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key)
        print(f"{'case':16s} {'ser= in info':14s} {'MAKER':8s} fingerprint")
        for label, serial, pad, want in CASES:
            der = ossl("req", "-x509", "-new", "-key", key, "-subj", "/CN=t", "-sha256",
                       "-days", "365",
                       "-set_serial", serial, "-outform", "DER")
            if pad:
                der = pad_serial(der, pad, key, d)
            r = gfmx.gfmx(der)
            base = base or r
            ser = [kv for kv in r["info"].split(";") if kv.startswith("ser=")]
            maker_ok = r["raw"]["maker"] == base["raw"]["maker"]
            fp_ok = r["gfmx"] == base["gfmx"]
            ok = ser == want and maker_ok and fp_ok
            fails += not ok
            print(f"{label:16s} {','.join(ser) or '-':14s} {'same' if maker_ok else 'MOVED':8s} "
                  f"{'same' if fp_ok else 'MOVED'}{'' if ok else '   <-- FAIL'}")
    print("PASS" if not fails else f"FAIL ({fails})")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
