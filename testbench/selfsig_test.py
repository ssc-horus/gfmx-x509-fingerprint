#!/usr/bin/env python3
"""
Self-signature check: every signature algorithm must give iss=s when the cert is
self-signed, and iss=n when the name matches but another key signed it (or the
signature is damaged). Legacy algorithms (MD5, SHA-1, DSA) are included on purpose:
the old check went through cryptography's verify_directly_issued_by, which refuses
them, so self-signed SHA-1/MD5/DSA certs came out as "n" (60% of a set of Android signing certificates).

Needs the openssl CLI (cryptography no longer signs with SHA-1/MD5).
Usage: selfsig_test.py
"""
from __future__ import annotations

import datetime as dt
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import gfmx  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

KEYS = {  # name -> openssl key generation
    "rsa": ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
    "rsapss": ["genpkey", "-algorithm", "RSA-PSS", "-pkeyopt", "rsa_keygen_bits:2048"],
    "dsa1k": None, "dsa2k": None,
    "p256": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
    "p384": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
    "p192": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime192v1"],
    "p224": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-224"],
    "p521": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"],
    "k256": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp256k1"],
    "bp256": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP256r1"],
    "bp384": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP384r1"],
    "bp512": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP512r1"],
    "p256c": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
              "-pkeyopt", "point-format:compressed"],
    "p224c": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-224",
              "-pkeyopt", "point-format:compressed"],
    "p256x": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
              "-pkeyopt", "ec_param_enc:explicit"],
    "p239": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime239v1"],
    "ed25519": ["genpkey", "-algorithm", "ed25519"],
    "ed448": ["genpkey", "-algorithm", "ed448"],
}
CASES = [  # (label, key, openssl req options)
    ("rsa-md5", "rsa", ["-md5"]), ("rsa-sha1", "rsa", ["-sha1"]),
    ("rsa-sha224", "rsa", ["-sha224"]), ("rsa-sha256", "rsa", ["-sha256"]),
    ("rsa-sha512", "rsa", ["-sha512"]), ("rsa-sha3-256", "rsa", ["-sha3-256"]),
    ("rsa-pss-sha256", "rsa", ["-sha256", "-sigopt", "rsa_padding_mode:pss"]),
    ("rsa-pss-sha1", "rsa", ["-sha1", "-sigopt", "rsa_padding_mode:pss"]),
    ("rsa-pss-sha512-salt0", "rsa", ["-sha512", "-sigopt", "rsa_padding_mode:pss",
                                     "-sigopt", "rsa_pss_saltlen:0"]),
    ("rsapss-key", "rsapss", ["-sha256"]),
    ("dsa1024-sha1", "dsa1k", ["-sha1"]), ("dsa2048-sha224", "dsa2k", ["-sha224"]),
    ("dsa2048-sha256", "dsa2k", ["-sha256"]),
    ("ecdsa-p256-sha1", "p256", ["-sha1"]), ("ecdsa-p256-sha256", "p256", ["-sha256"]),
    ("ecdsa-p384-sha384", "p384", ["-sha384"]), ("ecdsa-p256-sha3-256", "p256", ["-sha3-256"]),
    ("ecdsa-p192-sha256", "p192", ["-sha256"]), ("ecdsa-p224-sha224", "p224", ["-sha224"]),
    ("ecdsa-p521-sha512", "p521", ["-sha512"]), ("ecdsa-p521-sha1", "p521", ["-sha1"]),
    ("ecdsa-secp256k1-sha256", "k256", ["-sha256"]),
    ("ecdsa-bp256-sha256", "bp256", ["-sha256"]), ("ecdsa-bp384-sha384", "bp384", ["-sha384"]),
    ("ecdsa-bp512-sha512", "bp512", ["-sha512"]),
    ("ecdsa-p256-compressed", "p256c", ["-sha256"]),
    ("ecdsa-p224-compressed", "p224c", ["-sha256"]),  # p = 1 mod 4: Tonelli-Shanks
    ("ed25519", "ed25519", []), ("ed448", "ed448", []),
]
UNCHECKABLE = [  # (label, key, options): a curve outside the table gives "u"
    ("ecdsa-explicit-params", "p256x", ["-sha256"]),
    ("ecdsa-prime239v1", "p239", ["-sha256"]),
]


def ossl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def iss(der: bytes) -> str:
    return gfmx.gfmx(der)["raw"]["key"].split(";")[0].split("=")[1]


def wrong_signer(gen, h) -> list:
    """Same name, signed by a different key; and a damaged signature."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    a, b = gen(), gen()

    def build(signer):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(a.public_key()).serial_number(7)
                .not_valid_before(dt.datetime(2024, 1, 1))
                .not_valid_after(dt.datetime(2025, 1, 1))
                .sign(signer, h).public_bytes(serialization.Encoding.DER))
    good = build(a)
    damaged = bytearray(good)
    damaged[-1] ^= 1
    return [("self", good, "s"), ("other key", build(b), "n"), ("damaged", bytes(damaged), "n")]


def mldsa_cases() -> int:
    """ML-DSA-44/65/87 (FIPS 204, RFC 9881): self-signed, other key, damaged signature.
    Made with cryptography (the openssl CLI here may predate ML-DSA)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        print("ml-dsa                   skipped (cryptography without ML-DSA)")
        return 0
    fails = 0
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    for label, gen in (("ml-dsa-44", mldsa.MLDSA44PrivateKey.generate),
                       ("ml-dsa-65", mldsa.MLDSA65PrivateKey.generate),
                       ("ml-dsa-87", mldsa.MLDSA87PrivateKey.generate)):
        a, b = gen(), gen()

        def build(signer):
            return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(a.public_key()).serial_number(7)
                    .not_valid_before(dt.datetime(2026, 1, 1))
                    .not_valid_after(dt.datetime(2027, 1, 1))
                    .sign(signer, None).public_bytes(serialization.Encoding.DER))
        good = build(a)
        damaged = bytearray(good)
        damaged[-40] ^= 1
        for what, der, want in (("self", good, "s"), ("other key", build(b), "n"),
                                ("damaged", bytes(damaged), "n")):
            got = iss(der)
            fails += got != want
            print(f"{label + ' ' + what:24s} {want:6s} {got}{'' if got == want else '   <-- FAIL'}")
    return fails


def main() -> None:
    fails = 0
    with tempfile.TemporaryDirectory() as d:
        for k, cmd in KEYS.items():
            path = os.path.join(d, k + ".key")
            if cmd is None:
                ossl("dsaparam", "-genkey", "-out", path, "1024" if k == "dsa1k" else "2048")
            else:
                ossl(*cmd, "-out", path)
        print(f"{'case':24s} {'expect':6s} got")
        for label, key, opts in CASES:
            out = os.path.join(d, label + ".der")
            ossl("req", "-x509", "-new", "-subj", "/CN=t", "-days", "365", "-outform", "DER",
                 "-key", os.path.join(d, key + ".key"), "-out", out, *opts)
            got = iss(open(out, "rb").read())
            fails += got != "s"
            print(f"{label:24s} {'s':6s} {got}{'' if got == 's' else '   <-- FAIL'}")
        for label, key, opts in UNCHECKABLE:
            out = os.path.join(d, label + ".der")
            ossl("req", "-x509", "-new", "-subj", "/CN=t", "-days", "365", "-outform", "DER",
                 "-key", os.path.join(d, key + ".key"), "-out", out, *opts)
            got = iss(open(out, "rb").read())
            fails += got != "u"
            print(f"{label:24s} {'u':6s} {got}{'' if got == 'u' else '   <-- FAIL'}")
    gens = {"rsa": (lambda: rsa.generate_private_key(65537, 2048), hashes.SHA256()),
            "dsa": (lambda: dsa.generate_private_key(2048), hashes.SHA256()),
            "ecdsa": (lambda: ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()),
            "ecdsa-k1": (lambda: ec.generate_private_key(ec.SECP256K1()), hashes.SHA256()),
            "ecdsa-bp": (lambda: ec.generate_private_key(ec.BrainpoolP384R1()), hashes.SHA384()),
            "ed25519": (ed25519.Ed25519PrivateKey.generate, None),
            "ed448": (ed448.Ed448PrivateKey.generate, None)}
    for fam, (gen, h) in gens.items():
        for what, der, want in wrong_signer(gen, h):
            got = iss(der)
            fails += got != want
            print(f"{fam + ' ' + what:24s} {want:6s} {got}{'' if got == want else '   <-- FAIL'}")
    fails += mldsa_cases()
    print("PASS" if not fails else f"FAIL ({fails})")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
