#!/usr/bin/env python3
"""
Test-bench generator: blueprints + noise.

1. Pick a blueprint (stable configuration: key, signature hash, issuance,
   validity period and construction, serial style, string-type policy, subject
   template, extension list/order/criticality and contents).
2. noise.py fills the instance data (key, serial value, names, dates, SAN, URLs).
3. Make a few certs, then switch configuration and repeat. A switch is one of:
     fresh   - a brand-new random blueprint
     mutant  - a copy of an earlier blueprint with exactly ONE parameter changed
               (tests that the fingerprint notices every single real change)
     revisit - go back to an earlier blueprint (tests stability over time)

Writes certificates under blind random file names (so the fingerprinting tool learns
nothing from them), a truth table (truth.csv), and prints the parameter table.

Usage: gen_certs.py --out DIR [--blueprints 12] [--min 3] [--max 7] [--seed N]
                    [--revisit 0.25] [--special-rate 0.1]
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import random
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import (AuthorityInformationAccessOID, ExtendedKeyUsageOID,
                                   NameOID)

import noise

KEYS = ["rsa-2048", "rsa-2048", "rsa-3072", "rsa-4096", "ec-P256", "ec-P256",
        "ec-P384", "ec-P521", "ed-25519", "ed-448"]
HASHES = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}
# Validity: how a tool computes notAfter. "days"/"secs" = fixed duration,
# "cal" = calendar months (12 = 1 year), "end" = fixed end date.
VALIDITY = ([("days", n) for n in (7, 30, 90, 180, 365, 397, 730, 825, 3650, 10000)] +
            [("cal", n) for n in (1, 3, 6, 12, 24, 27, 120)] +
            [("secs", n) for n in (600, 3600, 43200)] +
            [("end", e) for e in ("9999", "2049")])
TIMEZONES = ["UTC", "UTC", "UTC", "Europe/Berlin", "America/New_York", "Australia/Sydney"]


def validity_class(unit: str, n) -> str:
    """The length a fingerprint can see. A fixed day count that calendar months can
    also produce (30, 90, 365, 730...) is the same class as those months: one cert
    cannot show which way it was counted. Different implementations of one class
    (clamp vs roll-over, UTC vs local time, 365 days vs 12 months) must not change
    the fingerprint."""
    if unit == "days":
        for m in range(max(1, round(n / 30.44) - 1), round(n / 30.44) + 2):
            if n in noise.calendar_spans(m):
                return f"cal:{m}"
    return f"{unit}:{n}"


def validity_impl(unit: str, n, rng: random.Random) -> dict:
    v = {"unit": unit, "n": n, "conv": None, "tz": None}
    if unit == "cal":
        v["conv"] = rng.choice(["clamp", "roll"])
    if unit in ("cal", "days"):
        v["tz"] = rng.choice(TIMEZONES)
    return v


def validity_text(v: dict) -> str:
    extra = "/".join(x for x in (v["conv"], v["tz"]) if x and x != "UTC")
    return f"{v['unit']}:{v['n']}" + (f"({extra})" if extra else "")
SERIAL_STYLES = ["rand64", "rand128", "rand159", "small", "timestamp"]
FIELDS = ["C", "ST", "L", "O", "OU", "CN", "emailAddress"]
FIELD_OID = {"C": NameOID.COUNTRY_NAME, "ST": NameOID.STATE_OR_PROVINCE_NAME,
             "L": NameOID.LOCALITY_NAME, "O": NameOID.ORGANIZATION_NAME,
             "OU": NameOID.ORGANIZATIONAL_UNIT_NAME, "CN": NameOID.COMMON_NAME,
             "emailAddress": NameOID.EMAIL_ADDRESS}
EKUS = {"serverAuth": ExtendedKeyUsageOID.SERVER_AUTH, "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
        "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
        "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
        "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING, "OCSPSigning": ExtendedKeyUsageOID.OCSP_SIGNING}
POLICY_OIDS = ["2.23.140.1.2.1", "2.23.140.1.2.2", "2.23.140.1.1", "1.3.6.1.4.1.99999.1.1",
               "1.3.6.1.4.1.99999.1.2"]
PRINTABLE_RE = re.compile(r"^[A-Za-z0-9 '()+,\-./:=?]*$")


# --------------------------------------------------------------------------- #
# Blueprints (stable configuration)
# --------------------------------------------------------------------------- #

def ku_bits_for(key: str, ca: bool, rng: random.Random) -> list:
    if key.startswith("rsa"):
        pool = ["digital_signature", "content_commitment", "key_encipherment", "data_encipherment"]
    elif key.startswith("ec"):
        pool = ["digital_signature", "content_commitment", "key_agreement"]
    else:
        pool = ["digital_signature", "content_commitment"]
    bits = sorted(rng.sample(pool, rng.randint(1, len(pool))))
    if ca:
        bits += ["key_cert_sign", "crl_sign"]
    return bits


# Subject templates real tools tend to use. Sharing a few templates across blueprints
# means NAMES alone can't tell blueprints apart, so the other segments must.
COMMON_SUBJECTS = [["CN"], ["C", "O", "CN"], ["O", "CN"], ["C", "ST", "L", "O", "OU", "CN"],
                   ["C", "O", "OU", "CN"], ["O"]]
EXT_KINDS = ["bc", "ku", "eku", "ski", "aki", "pol", "aia", "cdp"]


def new_ext(kind: str, key: str, is_ca: bool, rng: random.Random) -> dict:
    e = {"type": kind}
    if kind == "bc":
        e["critical"] = rng.random() < 0.7
        e["ca"] = is_ca
        e["path_len"] = rng.choice([None, 0, 1]) if is_ca else None
    elif kind == "ku":
        e["critical"] = rng.random() < 0.7
        e["bits"] = ku_bits_for(key, is_ca, rng)
    elif kind == "eku":
        e["critical"] = rng.random() < 0.1
        e["usages"] = sorted(rng.sample(list(EKUS), rng.randint(1, 3)))
    elif kind == "ski":
        e["critical"] = False
        e["method"] = rng.choice(["sha1", "sha256_trunc"])
    elif kind == "aki":
        e["critical"] = False
        e["form"] = rng.choice(["keyid", "keyid_issuer_serial"])
    elif kind == "pol":
        e["critical"] = False
        e["oids"] = sorted(rng.sample(POLICY_OIDS, rng.randint(1, 2)))
    elif kind in ("aia", "cdp"):
        e["critical"] = False
        e["scheme"] = rng.choice(["http", "ldap"])
    return e


def fix_signer(bp: dict, rng: random.Random) -> None:
    """Keep sig_hash consistent with whoever signs (EdDSA has no separate hash)."""
    signer = bp["key"] if bp["issuance"] == "self" else bp["ca_key"]
    if signer.startswith("ed"):
        bp["sig_hash"] = None
    elif bp["sig_hash"] is None:
        bp["sig_hash"] = rng.choice(list(HASHES))


def random_blueprint(rng: random.Random) -> dict:
    key = rng.choice(KEYS)
    issuance = rng.choice(["self", "self", "ca"])
    unit, n = rng.choice(VALIDITY)
    bp = {
        "key": key,
        "issuance": issuance,
        "ca_key": rng.choice(KEYS) if issuance == "ca" else None,
        "sig_hash": rng.choice(list(HASHES)),
        "validity": validity_class(unit, n),
        "validity_impl": validity_impl(unit, n, rng),
        "nb_align": rng.choice(["midnight", "any"]),
        "end_offset": "exact" if unit == "end" else rng.choice(["exact", "exact", "minus1s"]),
        "serial": rng.choice(SERIAL_STYLES),
        "string_policy": rng.choice(["printable_when_possible", "utf8_always"]),
    }
    fix_signer(bp, rng)
    if rng.random() < 0.8:
        bp["subject"] = list(rng.choice(COMMON_SUBJECTS))
    else:
        bp["subject"] = [f for f in FIELDS if rng.random() < 0.5] or ["CN"]
    is_ca = rng.random() < 0.2
    kinds = [k for k in EXT_KINDS if rng.random() < 0.5]
    rng.shuffle(kinds)
    bp["extensions"] = [new_ext(k, key, is_ca, rng) for k in kinds]
    if issuance == "ca":
        bp["ca_name"] = f"Bench CA {rng.randint(1000, 9999)}"
    return bp


def mutate(parent: dict, rng: random.Random) -> tuple[dict, str]:
    """Copy a blueprint and change exactly one configuration parameter.
    Returns (child, description). The fingerprint should change for every mutation
    except those listed as out of scope in match.py (string_policy)."""
    bp = json.loads(json.dumps(parent))
    exts = bp["extensions"]
    is_ca = any(e["type"] == "bc" and e["ca"] for e in exts) or \
        any(e["type"] == "ku" and "key_cert_sign" in e["bits"] for e in exts)
    options = ["key", "validity", "validity_impl", "nb_align", "serial", "string_policy",
               "subject", "issuance", "ext_add"]
    if bp["validity_impl"]["unit"] != "end":  # a fixed end date has no offset
        options.append("end_offset")
    if bp["sig_hash"]:
        options.append("sig_hash")
    if exts:
        options += ["ext_remove", "ext_critical", "ext_content"]
    if len(exts) >= 2:
        options.append("ext_order")
    what = rng.choice(options)

    def other(choices, current):
        return rng.choice([c for c in choices if c != current])

    if what == "key":
        old = bp["key"]
        bp["key"] = other(sorted(set(KEYS)), old)
        fix_signer(bp, rng)
        for e in exts:  # keep key usage valid for the new key type
            if e["type"] == "ku":
                e["bits"] = ku_bits_for(bp["key"], is_ca, random.Random(0))
        desc = f"key {old} -> {bp['key']}"
    elif what == "sig_hash":
        old = bp["sig_hash"]
        bp["sig_hash"] = other(list(HASHES), old)
        desc = f"sig_hash {old} -> {bp['sig_hash']}"
    elif what == "validity":  # a different length: the fingerprint must change
        old = validity_text(bp["validity_impl"])
        unit, n = rng.choice([u for u in VALIDITY if validity_class(*u) != bp["validity"]])
        bp["validity"], bp["validity_impl"] = validity_class(unit, n), validity_impl(unit, n, rng)
        if unit == "end":
            bp["end_offset"] = "exact"
        desc = f"validity {old} -> {validity_text(bp['validity_impl'])}"
    elif what == "validity_impl":  # same length, counted differently: must NOT change
        v = bp["validity_impl"]
        old = validity_text(v)
        same = [u for u in VALIDITY if validity_class(*u) == bp["validity"] and u[0] != "end"
                and u[0] != "secs"]
        if not same:
            return mutate(parent, rng)
        for _ in range(20):
            unit, n = rng.choice(same)
            nv = validity_impl(unit, n, rng)
            if nv != v:
                break
        else:
            return mutate(parent, rng)
        bp["validity_impl"] = nv
        desc = f"validity counting {old} -> {validity_text(nv)} (same length)"
    elif what == "nb_align":
        bp["nb_align"] = "any" if bp["nb_align"] == "midnight" else "midnight"
        desc = f"nb_align -> {bp['nb_align']}"
    elif what == "end_offset":
        bp["end_offset"] = "minus1s" if bp["end_offset"] == "exact" else "exact"
        desc = f"end_offset -> {bp['end_offset']}"
    elif what == "serial":
        old = bp["serial"]
        bp["serial"] = other(SERIAL_STYLES, old)
        desc = f"serial {old} -> {bp['serial']}"
    elif what == "string_policy":
        bp["string_policy"] = ("utf8_always" if bp["string_policy"] == "printable_when_possible"
                               else "printable_when_possible")
        desc = f"string_policy -> {bp['string_policy']}"
    elif what == "subject":
        old = bp["subject"]
        bp["subject"] = list(other([s for s in COMMON_SUBJECTS], old))
        desc = f"subject {','.join(old)} -> {','.join(bp['subject'])}"
    elif what == "issuance":
        if bp["issuance"] == "self":
            bp["issuance"], bp["ca_key"] = "ca", rng.choice(KEYS)
            bp["ca_name"] = f"Bench CA {rng.randint(1000, 9999)}"
        else:
            bp["issuance"], bp["ca_key"] = "self", None
            bp.pop("ca_name", None)
        fix_signer(bp, rng)
        desc = f"issuance -> {bp['issuance']}"
    elif what == "ext_add":
        missing = [k for k in EXT_KINDS if k not in {e["type"] for e in exts}]
        if not missing:
            return mutate(parent, rng)
        e = new_ext(rng.choice(missing), bp["key"], is_ca, rng)
        exts.insert(rng.randint(0, len(exts)), e)
        desc = f"add extension {e['type']}"
    elif what == "ext_remove":
        e = exts.pop(rng.randrange(len(exts)))
        desc = f"remove extension {e['type']}"
    elif what == "ext_critical":
        e = rng.choice(exts)
        e["critical"] = not e["critical"]
        desc = f"{e['type']} critical -> {e['critical']}"
    elif what == "ext_order":
        i, j = rng.sample(range(len(exts)), 2)
        exts[i], exts[j] = exts[j], exts[i]
        desc = f"swap order of {exts[j]['type']} and {exts[i]['type']}"
    else:  # ext_content
        e = rng.choice(exts)
        before = json.dumps(e, sort_keys=True)
        for _ in range(20):
            fresh = new_ext(e["type"], bp["key"], is_ca, rng)
            fresh["critical"] = e["critical"]
            if e["type"] == "bc":  # flip CA flag (path length alone is also fine)
                fresh["ca"] = not e["ca"]
                fresh["path_len"] = rng.choice([None, 0, 1]) if fresh["ca"] else None
            if json.dumps(fresh, sort_keys=True) != before:
                break
        else:
            return mutate(parent, rng)
        exts[exts.index(e)] = fresh
        desc = f"{e['type']} contents changed"
    if blueprint_id(bp) == blueprint_id(parent):
        return mutate(parent, rng)
    return bp, desc


def blueprint_id(bp: dict) -> str:
    canon = json.dumps(bp, sort_keys=True)
    return "BP-" + hashlib.sha1(canon.encode()).hexdigest()[:6]


# --------------------------------------------------------------------------- #
# Building certificates
# --------------------------------------------------------------------------- #

def pub_bits(pub) -> bytes:
    """Contents of the subjectPublicKey BIT STRING (what SKI hashes are computed over)."""
    if isinstance(pub, rsa.RSAPublicKey):
        return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def make_name(fields: list, policy: str) -> x509.Name:
    attrs = []
    for f, v in fields:
        if f == "C":
            t = _ASN1Type.PrintableString
        elif f == "emailAddress":
            t = _ASN1Type.IA5String
        elif policy == "printable_when_possible" and PRINTABLE_RE.match(v):
            t = _ASN1Type.PrintableString
        else:
            t = _ASN1Type.UTF8String
        attrs.append(x509.NameAttribute(FIELD_OID[f], v, _type=t))
    return x509.Name(attrs)


class CA:
    """One issuing CA per blueprint (part of the stable configuration)."""

    def __init__(self, bp: dict):
        self.key = noise.new_key(random.Random(), bp["ca_key"])
        self.name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bench"),
                               x509.NameAttribute(NameOID.COMMON_NAME, bp["ca_name"])])
        self.serial = random.getrandbits(64)


def build(bp: dict, inst: dict, ca: CA | None) -> x509.Certificate:
    key = inst["key"]
    pub = key.public_key()
    subject = make_name(inst["subject"], bp["string_policy"])
    if ca:
        issuer_name, issuer_pub, signer, issuer_serial = ca.name, ca.key.public_key(), ca.key, ca.serial
    else:
        issuer_name, issuer_pub, signer, issuer_serial = subject, pub, key, inst["serial"]

    exts = []
    for e in bp["extensions"]:
        t = e["type"]
        if t == "bc":
            ext = x509.BasicConstraints(ca=e["ca"], path_length=e["path_len"])
        elif t == "ku":
            b = set(e["bits"])
            ext = x509.KeyUsage(*(n in b for n in (
                "digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
                "key_agreement", "key_cert_sign", "crl_sign")), encipher_only=False, decipher_only=False)
        elif t == "eku":
            ext = x509.ExtendedKeyUsage([EKUS[u] for u in e["usages"]])
        elif t == "ski":
            bits = pub_bits(pub)
            digest = hashlib.sha1(bits).digest() if e["method"] == "sha1" else hashlib.sha256(bits).digest()[:20]
            ext = x509.SubjectKeyIdentifier(digest)
        elif t == "aki":
            kid = hashlib.sha1(pub_bits(issuer_pub)).digest()
            if e["form"] == "keyid":
                ext = x509.AuthorityKeyIdentifier(kid, None, None)
            else:
                ext = x509.AuthorityKeyIdentifier(kid, [x509.DirectoryName(issuer_name)], issuer_serial)
        elif t == "pol":
            ext = x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(o), None)
                                            for o in e["oids"]])
        elif t == "aia":
            url = f"{e['scheme']}://{inst['url_host']}/ca.crt"
            ext = x509.AuthorityInformationAccess([x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(url))])
        elif t == "cdp":
            url = f"{e['scheme']}://{inst['url_host']}/ca.crl"
            ext = x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(url)], relative_name=None,
                reasons=None, crl_issuer=None)])
        exts.append((ext, e["critical"]))

    # Noise: SAN present or not, at a random position in the extension order
    if inst["san"]:
        gns = [x509.DNSName(v) if k == "dns" else x509.IPAddress(__import__("ipaddress").ip_address(v))
               for k, v in inst["san"]["entries"]]
        pos = int(inst["san"]["position"] * (len(exts) + 1))
        exts.insert(pos, (x509.SubjectAlternativeName(gns), False))

    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(issuer_name).public_key(pub)
         .serial_number(inst["serial"])
         .not_valid_before(inst["not_before"]).not_valid_after(inst["not_after"]))
    for ext, crit in exts:
        b = b.add_extension(ext, crit)
    algo = None if isinstance(signer, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)) \
        else HASHES[bp["sig_hash"]]
    return b.sign(signer, algo)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def ext_summary(bp: dict) -> str:
    out = []
    for e in bp["extensions"]:
        t, bang = e["type"], "!" if e["critical"] else ""
        detail = {
            "bc": lambda: ("ca" + ("" if e["path_len"] is None else str(e["path_len"]))) if e["ca"] else "ee",
            "ku": lambda: ",".join(x[:2] for x in e["bits"]),
            "eku": lambda: ",".join(u[:3] for u in e["usages"]),
            "ski": lambda: e["method"],
            "aki": lambda: e["form"],
            "pol": lambda: str(len(e["oids"])),
            "aia": lambda: e["scheme"],
            "cdp": lambda: e["scheme"],
        }[t]()
        out.append(f"{t}{bang}({detail})")
    return " ".join(out) or "-"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--blueprints", type=int, default=12)
    ap.add_argument("--min", type=int, default=3)
    ap.add_argument("--max", type=int, default=7)
    ap.add_argument("--revisit", type=float, default=0.25,
                    help="chance a batch goes back to an earlier blueprint")
    ap.add_argument("--special-rate", type=float, default=0.1,
                    help="chance a name value contains a non-PrintableString character")
    ap.add_argument("--mutate", type=float, default=0.5,
                    help="chance a new configuration is a one-parameter mutant of an earlier one")
    ap.add_argument("--seed", type=int, default=None)
    a = ap.parse_args()

    rng = random.Random(a.seed)
    out = Path(a.out)
    (out / "certs").mkdir(parents=True, exist_ok=True)

    used: dict[str, dict] = {}      # id -> blueprint
    origin: dict[str, dict] = {}    # id -> how it was made
    cas: dict[str, CA] = {}
    rows = []
    batches = 0
    while len(used) < a.blueprints:
        if used and rng.random() < a.revisit:
            bid = rng.choice(sorted(used))
            bp, how = used[bid], "revisit"
        elif used and rng.random() < a.mutate:
            parent_id = rng.choice(sorted(used))
            bp, change = mutate(used[parent_id], rng)
            bid = blueprint_id(bp)
            how = f"mutant of {parent_id}: {change}"
            if bid not in used:
                origin[bid] = {"parent": parent_id, "change": change}
        else:
            bp = random_blueprint(rng)
            bid, how = blueprint_id(bp), "fresh"
            origin.setdefault(bid, {"parent": None, "change": None})
        used.setdefault(bid, bp)
        if bp["issuance"] == "ca" and bid not in cas:
            cas[bid] = CA(bp)
        batches += 1
        for _ in range(rng.randint(a.min, a.max)):
            inst = noise.fill(rng, bp, a.special_rate)
            cert = build(bp, inst, cas.get(bid))
            fname = f"{rng.getrandbits(48):012x}.pem"
            (out / "certs" / fname).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            rows.append({
                "file": fname, "batch": batches, "blueprint": bid, "origin": how,
                "key": bp["key"], "sig": bp["sig_hash"] or "-", "issuance": bp["issuance"],
                "validity": validity_text(bp["validity_impl"]), "nb_align": bp["nb_align"],
                "end_offset": bp["end_offset"], "serial": bp["serial"],
                "string_policy": bp["string_policy"], "subject": ",".join(bp["subject"]),
                "extensions": ext_summary(bp),
                # noise, for reference only
                "noise_not_before": inst["not_before"].isoformat(),
                "noise_san": "yes" if inst["san"] else "no",
                "noise_subject": " | ".join(v for _, v in inst["subject"]),
            })

    with open(out / "truth.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with open(out / "blueprints.json", "w") as f:
        json.dump({bid: {"blueprint": used[bid], "origin": origin.get(bid)} for bid in used},
                  f, indent=2, sort_keys=True)

    cols = ["file", "batch", "blueprint", "key", "sig", "issuance", "validity",
            "nb_align", "end_offset", "serial", "string_policy", "subject", "extensions", "origin"]
    widths = {c: max(len(c), *(len(str(r[c])) for r in rows)) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    for r in rows:
        print("  ".join(str(r[c]).ljust(widths[c]) for c in cols))
    print(f"\n{len(rows)} certificates, {len({r['blueprint'] for r in rows})} blueprints, "
          f"{batches} batches -> {out / 'certs'}  (truth: {out / 'truth.csv'})")


if __name__ == "__main__":
    main()
