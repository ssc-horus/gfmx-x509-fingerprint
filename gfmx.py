#!/usr/bin/env python3
"""
GFMX -- X.509 certificate template fingerprint (reference implementation).

    KEY:SPAN:MAKER:AUDIENCE:NAMES      e.g. 2116e00d:dc34f8dc:96d5c677::e52bbfa2

Each segment = first 8 hex chars of SHA-256 over a canonical pre-hash string.
An empty pre-hash string gives an empty segment (only AUDIENCE and NAMES can be empty).
The pre-hash strings are defined in docs/SPEC.md; docs/DESIGN.md explains why.

Input: the certificate's DER bytes. Standard library only, Python 3.11+.

  * KEY: issuance class, key algorithm and size or curve, signature algorithm.
    Issuance is s (self-signed, signature verifies), n (issuer == subject but it
    does not verify), u (issuer == subject, algorithm cannot be checked) or i
    (issued by another key). Every signature is verified here with plain integer
    math, so the answer never depends on a crypto library or its version.
  * SPAN: validity as a length (ISO 8601) and a kind (cal / exact / end...).
  * MAKER, AUDIENCE, NAMES: see docs/SPEC.md.

Library use:
    import gfmx
    gfmx.gfmx(der)["gfmx"]          # raises gfmx.GFMXError if not parseable

Command line:
    gfmx.py cert.pem certs/              # PEM (any number of certs), DER, folders
    gfmx.py -                            # stdin: PEM, DER, or one hex/base64 cert per line
    gfmx.py --host example.com:443       # live handshake, presented certificate
    gfmx.py --b64 MIIB...                # base64 DER
    add --raw for the pre-hash strings, --json for JSON lines, --csv FILE for a table
"""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import json
import os
import re
import socket
import ssl
import sys
from calendar import monthrange
from functools import lru_cache
from typing import List, Optional, Tuple

__version__ = "0.9.10"
SPEC_VERSION = "1-draft.3"  # the pre-hash definition this implementation follows
SEGMENTS = ("key", "span", "maker", "audience", "names")

# --------------------------------------------------------------------------- #
# Minimal DER reader that keeps the encoding details we need
# --------------------------------------------------------------------------- #


class TLV:
    __slots__ = ("cls", "constructed", "tagnum", "first", "content", "children",
                 "raw", "nonminimal_len")

    def __repr__(self) -> str:  # pragma: no cover
        return f"TLV({self.first:#04x}, len={len(self.content)})"


class DERError(ValueError):
    pass


# Real certificates nest about a dozen levels deep (policy qualifiers are the deepest).
# Input from scans is attacker-controlled, and an unbounded recursive parse lets a
# crafted certificate exhaust the stack, so anything deeper is rejected as malformed.
MAX_DEPTH = 64


def parse_tlv(buf: bytes, off: int = 0, depth: int = 0,
              tails: Optional[list] = None) -> Tuple[TLV, int]:
    """Parse one element and its children. Strict unless `tails` is a list: then a
    SEQUENCE that holds an OID and one value followed by bytes that do not parse keeps
    those two children, and the SEQUENCE is appended to `tails` (SPEC 3.1.1)."""
    if depth > MAX_DEPTH:
        raise DERError("nesting too deep")
    if off + 2 > len(buf):
        raise DERError("truncated header")
    t = TLV()
    first = buf[off]
    t.first = first
    t.cls = first >> 6
    t.constructed = bool(first & 0x20)
    tagnum = first & 0x1F
    i = off + 1
    if tagnum == 0x1F:
        tagnum = 0
        while True:
            if i >= len(buf):
                raise DERError("truncated tag")
            b = buf[i]
            i += 1
            tagnum = (tagnum << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    t.tagnum = tagnum
    if i >= len(buf):
        raise DERError("truncated header")
    lb = buf[i]
    i += 1
    t.nonminimal_len = False
    if lb < 0x80:
        length = lb
    elif lb == 0x80:
        raise DERError("indefinite length (BER)")
    else:
        n = lb & 0x7F
        lbytes = buf[i:i + n]
        if len(lbytes) != n:
            raise DERError("truncated length")
        length = int.from_bytes(lbytes, "big")
        i += n
        if length < 0x80 or lbytes[0] == 0:
            t.nonminimal_len = True
    end = i + length
    if end > len(buf):
        raise DERError("truncated content")
    t.content = buf[i:end]
    t.raw = buf[off:end]
    t.children = []
    if t.constructed:
        j = 0
        while j < len(t.content):
            try:
                child, j = parse_tlv(t.content, j, depth + 1, tails)
            except DERError:
                if (tails is not None and first == 0x30 and len(t.children) == 2
                        and t.children[0].first == 0x06):
                    tails.append(t)
                    break
                raise
            t.children.append(child)
    return t, end


MAX_ARC_BYTES = 64  # an arc encoded in more bytes is rendered as "x"
MAX_ARCS = 128      # an OID with more arcs is rendered as "x" as a whole


def decode_oid(content: bytes) -> str:
    """Dotted OID. An unterminated final arc is dropped. Arcs longer than
    MAX_ARC_BYTES (448 bits; UUID arcs under 2.25 need 19) are rendered as "x", and an
    OID with more than MAX_ARCS arcs as a whole is "x", which keeps hostile OIDs cheap,
    their rendering short, and the output identical across implementations."""
    arcs: List[object] = []
    val, n = 0, 0
    for b in content:
        n += 1
        if n <= MAX_ARC_BYTES:
            val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            if len(arcs) == MAX_ARCS:
                return "x"
            arcs.append(val if n <= MAX_ARC_BYTES else "x")
            val, n = 0, 0
    if not arcs:
        return ""
    first = arcs[0]
    if first == "x":
        head = [2, "x"]
    elif first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(a) for a in head + arcs[1:])


def small_uint(content: bytes) -> str:
    """Decimal value of a small unsigned INTEGER; "x" when the content exceeds 8 bytes."""
    return str(int.from_bytes(content, "big")) if len(content) <= 8 else "x"


def is_universal(t: TLV, num: int) -> bool:
    return t.cls == 0 and t.tagnum == num


def is_context(t: TLV, num: int) -> bool:
    return t.cls == 2 and t.tagnum == num


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

OID_SAN = "2.5.29.17"
OID_SKI = "2.5.29.14"
OID_AKI = "2.5.29.35"
OID_KU = "2.5.29.15"
OID_EKU = "2.5.29.37"
OID_BC = "2.5.29.19"
OID_POLICIES = "2.5.29.32"
OID_CDP = "2.5.29.31"
OID_AIA = "1.3.6.1.5.5.7.1.1"
OID_MS_TEMPLATE_NAME = "1.3.6.1.4.1.311.20.2"
OID_MS_TEMPLATE_INFO = "1.3.6.1.4.1.311.21.7"
OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
OID_CT_POISON = "1.3.6.1.4.1.11129.2.4.3"   # precertificate poison (RFC 6962)
OID_CT_SCTS = "1.3.6.1.4.1.11129.2.4.2"     # embedded SCT list (RFC 6962)
OID_ALT_SPKI = "2.5.29.72"                  # subjectAltPublicKeyInfo (X.509 hybrid)
OID_ALT_SIG_ALG = "2.5.29.73"               # altSignatureAlgorithm (X.509 hybrid)
OID_MTC = "1.3.6.1.5.5.7.6.67"              # id-alg-mtcProof (Merkle Tree Certificates)
OID_DSA = "1.2.840.10040.4.1"

# Left out of MAKER's extension list:
#   SAN       - present or absent depending on how the tool was invoked
#   CT poison / SCT list - a CT precertificate carries the poison, the final
#                certificate carries the SCT list instead; dropping both gives the
#                same GFMX whether the cert came from a CT log or a scan.
EXT_LIST_EXCLUDED = {OID_SAN, OID_CT_POISON, OID_CT_SCTS}

# Attributes whose ASN.1 string type is fixed by the standards, so the library
# made no choice (a wrong type here is recorded as an encoding violation instead).
FIXED_STRING_ATTRS = {
    "2.5.4.6": {0x13},                       # countryName: PrintableString
    "2.5.4.5": {0x13},                       # serialNumber: PrintableString
    "2.5.4.46": {0x13},                      # dnQualifier: PrintableString
    "1.2.840.113549.1.9.1": {0x16},          # emailAddress: IA5String
    "0.9.2342.19200300.100.1.25": {0x16},    # domainComponent: IA5String
}
STRING_TAGS = {0x13: "P", 0x0C: "U", 0x16: "I", 0x1E: "B", 0x14: "T", 0x1C: "V"}
PRINTABLE_RE = re.compile(r"^[A-Za-z0-9 '()+,\-./:=?]*$")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def h8(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:8] if s else ""


def parse_time(t: TLV) -> Tuple[Optional[dt.datetime], str, bool]:
    """Return (datetime, 'U'|'G', standard_format)."""
    s = t.content.decode("ascii", "replace")
    if is_universal(t, 23):  # UTCTime
        kind = "U"
        ok = bool(re.fullmatch(r"\d{12}Z", s))
        m = re.fullmatch(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z", s)
        if not m:
            return None, kind, False
        yy = int(m.group(1))
        year = 1900 + yy if yy >= 50 else 2000 + yy
        sec = int(m.group(6) or 0)
        try:
            d = dt.datetime(year, int(m.group(2)), int(m.group(3)), int(m.group(4)),
                            int(m.group(5)), sec)
        except ValueError:  # impossible date (e.g. 000000000000Z on embedded devices)
            return None, kind, False
        return d, kind, ok
    if is_universal(t, 24):  # GeneralizedTime
        kind = "G"
        ok = bool(re.fullmatch(r"\d{14}Z", s))
        m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(\.\d+)?Z", s)
        if not m:
            return None, kind, False
        try:
            d = dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                            int(m.group(4)), int(m.group(5)), int(m.group(6) or 0))
        except ValueError:
            return None, kind, False
        return d, kind, ok
    return None, "?", False


# --------------------------------------------------------------------------- #
# Validity span: length + kind
# --------------------------------------------------------------------------- #
# Tools count validity either in fixed units (openssl -days, keytool -validity,
# Go time.Duration) or in calendar units (Go AddDate, .NET AddYears/AddMonths, AD CS
# templates). A calendar span covers a different number of days depending on the
# start date (1 year = 365 or 366 days, 6 months = 181..184), so one cert cannot
# show which way it was counted: a 365-day cert may come from either kind of tool.
# The kind is therefore decided by the day count alone, never by the cert's dates:
#   cal    the count is one that N calendar months can produce -> length in Y/M
#   exact  no calendar span produces it -> length in exact days (or h/min/s)
#   end    a fixed end date (e.g. RFC 5280's 99991231235959Z) -> no length
# Every cert of a tool then gets the same length and kind, whatever its start date.

FIXED_ENDS = [  # (match, label)
    (lambda d: (d.year, d.month, d.day) == (9999, 12, 31), "9999"),  # RFC 5280 "no expiry"
    (lambda d: d == dt.datetime(2049, 12, 31, 23, 59, 59), "2049"),  # last UTCTime second
    (lambda d: d == dt.datetime(2038, 1, 19, 3, 14, 7), "2038"),     # 32-bit time_t limit
]
AVG_MONTH_DAYS = 146097 / 4800  # Gregorian 400-year cycle


@lru_cache(maxsize=None)
def calendar_days(months: int) -> Tuple[int, int]:
    """Fewest and most days that `months` calendar months can span, over every start
    date in a 400-year Gregorian cycle and both month-end conventions: clamp
    (Jan 31 + 1 month = Feb 28: .NET, Java, dateutil) and roll over
    (Jan 31 + 1 month = Mar 3: Go AddDate). Day-of-month 1..28 all behave like 1."""
    lo, hi = None, None
    for y in range(2000, 2400):
        for m in range(1, 13):
            yy, mm = divmod(m - 1 + months, 12)
            yy, mm = y + yy, mm + 1
            first = dt.date(yy, mm, 1).toordinal()
            tdim = monthrange(yy, mm)[1]
            for d in (1, 29, 30, 31):
                if d > monthrange(y, m)[1]:
                    continue
                start = dt.date(y, m, d).toordinal()
                for end in (first + min(d, tdim) - 1, first + d - 1):
                    span = end - start
                    lo = span if lo is None else min(lo, span)
                    hi = span if hi is None else max(hi, span)
    return lo, hi


def iso_months(n: int) -> str:
    y, m = divmod(n, 12)
    return "P" + (f"{y}Y" if y else "") + (f"{m}M" if m else "")


def half_up(x: float) -> int:
    return int(x + 0.5)  # x >= 0; avoids Python's round-half-to-even


def span_length(nb: dt.datetime, na: dt.datetime) -> Tuple[str, str]:
    """Return (length, kind) for the SPAN segment."""
    for match, label in FIXED_ENDS:
        if match(na):
            return "-", f"end{label}"
    dur = (na - nb).total_seconds()
    if dur < 0:
        return "-", "neg"
    if dur < 59.5:
        return f"PT{half_up(dur)}S", "exact"
    if dur < 3570:
        return f"PT{half_up(dur / 60)}M", "exact"
    if dur < 2 * 86400:
        return f"PT{half_up(dur / 3600)}H", "exact"
    days = half_up(dur / 86400)  # absorbs a -1 s end offset and a DST hour
    if 28 <= days <= 2_000_000:  # keeps calendar_days() inside year 9999
        n0 = half_up(days / AVG_MONTH_DAYS)
        for n in (n0 - 1, n0, n0 + 1):
            if n >= 1:
                lo, hi = calendar_days(n)
                if lo <= days <= hi:
                    return iso_months(n), "cal"
    return f"P{days}D", "exact"


def span_text(nb: dt.datetime, na: dt.datetime) -> str:
    """Exact span for the unhashed info column, e.g. 180d23:00:00."""
    s = int((na - nb).total_seconds())
    if s < 0:
        return "neg"
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{d}d{h:02d}:{m:02d}:{s:02d}"


def alg_params_code(alg: TLV) -> str:
    """AlgorithmIdentifier parameters: a=absent n=NULL o=OID s=SEQUENCE x=other."""
    if len(alg.children) < 2:
        return "a"
    p = alg.children[1]
    if is_universal(p, 5):
        return "n"
    if is_universal(p, 6):
        return "o"
    if is_universal(p, 16):
        return "s"
    return "x"


def expected_params(oid: str) -> Optional[str]:
    """What the standards require for this algorithm's parameters (None = unknown)."""
    if oid == "1.2.840.113549.1.1.10":          # RSASSA-PSS
        return "s"
    if oid.startswith("1.2.840.113549.1.1."):   # rsaEncryption, sha*WithRSAEncryption
        return "n"
    if oid == OID_EC:                           # ecPublicKey: named curve
        return "o"
    if oid.startswith("1.2.840.10045.4."):      # ecdsa-with-*
        return "a"
    if oid in ("1.3.101.112", "1.3.101.113"):   # Ed25519 / Ed448
        return "a"
    if oid.startswith("2.16.840.1.101.3.4.3."): # ML-DSA / SLH-DSA (NIST sigAlgs arc)
        return "a"
    if oid.startswith("2.16.840.1.101.3.4.4."): # ML-KEM (NIST KEMs arc)
        return "a"
    if oid == OID_MTC:                          # Merkle Tree Certificates proof
        return "a"
    return None


def alg_deviation(alg: TLV) -> Optional[str]:
    """Return a short code if the parameters deviate from the standard, else None.
    Keeps MAKER independent of key type: only library deviations are recorded."""
    oid = decode_oid(alg.children[0].content)
    got = alg_params_code(alg)
    want = expected_params(oid)
    if want is None:
        return f"?{got}"
    return None if got == want else f"{want}>{got}"


def key_detail(alg: TLV, bits: bytes) -> str:
    """Size or curve for KEY: RSA and RSA-PSS modulus size, EC named curve, DSA p size."""
    oid = decode_oid(alg.children[0].content)
    if oid in (OID_RSA, OID_RSA_PSS):
        try:
            rsa, _ = parse_tlv(bits, 0)
            return f"/{int.from_bytes(rsa.children[0].content, 'big').bit_length()}"
        except (DERError, IndexError):
            return "/?"
    if oid == OID_EC and len(alg.children) > 1 and is_universal(alg.children[1], 6):
        return "/" + decode_oid(alg.children[1].content)
    if oid == OID_DSA:  # "/-" when the parameters are inherited
        params = alg.children[1] if len(alg.children) > 1 else None
        if params is None or not params.children or not is_universal(params.children[0], 2):
            return "/-"
        return f"/{int.from_bytes(params.children[0].content, 'big').bit_length()}"
    return ""


def alt_key_part(v: Optional[TLV]) -> str:
    """Algorithm and size of a subjectAltPublicKeyInfo value; "-" if absent, "?" if malformed."""
    if v is None:
        return "-"
    try:
        alg = v.children[0]
        return decode_oid(alg.children[0].content) + key_detail(alg, v.children[1].content[1:])
    except IndexError:
        return "?"


def alt_sig_part(v: Optional[TLV]) -> str:
    """Algorithm of an altSignatureAlgorithm value; "-" if absent, "?" if malformed."""
    if v is None:
        return "-"
    try:
        return decode_oid(v.children[0].content)
    except IndexError:
        return "?"


def walk(t: TLV, flags: set, serial: Optional[TLV] = None) -> None:
    """Collect DER rule violations anywhere in the tree. The serial is left out of the
    INTEGER check: whether a padded or raw-bytes serial is minimally encoded depends on
    its random value (a tool that always prefixes 0x00 is non-minimal half the time)."""
    if t.nonminimal_len:
        flags.add("len")
    if is_universal(t, 1):  # BOOLEAN
        if len(t.content) != 1 or t.content[0] not in (0x00, 0xFF):
            flags.add("bool")
    if is_universal(t, 2) and len(t.content) > 1 and t is not serial:  # INTEGER
        c0, c1 = t.content[0], t.content[1]
        if (c0 == 0x00 and c1 < 0x80) or (c0 == 0xFF and c1 >= 0x80):
            flags.add("int")
    for c in t.children:
        walk(c, flags, serial)


def find_uris(t: TLV, out: List[str]) -> None:
    """Collect GeneralName uniformResourceIdentifier ([6] IA5String) values."""
    if is_context(t, 6) and not t.constructed:
        out.append(t.content.decode("ascii", "replace"))
    for c in t.children:
        find_uris(c, out)


def uri_scheme(u: str) -> str:
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*):", u)
    return m.group(1).lower() if m else "?"


# --------------------------------------------------------------------------- #
# Self-signature check
# --------------------------------------------------------------------------- #
# The issuance class must not depend on a crypto library's algorithm policy (e.g.
# cryptography's verify_directly_issued_by refuses SHA-1, MD5 and DSA, which turned
# 60% of APK signing certs into "n"). Every algorithm is verified here with plain
# integer math, for any digest: RSA (PKCS#1 v1.5 and PSS), DSA, ECDSA on the named
# curves in EC_CURVES, Ed25519 and Ed448. A signature algorithm, digest or curve we
# cannot check gives "u", the same answer on every machine.

_D = "2.16.840.1.101.3.4.2."
DIGEST_OIDS = {"1.2.840.113549.2.5": "md5", "1.3.14.3.2.26": "sha1",
               _D + "4": "sha224", _D + "1": "sha256", _D + "2": "sha384", _D + "3": "sha512",
               _D + "5": "sha512_224", _D + "6": "sha512_256", _D + "7": "sha3_224",
               _D + "8": "sha3_256", _D + "9": "sha3_384", _D + "10": "sha3_512"}
_R, _S = "1.2.840.113549.1.1.", "2.16.840.1.101.3.4.3."
SIG_ALGS = {  # signature OID -> (family, digest)
    _R + "4": ("rsa", "md5"), _R + "5": ("rsa", "sha1"), "1.3.14.3.2.29": ("rsa", "sha1"),
    _R + "14": ("rsa", "sha224"), _R + "11": ("rsa", "sha256"), _R + "12": ("rsa", "sha384"),
    _R + "13": ("rsa", "sha512"), _R + "15": ("rsa", "sha512_224"), _R + "16": ("rsa", "sha512_256"),
    _S + "13": ("rsa", "sha3_224"), _S + "14": ("rsa", "sha3_256"),
    _S + "15": ("rsa", "sha3_384"), _S + "16": ("rsa", "sha3_512"),
    _R + "10": ("pss", None),
    "1.2.840.10040.4.3": ("dsa", "sha1"), "1.3.14.3.2.27": ("dsa", "sha1"),
    _S + "1": ("dsa", "sha224"), _S + "2": ("dsa", "sha256"), _S + "3": ("dsa", "sha384"),
    _S + "4": ("dsa", "sha512"), _S + "5": ("dsa", "sha3_224"), _S + "6": ("dsa", "sha3_256"),
    _S + "7": ("dsa", "sha3_384"), _S + "8": ("dsa", "sha3_512"),
    "1.2.840.10045.4.1": ("ecdsa", "sha1"), "1.2.840.10045.4.3.1": ("ecdsa", "sha224"),
    "1.2.840.10045.4.3.2": ("ecdsa", "sha256"), "1.2.840.10045.4.3.3": ("ecdsa", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa", "sha512"), _S + "9": ("ecdsa", "sha3_224"),
    _S + "10": ("ecdsa", "sha3_256"), _S + "11": ("ecdsa", "sha3_384"),
    _S + "12": ("ecdsa", "sha3_512"),
    "1.3.101.112": ("eddsa", None), "1.3.101.113": ("eddsa", None),
    _S + "17": ("mldsa", None), _S + "18": ("mldsa", None), _S + "19": ("mldsa", None),
}
OID_RSA_PSS = _R + "10"

# The modular exponentiation below costs roughly (exponent bits) x (modulus bits)^2, and
# both come from the certificate. A crafted 32768-bit key with a 32768-bit exponent
# took 33 s for one certificate. Keys beyond these limits are not checked and give "u",
# the same answer on every machine. Real keys are far inside them (Go's crypto/rsa caps
# e at 31 bits, OpenSSL at 64 bits for large moduli). DSA is capped lower because it
# needs two full-size exponentiations: a 16384-bit p took ~0.1 s in Go and far longer
# here, while FIPS 186 DSA stops at 3072 bits.
MAX_MODULUS_BITS = 16384
MAX_RSA_EXP_BITS = 64
MAX_DSA_P_BITS = 4096
MAX_DSA_Q_BITS = 512


class Unverifiable(Exception):
    """The signature algorithm (or its digest) cannot be checked here."""


def digest(name: str, data: bytes) -> bytes:
    try:
        return hashlib.new(name, data, usedforsecurity=False).digest()
    except (ValueError, TypeError):
        raise Unverifiable(name)


def _int(t: TLV) -> int:
    return int.from_bytes(t.content, "big", signed=True)


def _rsa_key(spki: TLV) -> Tuple[int, int]:
    key, _ = parse_tlv(spki.children[1].content[1:], 0)
    n, e = _int(key.children[0]), _int(key.children[1])
    if n.bit_length() > MAX_MODULUS_BITS or e.bit_length() > MAX_RSA_EXP_BITS:
        raise Unverifiable("rsa key too large")
    return n, e


def _mgf1(seed: bytes, length: int, h: str) -> bytes:
    out, c = b"", 0
    while len(out) < length:
        out += digest(h, seed + c.to_bytes(4, "big"))
        c += 1
    return out[:length]


def _pss_hashes(params: Optional[TLV]) -> Tuple[str, str]:
    """(message digest, MGF1 digest) from RSASSA-PSS-params; defaults are SHA-1."""
    h = mgf = "sha1"
    for p in (params.children if params is not None else []):
        if p.cls == 2 and p.tagnum == 0:
            h = DIGEST_OIDS.get(decode_oid(p.children[0].children[0].content), "?")
        elif p.cls == 2 and p.tagnum == 1:
            mgf_alg = p.children[0]
            if len(mgf_alg.children) < 2:
                raise Unverifiable("mgf")
            mgf = DIGEST_OIDS.get(decode_oid(mgf_alg.children[1].children[0].content), "?")
    if "?" in (h, mgf):
        raise Unverifiable("pss digest")
    return h, mgf


def verify_rsa(spki: TLV, tbs: bytes, sig: bytes, h: Optional[str]) -> bool:
    n, e = _rsa_key(spki)
    k = (n.bit_length() + 7) // 8
    s = int.from_bytes(sig, "big")
    if not 0 < s < n or e <= 0:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    if em[:2] != b"\x00\x01":
        return False
    sep = em.find(b"\x00", 2)
    if sep < 10 or em[2:sep] != b"\xff" * (sep - 2):
        return False
    t = em[sep + 1:]
    try:  # DigestInfo: use the digest the signer actually embedded
        di, end = parse_tlv(t, 0)
        if end == len(t) and len(di.children) == 2 and is_universal(di.children[1], 4):
            name = DIGEST_OIDS.get(decode_oid(di.children[0].children[0].content))
            if name:
                return di.children[1].content == digest(name, tbs)
    except (DERError, IndexError):
        pass
    if h is None:
        raise Unverifiable("rsa digest")
    return t == digest(h, tbs)  # bare digest without DigestInfo (very old signers)


def verify_pss(spki: TLV, tbs: bytes, sig: bytes, params: Optional[TLV]) -> bool:
    h, mh = _pss_hashes(params)
    n, e = _rsa_key(spki)
    s = int.from_bytes(sig, "big")
    if not 0 < s < n:
        return False
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    m = pow(s, e, n)
    if m.bit_length() > 8 * em_len:  # RFC 8017 I2OSP "integer too large": invalid
        return False
    em = m.to_bytes(em_len, "big")
    h_len = len(digest(h, b""))
    if em[-1] != 0xBC or em_len < h_len + 2:
        return False
    masked, hh = em[:em_len - h_len - 1], em[em_len - h_len - 1:-1]
    top = 8 * em_len - em_bits
    if masked[0] >> (8 - top) if top else 0:
        return False
    db = bytearray(a ^ b for a, b in zip(masked, _mgf1(hh, len(masked), mh)))
    if top:
        db[0] &= 0xFF >> top
    i = 0
    while i < len(db) and db[i] == 0:
        i += 1
    if i == len(db) or db[i] != 1:
        return False
    salt = bytes(db[i + 1:])  # salt length taken from the encoding itself
    return digest(h, b"\x00" * 8 + digest(h, tbs) + salt) == hh


def verify_dsa(spki: TLV, tbs: bytes, sig: bytes, h: str) -> bool:
    params = spki.children[0].children[1:] if len(spki.children[0].children) > 1 else []
    if not params or not params[0].children:
        raise Unverifiable("dsa params inherited")
    p, q, g = (_int(c) for c in params[0].children[:3])
    if (p.bit_length() > MAX_DSA_P_BITS or q.bit_length() > MAX_DSA_Q_BITS
            or g.bit_length() > p.bit_length()):
        raise Unverifiable("dsa key too large")
    if p < 2 or q < 2:
        return False
    y = _int(parse_tlv(spki.children[1].content[1:], 0)[0])
    if y.bit_length() > p.bit_length():  # g and y longer than p cost time, never verify more
        raise Unverifiable("dsa key too large")
    rs, _ = parse_tlv(sig, 0)
    r, s = _int(rs.children[0]), _int(rs.children[1])
    if not (0 < r < q and 0 < s < q):
        return False
    z = int.from_bytes(digest(h, tbs)[:(q.bit_length() + 7) // 8], "big")
    if len(digest(h, b"")) * 8 > q.bit_length():
        z >>= max(0, ((q.bit_length() + 7) // 8) * 8 - q.bit_length())
    w = pow(s, -1, q)
    v = (pow(g, z * w % q, p) * pow(y, r * w % q, p)) % p % q
    return v == r


EC_CURVES = {  # named curve OID -> (name, p, a, b, Gx, Gy, n); all have cofactor 1
    "1.2.840.10045.3.1.1": ("prime192v1",
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC,
        0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1,
        0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
        0x7192B95FFC8DA78631011ED6B24CDD573F977A11E794811,
        0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831,
    ),
    "1.3.132.0.33": ("secp224r1",
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE,
        0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4,
        0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
        0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,
    ),
    "1.2.840.10045.3.1.7": ("prime256v1",
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    ),
    "1.3.132.0.34": ("secp384r1",
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
        0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    ),
    "1.3.132.0.35": ("secp521r1",
        0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC,
        0x51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
        0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
        0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
        0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
    ),
    "1.3.132.0.10": ("secp256k1",
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        0x0,
        0x7,
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    ),
    "1.3.36.3.3.2.8.1.1.7": ("brainpoolP256r1",
        0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377,
        0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9,
        0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6,
        0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262,
        0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997,
        0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7,
    ),
    "1.3.36.3.3.2.8.1.1.11": ("brainpoolP384r1",
        0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53,
        0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826,
        0x4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11,
        0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E,
        0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315,
        0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565,
    ),
    "1.3.36.3.3.2.8.1.1.13": ("brainpoolP512r1",
        0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3,
        0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA,
        0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723,
        0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822,
        0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892,
        0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069,
    ),
}


# ECDSA and EdDSA are verified with plain integer math too, so the result never
# depends on which curves or encodings a crypto library happens to accept. ECDSA
# covers the named prime curves below (all cofactor 1); any other curve, explicit
# curve parameters included, gives "u". These checks run only on certificates whose
# issuer and subject are identical, and speed is not a goal here.

def _ec_add(P, Q, a: int, p: int):
    """Affine point addition on y^2 = x^3 + ax + b; None is the point at infinity."""
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p


def _ec_mul2(k1: int, P, k2: int, Q, a: int, p: int):
    """k1*P + k2*Q (Shamir's trick)."""
    PQ = _ec_add(P, Q, a, p)
    R = None
    for i in range(max(k1.bit_length(), k2.bit_length()) - 1, -1, -1):
        R = _ec_add(R, R, a, p)
        b1, b2 = (k1 >> i) & 1, (k2 >> i) & 1
        if b1 and b2:
            R = _ec_add(R, PQ, a, p)
        elif b1:
            R = _ec_add(R, P, a, p)
        elif b2:
            R = _ec_add(R, Q, a, p)
    return R


def _sqrt_mod(v: int, p: int) -> Optional[int]:
    """A square root of v mod an odd prime p (Tonelli-Shanks), or None."""
    v %= p
    if v == 0:
        return 0
    if pow(v, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(v, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q, s = q // 2, s + 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(v, q, p), pow(v, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2, i = t2 * t2 % p, i + 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, b * b % p, t * b * b % p, r * b % p
    return r


def _ec_point(data: bytes, curve) -> Optional[Tuple[int, int]]:
    """Decode an uncompressed (04) or compressed (02/03) point; None if invalid."""
    _, p, a, b = curve[:4]
    flen = (p.bit_length() + 7) // 8
    if len(data) == 1 + 2 * flen and data[0] == 4:
        x = int.from_bytes(data[1:1 + flen], "big")
        y = int.from_bytes(data[1 + flen:], "big")
    elif len(data) == 1 + flen and data[0] in (2, 3):
        x = int.from_bytes(data[1:], "big")
        if x >= p:
            return None
        y = _sqrt_mod(x * x * x + a * x + b, p)
        if y is None:
            return None
        if y & 1 != data[0] & 1:
            y = (p - y) % p
    else:
        return None
    if x >= p or y >= p or (y * y - (x * x * x + a * x + b)) % p:
        return None
    return x, y


def _der_sig_pair(sig: bytes) -> Optional[Tuple[int, int]]:
    """(r, s) from a strictly DER-encoded Ecdsa-Sig-Value, else None."""
    try:
        t, end = parse_tlv(sig, 0)
    except DERError:
        return None
    if end != len(sig) or not is_universal(t, 16) or len(t.children) != 2 or t.nonminimal_len:
        return None
    out = []
    for c in t.children:
        b = c.content
        if (not is_universal(c, 2) or c.nonminimal_len or not b or b[0] & 0x80
                or (len(b) > 1 and b[0] == 0 and b[1] < 0x80)):
            return None
        out.append(int.from_bytes(b, "big"))
    return out[0], out[1]


def verify_ecdsa(spki: TLV, tbs: bytes, sig: bytes, h: str) -> bool:
    alg = spki.children[0]
    if decode_oid(alg.children[0].content) != OID_EC:
        return False
    if len(alg.children) < 2 or not is_universal(alg.children[1], 6):
        raise Unverifiable("ec params")  # explicit or inherited curve parameters
    curve = EC_CURVES.get(decode_oid(alg.children[1].content))
    if curve is None:
        raise Unverifiable("ec curve")
    _, p, a, _, gx, gy, n = curve
    Q = _ec_point(spki.children[1].content[1:], curve)
    rs = _der_sig_pair(sig)
    if Q is None or rs is None:
        return False
    r, s = rs
    if not (0 < r < n and 0 < s < n):
        return False
    d = digest(h, tbs)
    e = int.from_bytes(d, "big") >> max(0, 8 * len(d) - n.bit_length())
    w = pow(s, -1, n)
    X = _ec_mul2(e * w % n, (gx, gy), r * w % n, Q, a, p)
    return X is not None and X[0] % n == r


# EdDSA (RFC 8032), affine Edwards arithmetic. Verification recomputes R = [S]B - [k]A
# and compares its encoding with the R bytes in the signature (cofactorless; S must be
# below the group order L; A must be a canonical encoding of a curve point).
_P25519 = 2 ** 255 - 19
_P448 = 2 ** 448 - 2 ** 224 - 1
ED_CURVES = {  # OID -> (name, p, a, d, L, Bx, By, encoded length)
    "1.3.101.112": ("ed25519", _P25519, -1, -121665 * pow(121666, -1, _P25519) % _P25519,
                    2 ** 252 + 27742317777372353535851937790883648493,
                    0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A,
                    0x6666666666666666666666666666666666666666666666666666666666666658, 32),
    "1.3.101.113": ("ed448", _P448, 1, _P448 - 39081,
                    2 ** 446 - 13818066809895115352007386748515426880336692474882178609894547503885,
                    224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710,
                    298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660,
                    57),
}


def _ed_add(P, Q, c):
    _, p, a, d = c[:4]
    (x1, y1), (x2, y2) = P, Q
    t = d * x1 * x2 * y1 * y2 % p
    x3 = (x1 * y2 + y1 * x2) * pow(1 + t, -1, p) % p
    y3 = (y1 * y2 - a * x1 * x2) * pow(1 - t, -1, p) % p
    return x3, y3


def _ed_mul(k: int, P, c):
    R = (0, 1)
    for i in range(k.bit_length() - 1, -1, -1):
        R = _ed_add(R, R, c)
        if (k >> i) & 1:
            R = _ed_add(R, P, c)
    return R


def _ed_encode(P, c) -> bytes:
    x, y = P
    n = c[7]
    return (y | ((x & 1) << (8 * n - 1))).to_bytes(n, "little")


def _ed_decode(b: bytes, c) -> Optional[Tuple[int, int]]:
    _, p, a, d = c[:4]
    n = c[7]
    if len(b) != n:
        return None
    v = int.from_bytes(b, "little")
    sign = v >> (8 * n - 1)
    y = v & ((1 << (8 * n - 1)) - 1)
    if y >= p:
        return None
    # a x^2 + y^2 = 1 + d x^2 y^2  ->  x^2 = (y^2 - 1) / (d y^2 - a)
    x = _sqrt_mod((y * y - 1) * pow(d * y * y - a, -1, p), p)
    if x is None or (x == 0 and sign):
        return None
    if x & 1 != sign:
        x = p - x
    return x, y


def verify_eddsa(spki: TLV, tbs: bytes, sig: bytes, oid: str) -> bool:
    if decode_oid(spki.children[0].children[0].content) != oid:
        return False
    c = ED_CURVES[oid]
    _, p, _, _, L, bx, by, n = c
    A = _ed_decode(spki.children[1].content[1:], c)
    if A is None or len(sig) != 2 * n:
        return False
    S = int.from_bytes(sig[n:], "little")
    if S >= L:
        return False
    msg = sig[:n] + spki.children[1].content[1:] + tbs
    if n == 32:
        k = int.from_bytes(hashlib.sha512(msg).digest(), "little")
    else:
        k = int.from_bytes(hashlib.shake_256(b"SigEd448\x00\x00" + msg).digest(114), "little")
    k %= L
    R = _ed_add(_ed_mul(S, (bx, by), c), _ed_mul(k, ((p - A[0]) % p, A[1]), c), c)
    return _ed_encode(R, c) == sig[:n]


# ML-DSA (FIPS 204), as profiled for certificates by RFC 9881: pure ML-DSA with an
# empty context string. Integer math only, like every other check here.
Q = 8380417
N = 256
D = 13
ZETA = 1753
MLDSA = {  # OID -> (k, l, tau, gamma1, gamma2, beta, omega, lambda)
    "2.16.840.1.101.3.4.3.17": (4, 4, 39, 1 << 17, (Q - 1) // 88, 78, 80, 128),
    "2.16.840.1.101.3.4.3.18": (6, 5, 49, 1 << 19, (Q - 1) // 32, 196, 55, 192),
    "2.16.840.1.101.3.4.3.19": (8, 7, 60, 1 << 19, (Q - 1) // 32, 120, 75, 256),
}


def _brv8(x):
    return int(f"{x:08b}"[::-1], 2)


ZETAS = [pow(ZETA, _brv8(i), Q) for i in range(256)]


def _ntt(w):
    w = list(w)
    m, ln = 0, 128
    while ln >= 1:
        start = 0
        while start < 256:
            m += 1
            z = ZETAS[m]
            for j in range(start, start + ln):
                t = z * w[j + ln] % Q
                w[j + ln] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
            start += 2 * ln
        ln //= 2
    return w


def _intt(w):
    w = list(w)
    m, ln = 256, 1
    while ln < 256:
        start = 0
        while start < 256:
            m -= 1
            z = Q - ZETAS[m]
            for j in range(start, start + ln):
                t = w[j]
                w[j] = (t + w[j + ln]) % Q
                w[j + ln] = z * (t - w[j + ln]) % Q
            start += 2 * ln
        ln *= 2
    f = 8347681  # 256^-1 mod q
    return [f * x % Q for x in w]


def _unpack(b, bits):
    """Little-endian bit stream -> list of `bits`-bit integers."""
    v = int.from_bytes(b, "little")
    mask = (1 << bits) - 1
    return [(v >> (bits * i)) & mask for i in range(len(b) * 8 // bits)]


def _pack(coeffs, bits):
    v = 0
    for i, c in enumerate(coeffs):
        v |= c << (bits * i)
    return v.to_bytes(len(coeffs) * bits // 8, "little")


def _rej_ntt_poly(seed):
    out, need = [], 840
    while True:
        s = hashlib.shake_128(seed).digest(need)
        out = []
        for i in range(0, need - 2, 3):
            z = s[i] | (s[i + 1] << 8) | ((s[i + 2] & 0x7F) << 16)
            if z < Q:
                out.append(z)
                if len(out) == 256:
                    return out
        need *= 2


def _sample_in_ball(seed, tau):
    need = 8 + 4 * 256
    while True:
        s = hashlib.shake_256(seed).digest(need)
        signs = int.from_bytes(s[:8], "little")
        c = [0] * 256
        pos = 8
        ok = True
        for i in range(256 - tau, 256):
            while True:
                if pos >= len(s):
                    ok = False
                    break
                j = s[pos]
                pos += 1
                if j <= i:
                    break
            if not ok:
                break
            c[i] = c[j]
            c[j] = Q - 1 if (signs >> (i + tau - 256)) & 1 else 1
        if ok:
            return c
        need *= 2


def _decompose(r, g2):
    rp = r % Q
    r0 = rp % (2 * g2)
    if r0 > g2:
        r0 -= 2 * g2
    if rp - r0 == Q - 1:
        return 0, r0 - 1
    return (rp - r0) // (2 * g2), r0


def _use_hint(h, r, g2):
    m = (Q - 1) // (2 * g2)
    r1, r0 = _decompose(r, g2)
    if h:
        return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m
    return r1


def mldsa_verify(oid: str, pk: bytes, msg: bytes, sig: bytes, ctx: bytes = b"") -> bool:
    """True if sig is a valid ML-DSA signature on msg (FIPS 204 ML-DSA.Verify)."""
    k, l, tau, g1, g2, beta, omega, lam = MLDSA[oid]
    if len(pk) != 32 + 320 * k:
        return False
    zbits = 1 + (g1 - 1).bit_length()
    clen = lam // 4
    if len(sig) != clen + l * 32 * zbits + omega + k or len(ctx) > 255:
        return False
    rho = pk[:32]
    t1 = [_unpack(pk[32 + 320 * i:32 + 320 * (i + 1)], 10) for i in range(k)]
    ct = sig[:clen]
    z = []
    off = clen
    for _ in range(l):
        z.append([g1 - x for x in _unpack(sig[off:off + 32 * zbits], zbits)])
        off += 32 * zbits
    y = sig[off:]
    h = [[0] * 256 for _ in range(k)]
    idx = 0
    for i in range(k):  # HintBitUnpack
        if y[omega + i] < idx or y[omega + i] > omega:
            return False
        first = idx
        while idx < y[omega + i]:
            if idx > first and y[idx - 1] >= y[idx]:
                return False
            h[i][y[idx]] = 1
            idx += 1
    if any(y[i] for i in range(idx, omega)):
        return False
    if max(abs(c) for poly in z for c in poly) >= g1 - beta:
        return False
    A = [[_rej_ntt_poly(rho + bytes([s, r])) for s in range(l)] for r in range(k)]
    tr = hashlib.shake_256(pk).digest(64)
    mp = bytes([0, len(ctx)]) + ctx + msg
    mu = hashlib.shake_256(tr + mp).digest(64)
    c_hat = _ntt(_sample_in_ball(ct, tau))
    z_hat = [_ntt([x % Q for x in poly]) for poly in z]
    w1 = []
    for r in range(k):
        acc = [0] * 256
        for s in range(l):
            a = A[r][s]
            zs = z_hat[s]
            for j in range(256):
                acc[j] += a[j] * zs[j]
        t_hat = _ntt([(x << D) % Q for x in t1[r]])
        acc = [(acc[j] - c_hat[j] * t_hat[j]) % Q for j in range(256)]
        w = _intt(acc)
        w1.append([_use_hint(h[r][j], w[j], g2) for j in range(256)])
    wbits = ((Q - 1) // (2 * g2) - 1).bit_length()
    w1enc = b"".join(_pack(p, wbits) for p in w1)
    return hashlib.shake_256(mu + w1enc).digest(clen) == ct


def self_signed(spki: TLV, tbs: TLV, sig_alg: TLV, sig_bits: TLV) -> bool:
    """True if the certificate's signature verifies under its own public key.
    Raises Unverifiable when the algorithm cannot be checked."""
    oid = decode_oid(sig_alg.children[0].content)
    if oid not in SIG_ALGS:
        raise Unverifiable(oid)
    fam, h = SIG_ALGS[oid]
    sig = sig_bits.content[1:]
    pk_oid = decode_oid(spki.children[0].children[0].content)
    try:
        if fam in ("rsa", "pss"):
            if pk_oid not in (OID_RSA, OID_RSA_PSS):
                return False
            if fam == "pss":
                params = sig_alg.children[1] if len(sig_alg.children) > 1 else None
                return verify_pss(spki, tbs.raw, sig, params)
            return verify_rsa(spki, tbs.raw, sig, h)
        if fam == "dsa":
            return pk_oid == OID_DSA and verify_dsa(spki, tbs.raw, sig, h)
        if fam == "ecdsa":
            return verify_ecdsa(spki, tbs.raw, sig, h)
        if fam == "mldsa":
            return pk_oid == oid and mldsa_verify(oid, spki.children[1].content[1:], tbs.raw, sig)
        return verify_eddsa(spki, tbs.raw, sig, oid)
    except (DERError, IndexError, ValueError, ZeroDivisionError):
        return False


# --------------------------------------------------------------------------- #
# GFMX
# --------------------------------------------------------------------------- #


class GFMXError(ValueError):
    """The input is not a parseable X.509 certificate."""


def gfmx(der: bytes) -> dict:
    """Fingerprint one DER-encoded certificate.

    Returns {"gfmx": "KEY:SPAN:MAKER:AUDIENCE:NAMES", "raw": {segment: pre-hash},
    "info": unhashed info}. Raises GFMXError if the input cannot be parsed."""
    if not isinstance(der, (bytes, bytearray, memoryview)):
        raise TypeError("gfmx() takes the certificate's DER bytes")
    try:
        return _gfmx(bytes(der))
    except _FAILURES as e:
        raise GFMXError(str(e) or e.__class__.__name__) from None


_FAILURES = (DERError, IndexError, ValueError, AttributeError, TypeError,
             ZeroDivisionError, OverflowError, KeyError, RecursionError)


def _parse_name_tails(der: bytes, strict_error: DERError) -> Tuple[TLV, int]:
    """Lenient parse for a certificate that failed the strict one. Data after the value
    is accepted only inside an issuer or subject attribute (seen from firmware that
    patched the outer lengths but not the value's own, e.g. 2Wire gateways); anywhere
    else, or if anything else is wrong, the certificate keeps its strict-parse error."""
    tails: list = []
    try:
        root, end = parse_tlv(der, 0, 0, tails)
        f = root.children[0].children
        idx = 1 if is_context(f[0], 0) else 0
        name_atvs = {id(atv) for name in (f[idx + 2], f[idx + 4])
                     for rdn in name.children for atv in rdn.children}
    except (DERError, IndexError):
        raise strict_error from None
    if not tails or any(id(t) not in name_atvs for t in tails):
        raise strict_error
    return root, end


def _gfmx(der: bytes) -> dict:
    try:
        root, end = parse_tlv(der, 0)
    except DERError as strict_error:
        # Second pass only for input that fails the strict parse, so every certificate
        # that parses strictly is processed exactly as before (SPEC 3.1.1). If the
        # lenient pass fails anywhere later, the strict-parse error is reported.
        root, end = _parse_name_tails(der, strict_error)
        try:
            return _fingerprint(der, root, end, {"atvtrail"})
        except _FAILURES:
            raise strict_error from None
    return _fingerprint(der, root, end, set())


def _fingerprint(der: bytes, root: TLV, end: int, flags: set) -> dict:
    if end != len(der):
        flags.add("trail")

    tbs, sig_alg_outer = root.children[0], root.children[1]
    f = list(tbs.children)
    idx = 0

    # version
    version = "1"
    if is_context(f[0], 0):
        vint = f[0].children[0]
        version = (str(int.from_bytes(vint.content, "big") + 1)
                   if len(vint.content) <= 8 else "x")
        if version == "1":
            flags.add("v1x")  # DEFAULT v1 encoded explicitly
        idx = 1
    serial_t = f[idx]
    walk(root, flags, serial_t)
    sig_alg_tbs = f[idx + 1]
    issuer = f[idx + 2]
    validity = f[idx + 3]
    subject = f[idx + 4]
    spki = f[idx + 5]
    rest = f[idx + 6:]

    if sig_alg_tbs.raw != sig_alg_outer.raw:
        flags.add("sigmm")

    exts: List[Tuple[str, bool, TLV]] = []
    for r in rest:
        if is_context(r, 1) or is_context(r, 2):
            flags.add("uid")
        elif is_context(r, 3):
            seq = r.children[0]
            if not seq.children:
                flags.add("extempty")
            for e in seq.children:
                oid = decode_oid(e.children[0].content)
                critical = False
                if len(e.children) == 3:
                    critical = e.children[1].content != b"\x00"
                    if not critical:
                        flags.add("critF")  # DEFAULT FALSE encoded explicitly
                octet = e.children[-1]
                try:
                    val, _ = parse_tlv(octet.content, 0)
                    walk(val, flags)
                except (DERError, IndexError):
                    val = None
                    flags.add("extbad")
                exts.append((oid, critical, val))
    if len({o for o, _, _ in exts}) != len(exts):
        flags.add("dupext")  # RFC 5280 forbids repeating an extension
    ext_by_oid = {}
    for o, c, v in exts:  # the first occurrence counts, as in most validators
        ext_by_oid.setdefault(o, (c, v))

    # ---- names ----
    def name_info(name: TLV) -> Tuple[List[str], List[str]]:
        """Return (rdn OID groups, list of string-type choices)."""
        groups, choices = [], []
        for rdn in name.children:
            oids = []
            for atv in rdn.children:
                oid = decode_oid(atv.children[0].content)
                oids.append(oid)
                v = atv.children[1]
                tag = v.first
                if oid in FIXED_STRING_ATTRS:
                    if tag not in FIXED_STRING_ATTRS[oid]:
                        flags.add("strspec")
                    continue
                if tag in STRING_TAGS:
                    try:
                        text = v.content.decode({0x1E: "utf-16-be", 0x1C: "utf-32-be"}.get(tag, "utf-8"))
                    except UnicodeDecodeError:
                        text = None
                    if text is not None and PRINTABLE_RE.match(text):
                        choices.append(STRING_TAGS[tag])  # a real choice existed
                else:
                    choices.append("X")
            groups.append("+".join(oids))
        return groups, choices

    i_groups, i_choices = name_info(issuer)
    s_groups, s_choices = name_info(subject)
    str_policy = ",".join(sorted(set(i_choices + s_choices))) or "-"

    if issuer.raw == subject.raw:
        rel = "eq"
    elif not issuer.children:
        rel = "ie"
    elif not subject.children:
        rel = "se"
    else:
        rel = "df"

    # ---- validity ----
    nb, nb_kind, nb_ok = parse_time(validity.children[0])
    na, na_kind, na_ok = parse_time(validity.children[1])
    if not (nb_ok and na_ok):
        flags.add("tfmt")
    for d, k in ((nb, nb_kind), (na, na_kind)):
        if d and k == "G" and d.year < 2050:
            flags.add("gt2050")
        if d and k == "U" and d.year >= 2050:
            flags.add("ut2050")
    if nb and na and na < nb:
        flags.add("negval")  # e.g. a 2050+ date forced into UTCTime wraps to 19xx
    # The time types themselves (UTCTime / GeneralizedTime) are NOT recorded: RFC 5280
    # switches type at 2050, so a long-lived cert's type depends on its creation
    # date and validity, not on the library. Only rule violations are flagged.

    length, kind, construction, span_info = "?", "?", "?", "?"
    if nb and na:
        # SPAN: length + kind (see span_length)
        length, kind = span_length(nb, na)
        span_info = span_text(nb, na)
        # MAKER: how the end date was built from the start date.
        # Calendar vs fixed counting is NOT recorded here (it is only visible when a
        # span crosses Feb 29, so one tool would flip with its creation date).
        dur = (na - nb).total_seconds()
        align = "mid" if (nb.hour, nb.minute, nb.second) == (0, 0, 0) else "any"
        if kind.startswith("end"):
            cons = "end"  # fixed end date: the span depends only on the start time
        elif dur < 0:
            cons = "neg"
        else:
            cons = None
            for off, off_code in ((0, "x"), (1, "m1")):
                t = dur + off
                # whole days, also +/- 1 h: calendar math done in local time gains
                # or loses the DST hour when the span crosses a DST change
                if t >= 82800 and t % 86400 in (0, 3600, 82800):
                    cons = f"day.{off_code}"
                    break
                if t % 3600 == 0:
                    cons = f"hr.{off_code}"
                    break
                # whole minutes only below 2 days: on a long span whose start and end
                # seconds are unrelated (CA reissues, random backdating) one cert in 60
                # is a whole minute by chance, which split MAKER for ~3% of such certs
                if t % 60 == 0 and t < 2 * 86400:
                    cons = f"min.{off_code}"
                    break
            cons = cons or "oth"
        construction = f"{cons}.{align}"

    # ---- serial ----
    # The sign is NOT hashed: a tool that writes raw random bytes as the serial gets a
    # negative one whenever the top bit is set (half the time), which split MAKER.
    # Classes use the magnitude; the sign goes to the unhashed info.
    sc = serial_t.content
    sval = int.from_bytes(sc, "big", signed=True) if sc else 0
    ser_neg = sval < 0
    ser_pad = len(sc) > 1 and ((sc[0] == 0x00 and sc[1] < 0x80) or (sc[0] == 0xFF and sc[1] >= 0x80))
    ser_info = ",".join(x for x, on in (("neg", ser_neg), ("pad", ser_pad)) if on)
    sval = abs(sval)
    # Merkle Tree Certificates: the serial is (log number << 48) | index in the log.
    # Its size depends on the log number and index, so it gets its own class; the
    # log number and index go to the unhashed info. A log number over 8 bytes is
    # rendered as "x" (decimal rendering of a huge serial costs quadratic time).
    is_mtc = decode_oid(sig_alg_outer.children[0].content) == OID_MTC
    if is_mtc:
        ser = "mtc"
        log = sval >> 48
        ser_info_mtc = f"{log if log.bit_length() <= 64 else 'x'}/{sval & ((1 << 48) - 1)}"
    elif sval == 0:
        ser = "z"
    else:
        bl = sval.bit_length()
        ser = None
        if nb and 28 <= bl <= 64:
            ts = int(nb.replace(tzinfo=dt.timezone.utc).timestamp())
            for scale in (1, 1000, 1_000_000_000):
                if abs(sval - ts * scale) <= 2 * 86400 * scale:
                    ser = "t"
                    break
        if ser is None:
            ser = "s" if bl <= 32 else f"r{-(-bl // 32) * 4}"

    # ---- public key / signature (KEY) ----
    pk_alg = spki.children[0]
    pk_oid = decode_oid(pk_alg.children[0].content)
    pk_bits = spki.children[1].content[1:]  # drop unused-bits byte
    pk_detail = key_detail(pk_alg, pk_bits)
    sig_oid = decode_oid(sig_alg_outer.children[0].content)

    # ---- issuance class ----
    # s = signature verifies under the cert's own key, n = issuer == subject but it
    # does not, u = issuer == subject and the algorithm cannot be checked, i = other.
    issuance = "i"
    if issuer.raw == subject.raw:
        try:
            issuance = "s" if self_signed(spki, tbs, sig_alg_outer, root.children[2]) else "n"
        except Unverifiable:
            issuance = "u"

    # ---- key identifiers ----
    ski_code, aki_code = "-", "-"
    if OID_SKI in ext_by_oid and ext_by_oid[OID_SKI][1] is not None:
        kid = ext_by_oid[OID_SKI][1].content
        sha1 = hashlib.sha1(pk_bits).digest()
        m2 = bytes([(sha1[-8] & 0x0F) | 0x40]) + sha1[-7:]
        cands = {
            "m1": sha1,
            "m2": m2,
            "s256": hashlib.sha256(pk_bits).digest()[:20],
            "s384": hashlib.sha384(pk_bits).digest()[:20],
            "s512": hashlib.sha512(pk_bits).digest()[:20],
            "spki1": hashlib.sha1(spki.raw).digest(),
            "spki256": hashlib.sha256(spki.raw).digest()[:20],
        }
        ski_code = next((k for k, v in cands.items() if v == kid), f"o{len(kid)}")
    if OID_AKI in ext_by_oid and ext_by_oid[OID_AKI][1] is not None:
        parts = "".join({0: "k", 1: "i", 2: "s"}.get(c.tagnum, "?")
                        for c in ext_by_oid[OID_AKI][1].children if c.cls == 2)
        aki_code = parts or "e"

    # ---- AUDIENCE ----
    aud = []
    if OID_EKU in ext_by_oid and ext_by_oid[OID_EKU][1] is not None:
        ekus = sorted(decode_oid(c.content) for c in ext_by_oid[OID_EKU][1].children)
        aud.append("eku=" + ",".join(ekus))
    if OID_KU in ext_by_oid and ext_by_oid[OID_KU][1] is not None:
        bits = ext_by_oid[OID_KU][1].content[1:]
        mask = 0
        for i in range(min(len(bits) * 8, 9)):
            if bits[i // 8] & (0x80 >> (i % 8)):
                mask |= 1 << i
        aud.append(f"ku={mask:03x}")
    if OID_BC in ext_by_oid and ext_by_oid[OID_BC][1] is not None:
        ca, pl = False, None
        for c in ext_by_oid[OID_BC][1].children:
            if is_universal(c, 1):
                ca = c.content != b"\x00"
            elif is_universal(c, 2):
                pl = small_uint(c.content)
        aud.append("bc=" + ("c" + ("" if pl is None else str(pl)) if ca else "e"))
    pol = []
    if OID_POLICIES in ext_by_oid and ext_by_oid[OID_POLICIES][1] is not None:
        pol += [decode_oid(pi.children[0].content) for pi in ext_by_oid[OID_POLICIES][1].children]
    if OID_MS_TEMPLATE_INFO in ext_by_oid and ext_by_oid[OID_MS_TEMPLATE_INFO][1] is not None:
        tmpl = ext_by_oid[OID_MS_TEMPLATE_INFO][1].children
        if tmpl:
            pol.append("tmpl:" + decode_oid(tmpl[0].content))
    if OID_MS_TEMPLATE_NAME in ext_by_oid and ext_by_oid[OID_MS_TEMPLATE_NAME][1] is not None:
        v = ext_by_oid[OID_MS_TEMPLATE_NAME][1]
        try:
            name = v.content.decode("utf-16-be" if v.first == 0x1E else "utf-8")
        except UnicodeDecodeError:
            name = "?"
        pol.append("tmplname:" + name)
    if pol:
        aud.append("pol=" + ",".join(sorted(pol)))
    ptr = []
    for oid, label in ((OID_AIA, "aia"), (OID_CDP, "cdp")):
        if oid in ext_by_oid and ext_by_oid[oid][1] is not None:
            uris: List[str] = []
            find_uris(ext_by_oid[oid][1], uris)
            schemes = sorted({uri_scheme(u) for u in uris}) or ["-"]
            ptr.append(f"{label}:" + "+".join(schemes))
    if ptr:
        aud.append("ptr=" + ",".join(ptr))
    audience_pre = ";".join(sorted(aud))

    # ---- assemble pre-hash strings ----
    ext_list = ",".join(o + ("!" if c else "") for o, c, _ in exts
                        if o not in EXT_LIST_EXCLUDED)
    algs = [sig_alg_tbs, pk_alg, sig_alg_outer]
    alt_pk_v = ext_by_oid.get(OID_ALT_SPKI, (None, None))[1]
    alt_sig_v = ext_by_oid.get(OID_ALT_SIG_ALG, (None, None))[1]
    if alt_pk_v is not None and alt_pk_v.children and alt_pk_v.children[0].children:
        algs.append(alt_pk_v.children[0])
    if alt_sig_v is not None and alt_sig_v.children:
        algs.append(alt_sig_v)
    devs = [d for d in map(alg_deviation, algs) if d]
    algp = ",".join(devs) or "std"
    key_pre = f"iss={issuance};pk={pk_oid}{pk_detail};sig={sig_oid}"
    # Hybrid certificates (X.509 alternative key and signature extensions): the second,
    # usually post-quantum, algorithm pair is added to KEY when present.
    alt_pk_v = ext_by_oid.get(OID_ALT_SPKI, (None, None))[1]
    alt_sig_v = ext_by_oid.get(OID_ALT_SIG_ALG, (None, None))[1]
    if alt_pk_v is not None or alt_sig_v is not None:
        key_pre += f";alt={alt_key_part(alt_pk_v)}/{alt_sig_part(alt_sig_v)}"
    # SPAN is its own segment: the validity length is often the one setting an
    # operator chose (keytool -validity), but some builders randomise it (msfvenom).
    # Keeping it apart lets a hunt skip SPAN alone and keep the key and signature.
    # kind stays with length: it is derived from the same day count, so a random
    # length makes it random too.
    span_pre = f"len={length};kind={kind}"
    # The string-type choice (str) is NOT hashed: it is only observable when a name
    # value happens to fit PrintableString, so random names can hide it and split the
    # fingerprint (failed the test bench). It is kept as unhashed info for analysts.
    maker_pre = (f"ver={version};enc={','.join(sorted(flags)) or '-'};"
                 f"algp={algp};rel={rel};ext={ext_list};ser={ser};"
                 f"kid={ski_code}/{aki_code};vc={construction};mtc={'log' if is_mtc else ''}")
    names_pre = ""
    if i_groups or s_groups:
        names_pre = "i=" + ",".join(i_groups) + "|s=" + ",".join(s_groups)

    segs = [h8(key_pre), h8(span_pre), h8(maker_pre), h8(audience_pre), h8(names_pre)]
    return {
        "gfmx": ":".join(segs),
        "raw": {"key": key_pre, "span": span_pre, "maker": maker_pre,
                "audience": audience_pre, "names": names_pre},
        "info": f"str={str_policy};span={span_info}" + (f";ser={ser_info}" if ser_info else "")
                + (f";mtc={ser_info_mtc}" if is_mtc else ""),
    }


# --------------------------------------------------------------------------- #
# Input handling
# --------------------------------------------------------------------------- #

PEM_RE = re.compile(rb"-----BEGIN ((?:X509 |TRUSTED )?)CERTIFICATE-----(.+?)-----END (?:X509 |TRUSTED )?CERTIFICATE-----", re.S)
HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:\s]?)+$")


def decode_text_line(line: str) -> Optional[bytes]:
    """One certificate per line, as hex (tshark, Zeek) or base64 (APIs, CT logs)."""
    line = line.strip(" \t\r\n\v\f")
    if not line or line.startswith("#"):
        return None
    if line.startswith("30") and HEX_RE.match(line):
        return bytes.fromhex(re.sub(r"[:\s]", "", line))
    return b64decode(line)


def b64decode(s: str) -> bytes:
    """Strict base64 (standard or URL-safe alphabet, padding optional)."""
    s = re.sub(r"\s", "", s).rstrip("=")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except ValueError:
        try:
            return base64.b64decode(s, altchars=b"-_", validate=True)
        except ValueError:
            raise ValueError(f"neither hex nor base64: {s[:40]!r}") from None


def pem_der(kind: bytes, body: bytes) -> bytes:
    """DER of one PEM block. A TRUSTED CERTIFICATE block (OpenSSL's X509_AUX format)
    holds the certificate followed by trust settings and an alias; only the certificate
    is kept, so it fingerprints the same as in a plain PEM file (no "trail" flag)."""
    der = b64decode(body.decode("ascii", "replace"))
    return first_element(der) if kind == b"TRUSTED " else der


def first_element(b: bytes) -> bytes:
    """The first element of b, from its outer header only (the contents are not read, so a
    certificate that is malformed inside is cut at the same place), or b unchanged if the
    header cannot be read. Same rules as Go extract.FirstElement."""
    if len(b) < 2:
        return b
    i = 1
    if b[0] & 0x1F == 0x1F:
        while i < len(b) and b[i] & 0x80:
            i += 1
        i += 1
    if i >= len(b):
        return b
    n = b[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or i + k > len(b):
            return b
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    return b if i + n > len(b) else b[:i + n]


def load_bytes(data: bytes) -> List[bytes]:
    """PEM (any number of certificates), raw DER, or one hex/base64 cert per line."""
    blocks = PEM_RE.findall(data)
    if blocks:
        return [pem_der(kind, b) for kind, b in blocks]
    if data[:1] == b"\x30":
        return [data]
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return [data]
    out = []
    try:
        for line in text.split("\n"):
            der = decode_text_line(line)
            if der is not None:
                out.append(der)
    except ValueError:  # not a list of certificates: let the DER parser report it
        return [data]
    return out


def load_file(path: str) -> List[bytes]:
    with open(path, "rb") as f:
        return load_bytes(f.read())


def split_hostport(hostport: str) -> Tuple[str, int]:
    """host, host:port, [v6]:port or bare v6 address -> (host, port)."""
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else 443
    if hostport.count(":") == 1:
        host, port = hostport.split(":")
        return host, int(port)
    return hostport, 443


def fetch_leaf(hostport: str, timeout: float = 10.0, sni: Optional[str] = None) -> bytes:
    """Leaf certificate from a live TLS handshake. Validation is off on purpose: the
    point is to fingerprint whatever the server presents. Every cipher suite and
    protocol version the local OpenSSL still has is offered (security level 0), since
    old appliances often speak nothing newer. The SNI sent is sni when given, else the
    host when it is a name; an IP address without sni sends none, and the server
    answers with its default certificate."""
    host, port = split_hostport(hostport)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:  # not OpenSSL, or a build without security levels
        pass
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=sni or host) as tls:
            return tls.getpeercert(binary_form=True)


def expand(paths: List[str]) -> List[Tuple[str, Optional[OSError]]]:
    """Files as given; directories expand to their certificate files (sorted). A folder
    that cannot be listed comes back with its error, so the run reports it and goes on."""
    out: List[Tuple[str, Optional[OSError]]] = []
    for p in paths:
        if os.path.isdir(p):
            try:
                names = os.listdir(p)
            except OSError as e:
                out.append((p, e))
                continue
            out += [(os.path.join(p, f), None) for f in sorted(names)
                    if f.lower().endswith((".pem", ".der", ".crt", ".cer"))]
        else:
            out.append((p, None))
    return out


def run_one(label: str, der: bytes) -> dict:
    row = {"source": label, "sha256": hashlib.sha256(der).hexdigest()}
    try:
        row.update(gfmx(der))
        row["error"] = None
    except GFMXError as e:
        row.update({"gfmx": None, "raw": None, "info": None, "error": str(e)})
    return row


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="gfmx", description="GFMX: X.509 certificate template fingerprint "
        "(KEY:SPAN:MAKER:AUDIENCE:NAMES).",
        epilog="Exit status: 0 all certificates fingerprinted, 1 at least one could not "
        "be parsed, 2 usage or I/O error.")
    ap.add_argument("files", nargs="*", help="certificate files or folders; '-' reads stdin "
                    "(PEM, DER, or one hex/base64 certificate per line)")
    ap.add_argument("--host", action="append", default=[], metavar="HOST[:PORT]",
                    help="fingerprint the certificate a live TLS server presents")
    ap.add_argument("--sni", metavar="NAME", help="server name to send with --host (default: "
                    "the host when it is a name; none for an IP)")
    ap.add_argument("--b64", action="append", default=[], help="base64 DER certificate")
    ap.add_argument("--raw", action="store_true", help="print each segment's pre-hash string")
    ap.add_argument("--json", action="store_true", help="one JSON object per certificate")
    ap.add_argument("--csv", help="also write a table to this CSV file")
    ap.add_argument("--quiet", action="store_true", help="no per-certificate output")
    ap.add_argument("--version", action="version", version=f"gfmx {__version__} (spec {SPEC_VERSION})")
    a = ap.parse_args(argv)
    if not (a.files or a.host or a.b64):
        ap.print_usage(sys.stderr)
        return 2

    def items():
        """(label, der, input error). An unreadable input is reported and skipped."""
        for p, err in expand(a.files):
            label = "stdin" if p == "-" else p
            if err is not None:
                yield label, None, err
                continue
            try:
                ders = load_bytes(sys.stdin.buffer.read()) if p == "-" else load_file(p)
            except (OSError, ValueError) as e:
                yield label, None, e
                continue
            for n, der in enumerate(ders):
                yield (label if n == 0 and label != "stdin" else f"{label}#{n}"), der, None
        for hp in a.host:
            try:
                yield hp, fetch_leaf(hp, sni=a.sni), None
            except (OSError, ValueError) as e:
                yield hp, None, e
        for n, b in enumerate(a.b64):
            try:
                yield f"b64#{n}", b64decode(b), None
            except ValueError as e:
                yield f"b64#{n}", None, e

    rows, failed, input_errors = [], 0, 0
    try:
        for label, der, err in items():
            if err is not None:
                input_errors += 1
                print(f"gfmx: {label}: {err}", file=sys.stderr)
                continue
            r = run_one(label, der)
            failed += r["error"] is not None
            if a.csv:
                rows.append(r)
            if a.quiet:
                continue
            if a.json:
                print(json.dumps(r, ensure_ascii=False), flush=False)
            elif r["error"]:
                print(f"{'error':<44} {label}  ({r['error']})")
            else:
                print(f"{r['gfmx']:<44} {label}")
                if a.raw:
                    for k, v in r["raw"].items():
                        print(f"    {k:<8} {v}")
                    print(f"    {'info':<8} {r['info']}  (not hashed)")
    except OSError as e:  # e.g. stdout closed
        print(f"gfmx: {e}", file=sys.stderr)
        return 2

    if a.csv:
        try:
            with open(a.csv, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["file", "gfmx", "raw_key", "raw_span", "raw_maker", "raw_audience",
                            "raw_names", "info", "sha256", "error"])
                for r in rows:
                    raw = r["raw"] or {}
                    w.writerow([os.path.basename(r["source"]), r["gfmx"] or "!:!:!:!:!",
                                *(raw.get(k, "") for k in SEGMENTS), r["info"] or "",
                                r["sha256"], r["error"] or ""])
        except OSError as e:
            print(f"gfmx: cannot write {a.csv}: {e}", file=sys.stderr)
            return 2
        print(f"{len(rows)} certificates fingerprinted -> {a.csv}"
              + (f" ({failed} could not be parsed)" if failed else ""), file=sys.stderr)
    return 2 if input_errors else 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
