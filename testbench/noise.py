"""
Noise filler: takes a blueprint (the stable configuration) and fills in everything
that is per-certificate instance data. Nothing here may change the fingerprint.

Randomized per certificate:
  * the key pair (new key every time)
  * serial number value (in the style the blueprint dictates)
  * every name value (CN, O, OU, ...), sometimes with characters that do not fit
    PrintableString
  * notBefore anywhere in 2000-2049 (so periods cross Feb 29, DST changes and the
    year 2050; calendar-month spans land on every possible day count)
  * SAN: present or absent, DNS names and/or IPs, at a random position in the
    extension order
  * URL hosts in AIA/CDP
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import random
import string
from calendar import monthrange
from functools import lru_cache
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

WORDS = ("alpha bravo cedar delta ember falcon granite harbor indigo juniper kestrel "
         "lumen marble nimbus onyx prairie quartz raven summit tundra umber vertex "
         "willow xenon yarrow zephyr").split()

# Characters that do not fit PrintableString, to exercise the string-type rule.
NON_PRINTABLE_BITS = ["_", "@", "&", "é", "ü", "*"]


def rand_word(rng: random.Random) -> str:
    if rng.random() < 0.5:
        return rng.choice(WORDS)
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(3, 12)))


def rand_value(rng: random.Random, field: str, special_rate: float) -> str:
    """A random value for a name field."""
    if field == "C":
        return rng.choice(["US", "GB", "DE", "NL", "IL", "SG", "BR", "JP"])
    if field == "emailAddress":
        return f"{rand_word(rng)}@{rand_word(rng)}.com"
    if field == "CN":
        v = rng.choice([
            f"{rand_word(rng)}.{rng.choice(['com', 'net', 'org', 'io'])}",
            f"{rand_word(rng)}-{rng.randint(1, 999)}",
            rand_word(rng).title(),
            str(ipaddress.IPv4Address(rng.getrandbits(32))),
        ])
    elif field in ("O", "OU"):
        v = " ".join(rand_word(rng).title() for _ in range(rng.randint(1, 3)))
    else:  # ST, L
        v = rand_word(rng).title()
    if rng.random() < special_rate:
        pos = rng.randint(0, len(v))
        v = v[:pos] + rng.choice(NON_PRINTABLE_BITS) + v[pos:]
    return v


def new_key(rng: random.Random, key_spec: str):
    kind, param = key_spec.split("-")
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=int(param))
    if kind == "ec":
        curve = {"P256": ec.SECP256R1(), "P384": ec.SECP384R1(), "P521": ec.SECP521R1()}[param]
        return ec.generate_private_key(curve)
    if kind == "ed":
        return ed25519.Ed25519PrivateKey.generate() if param == "25519" else ed448.Ed448PrivateKey.generate()
    raise ValueError(key_spec)


def serial_value(rng: random.Random, style: str, not_before: dt.datetime) -> int:
    if style == "rand64":
        return rng.getrandbits(63) | (1 << 40)      # positive, 41-63 bits
    if style == "rand128":
        return rng.getrandbits(128) | (1 << 100)
    if style == "rand159":
        return rng.getrandbits(159) | (1 << 130)
    if style == "small":
        return rng.randint(1, 100_000)
    if style == "timestamp":
        return int(not_before.replace(tzinfo=dt.timezone.utc).timestamp())
    raise ValueError(style)


def add_months(d: dt.datetime, n: int, conv: str) -> dt.datetime:
    """Calendar arithmetic as real libraries do it.
    clamp: Jan 31 + 1 month = Feb 28 (.NET AddMonths, Java plusMonths, dateutil)
    roll:  Jan 31 + 1 month = Mar 3  (Go AddDate normalizes the overflow)"""
    y, m = divmod(d.month - 1 + n, 12)
    y, m = d.year + y, m + 1
    if conv == "clamp":
        return d.replace(year=y, month=m, day=min(d.day, monthrange(y, m)[1]))
    return d.replace(year=y, month=m, day=1) + dt.timedelta(days=d.day - 1)


@lru_cache(maxsize=None)
def calendar_spans(months: int) -> frozenset:
    """Every day count `months` calendar months can span (400-year cycle, both
    conventions). Used only to label blueprints that are the same by design."""
    out = set()
    for y in range(2000, 2400):
        for m in range(1, 13):
            for d in (1, 29, 30, 31):
                if d <= monthrange(y, m)[1]:
                    s = dt.datetime(y, m, d)
                    out |= {(add_months(s, months, c) - s).days for c in ("clamp", "roll")}
    return frozenset(out)


FIXED_ENDS = {"9999": dt.datetime(9999, 12, 31, 23, 59, 59),
              "2049": dt.datetime(2049, 12, 31, 23, 59, 59)}


def validity(rng: random.Random, bp: dict) -> tuple[dt.datetime, dt.datetime]:
    """Random start date; how the end is computed comes from the blueprint:
      days N / secs N   fixed duration
      cal N             N calendar months (clamp or roll-over convention)
      end Y             fixed end date
    For days and cal, the arithmetic may be done in a local time zone (wall clock)
    and converted to UTC afterwards, so spans crossing a DST change gain or lose
    an hour, as with .NET DateTime.Now.AddYears()."""
    v = bp["validity_impl"]
    start = dt.datetime(2000, 1, 1) + dt.timedelta(days=rng.randint(0, 50 * 365 - 1))
    if bp["nb_align"] == "midnight":
        nb = start
    else:
        nb = start + dt.timedelta(seconds=rng.randint(1, 86399))
    if v["unit"] == "end":
        return nb, FIXED_ENDS[v["n"]]
    if v["unit"] == "secs":
        na = nb + dt.timedelta(seconds=v["n"])
    else:
        tz = ZoneInfo(v["tz"])
        local = nb.replace(tzinfo=dt.timezone.utc).astimezone(tz).replace(tzinfo=None)
        if v["unit"] == "days":
            end_local = local + dt.timedelta(days=v["n"])
        else:
            end_local = add_months(local, v["n"], v["conv"])
        na = end_local.replace(tzinfo=tz).astimezone(dt.timezone.utc).replace(tzinfo=None)
    if bp["end_offset"] == "minus1s":
        na -= dt.timedelta(seconds=1)
    return nb, na


def fill(rng: random.Random, bp: dict, special_rate: float = 0.1) -> dict:
    """Return the instance data for one certificate built from blueprint `bp`."""
    key = new_key(rng, bp["key"])
    nb, na = validity(rng, bp)
    names = [(f, rand_value(rng, f, special_rate)) for f in bp["subject"]]
    san = None
    if rng.random() < 0.6:
        entries = []
        for _ in range(rng.randint(1, 4)):
            if rng.random() < 0.7:
                entries.append(("dns", f"{rand_word(rng)}.{rand_word(rng)}.com"))
            else:
                entries.append(("ip", str(ipaddress.IPv4Address(rng.getrandbits(32)))))
        san = {"entries": entries, "position": rng.random()}
    return {
        "key": key,
        "not_before": nb,
        "not_after": na,
        "serial": serial_value(rng, bp["serial"], nb),
        "subject": names,
        "san": san,
        "url_host": f"{rand_word(rng)}.{rand_word(rng)}.net",
    }
