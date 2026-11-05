#!/usr/bin/env python3
"""
Fingerprint every certificate in a packet capture with GFMX.

tshark reassembles the TLS handshakes; this script prints one row per certificate
(JSON lines or CSV) with the packet it arrived in: frame, time, TCP stream, source and
destination address and port, its position in the Certificate message, and the SNI
seen in that TCP stream, if any. It does not decide which side is the server or the
client; whoever reads the output can, from the addresses and ports. Certificates are
visible in TLS 1.2 and earlier; TLS 1.3 and QUIC encrypt them (decrypt with an
SSLKEYLOGFILE: -o tls.keylog_file:FILE).

A truncated or damaged capture is read as far as tshark gets; the script prints what
it found and a warning on stderr. Certificates that cannot be fingerprinted get
gfmx = null and the reason in gfmx_error.

Usage:
  gfmx_pcap.py capture.pcapng                 # JSON lines on stdout
  gfmx_pcap.py --csv out.csv capture.pcap
  gfmx_pcap.py --gfmx-bin ./gfmx big.pcap # use the Go CLI (much faster)
  gfmx_pcap.py --tshark-opt tls.keylog_file:keys.log capture.pcapng

Needs tshark on PATH. Without --gfmx-bin it imports the reference gfmx.py from
the repository root (no other dependency).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", ".."))

FIELDS = ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ipv6.src", "tcp.srcport",
          "ip.dst", "ipv6.dst", "tcp.dstport", "tls.handshake.type",
          "tls.handshake.extensions_server_name", "tls.handshake.certificate"]


def tshark_rows(pcap: str, opts: list) -> list:
    """Rows tshark could read. tshark exits non-zero on a capture cut short in the
    middle of a packet; everything before that point is still usable."""
    cmd = ["tshark", "-r", pcap, "-n", "-Y", "tls.handshake.type == 1 || tls.handshake.certificate",
           "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    for o in opts:
        cmd += ["-o", o]
    for f in FIELDS:
        cmd += ["-e", f]
    res = subprocess.run(cmd, capture_output=True, text=True)
    rows = [dict(zip(FIELDS, line.split("\t"))) for line in res.stdout.splitlines() if line]
    if res.returncode != 0:
        msg = res.stderr.strip().splitlines()[-1] if res.stderr.strip() else f"exit status {res.returncode}"
        if not rows:
            raise SystemExit(f"tshark could not read {pcap}: {msg}")
        print(f"warning: tshark stopped early ({msg}); using the {len(rows)} rows read before that",
              file=sys.stderr)
    return rows


def fingerprints_py(ders: list) -> list:
    import gfmx
    out = []
    for der in ders:
        try:
            out.append(gfmx.gfmx(der))
        except gfmx.GFMXError as e:
            out.append({"error": str(e) or "not a certificate"})
    return out


def fingerprints_bin(ders: list, binary: str) -> list:
    if not ders:
        return []
    data = "".join(der.hex() + "\n" for der in ders)
    try:
        res = subprocess.run([binary, "--json", "-"], input=data, capture_output=True, text=True)
    except OSError as e:
        raise SystemExit(f"cannot run {binary}: {e}")
    rows = [json.loads(l) for l in res.stdout.splitlines()]
    by_idx = {int(r["source"].split("#")[1]): r for r in rows}
    return [by_idx.get(i, {"error": "no output from " + binary}) for i in range(len(ders))]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("pcap")
    ap.add_argument("--csv", help="write CSV here instead of JSON lines on stdout")
    ap.add_argument("--gfmx-bin", help="path to the gfmx CLI (Go) to use instead of gfmx.py")
    ap.add_argument("--tshark-opt", action="append", default=[], help="extra tshark -o preference")
    a = ap.parse_args()

    rows = tshark_rows(a.pcap, a.tshark_opt)
    sni = {}
    for r in rows:  # ClientHello: remember the SNI seen in each TCP stream
        if "1" in r["tls.handshake.type"].split(",") and r["tls.handshake.extensions_server_name"]:
            sni[r["tcp.stream"]] = r["tls.handshake.extensions_server_name"].split(",")[0]
    found = []
    for r in rows:
        if not r["tls.handshake.certificate"]:
            continue
        for i, h in enumerate(r["tls.handshake.certificate"].split(",")):
            der = bytes.fromhex(h.replace(":", ""))
            found.append({
                "frame": int(r["frame.number"]), "time": r["frame.time_epoch"],
                "stream": r["tcp.stream"],
                "src": r["ip.src"] or r["ipv6.src"], "src_port": r["tcp.srcport"],
                "dst": r["ip.dst"] or r["ipv6.dst"], "dst_port": r["tcp.dstport"],
                "sni": sni.get(r["tcp.stream"], ""), "chain_index": i,
                "sha256": hashlib.sha256(der).hexdigest(), "_der": der})
    fps = (fingerprints_bin if a.gfmx_bin else fingerprints_py)(
        [f["_der"] for f in found], *([a.gfmx_bin] if a.gfmx_bin else []))
    for f, fp in zip(found, fps):
        del f["_der"]
        f["gfmx"] = fp.get("gfmx")
        f["raw"] = fp.get("raw")
        f["gfmx_error"] = fp.get("error")
    if a.csv:
        cols = ["frame", "time", "stream", "src", "src_port", "dst", "dst_port", "sni",
                "chain_index", "sha256", "gfmx", "gfmx_error"]
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(found)
        print(f"{len(found)} certificates -> {a.csv}", file=sys.stderr)
    else:
        for f in found:
            print(json.dumps(f))
    return 0


if __name__ == "__main__":
    sys.exit(main())
