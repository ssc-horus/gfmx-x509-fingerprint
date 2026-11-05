#!/usr/bin/env python3
"""Connector contracts, on the fixtures in connectors/testdata/.

Every connector reports each certificate it sees, fingerprints it with gfmx, and when
it cannot, says why (gfmx_error) instead of dropping it or guessing. None of them
decides which side of a connection is the server or the client.

Parts that need tshark are skipped when tshark is not installed. Set GFMX_BIN to a
built Go CLI to also test the PCAP script with it.

    python3 tests/test_connectors.py
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "connectors", "testdata")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "connectors", "suricata"))
import gfmx  # noqa: E402
import eve_gfmx  # noqa: E402

TSHARK = shutil.which("tshark")
GFMX_BIN = os.environ.get("GFMX_BIN")
ROLE_WORDS = {"server", "client", "role", "resp_h", "resp_p", "orig_h", "orig_p"}


def fixture(name: str) -> str:
    return os.path.join(DATA, name)


def lines(name: str) -> list:
    with open(fixture(name)) as f:
        return f.readlines()


def run(args, **kw):
    return subprocess.run([sys.executable] + args, capture_output=True, text=True, **kw)


def mtls_ders() -> list:
    """The three certificates in mtls.pcap, in order: server leaf, its CA, client."""
    leaf, ca = json.loads(lines("eve.json")[0])["tls"]["chain"]
    rows = [l.split("\t") for l in lines("gfmx_der.log") if not l.startswith("#")]
    client = rows[2][3]
    return [base64.b64decode(x) for x in (leaf, ca, client)]


def fp(der: bytes) -> str:
    return gfmx.gfmx(der)["gfmx"]


class Suricata(unittest.TestCase):
    def test_eve(self):
        out = [eve_gfmx.enrich(l) for l in lines("eve.json")]
        good, bad, nocert, flow, junk = out
        leaf, ca, _ = mtls_ders()
        t = json.loads(good)["tls"]
        self.assertEqual(t["gfmx"], fp(leaf))
        self.assertEqual(t["gfmx_chain"], [fp(leaf), fp(ca)])
        self.assertNotIn("gfmx_error", t)
        self.assertNotIn("gfmx_chain_errors", t)
        t = json.loads(bad)["tls"]
        self.assertIsNone(t["gfmx"])
        self.assertTrue(t["gfmx_error"])
        self.assertEqual(t["gfmx_chain"], [None, None])
        self.assertEqual(t["gfmx_chain_errors"][1], "not base64")
        self.assertNotIn("gfmx", json.loads(nocert)["tls"])  # nothing logged, nothing added
        self.assertEqual(flow, lines("eve.json")[3])  # passes through
        self.assertEqual(junk, "not json at all\n")


class Zeek(unittest.TestCase):
    def check(self, recs):
        leaf, ca, client = mtls_ders()
        self.assertEqual([r["gfmx"] for r in recs[:3]], [fp(leaf), fp(ca), fp(client)])
        self.assertTrue(all(r["gfmx_error"] in (None, "-") for r in recs[:3]))
        self.assertIn(recs[3]["gfmx"], (None, "-"))
        self.assertNotIn(recs[3]["gfmx_error"], (None, "-"))
        self.assertEqual(recs[4]["gfmx_error"], "no certificate")
        for r in recs:
            self.assertFalse(ROLE_WORDS & set(r), r)
            self.assertNotIn("der", r)

    def test_tsv(self):
        res = run([os.path.join(ROOT, "connectors", "zeek", "zeek_gfmx.py"), fixture("gfmx_der.log")])
        self.assertEqual(res.returncode, 0, res.stderr)
        lines = res.stdout.splitlines()
        fields = next(l for l in lines if l.startswith("#fields")).split("\t")[1:]
        types = next(l for l in lines if l.startswith("#types")).split("\t")[1:]
        self.assertEqual(len(fields), len(types))
        self.assertEqual(fields[-2:], ["gfmx", "gfmx_error"])
        rows = [dict(zip(fields, l.split("\t"))) for l in lines
                if not l.startswith("#") and len(l.split("\t")) == len(fields)]
        self.check(rows)
        self.assertIn("short\trow", lines)  # a row it cannot read passes through
        self.assertTrue(lines[-1].startswith("#close"))

    def test_json(self):
        res = run([os.path.join(ROOT, "connectors", "zeek", "zeek_gfmx.py"), fixture("gfmx_der.json")])
        self.assertEqual(res.returncode, 0, res.stderr)
        lines = res.stdout.splitlines()
        self.check([json.loads(l) for l in lines[:5]])
        self.assertEqual(lines[5], "{broken json")


class Misp(unittest.TestCase):
    def test_template(self):
        try:
            import jsonschema
            import pymisp
        except ImportError:
            self.skipTest("pymisp and jsonschema not installed")
        base = os.path.join(os.path.dirname(pymisp.__file__), "data", "misp-objects")
        with open(os.path.join(base, "schema_objects.json")) as f:
            schema = json.load(f)
        path = os.path.join(ROOT, "connectors", "misp")
        with open(os.path.join(path, "gfmx", "definition.json")) as f:
            jsonschema.validate(json.load(f), schema)
        leaf = mtls_ders()[0]
        obj = pymisp.MISPObject("gfmx", misp_objects_path_custom=path, strict=True)
        value = fp(leaf)
        obj.add_attribute("gfmx", value=value)
        obj.add_attribute("pattern", value=":".join(["*"] + value.split(":")[1:]))
        for name, seg in zip(("key", "span", "maker", "audience", "names"), value.split(":")):
            if seg:
                obj.add_attribute(name, value=seg)
        self.assertEqual(json.loads(obj.to_json())["name"], "gfmx")


class Ghidra(unittest.TestCase):
    def test_carving(self):
        """The script's own carving (Ghidra itself runs in the manual 'ghidra' workflow)."""
        sys.path.insert(0, os.path.join(ROOT, "connectors", "ghidra"))
        import GFMXCertificates  # noqa: E402  (does nothing outside Ghidra)
        with open(os.path.join(ROOT, "go", "extract", "testdata", "implant.bin"), "rb") as f:
            found = list(GFMXCertificates.find_certificates(f.read()))
        self.assertEqual(len(found), 2)
        self.assertTrue(all(r["gfmx"] == fp(der) for _, der, r in found))


@unittest.skipUnless(TSHARK, "tshark not installed")
class Pcap(unittest.TestCase):
    script = os.path.join(ROOT, "connectors", "tshark", "gfmx_pcap.py")

    def rows(self, pcap, *extra):
        res = run([self.script, *extra, pcap])
        self.assertEqual(res.returncode, 0, res.stderr)
        return [json.loads(l) for l in res.stdout.splitlines()], res.stderr

    def check_mtls(self, rows):
        leaf, ca, client = mtls_ders()
        self.assertEqual([r["gfmx"] for r in rows], [fp(leaf), fp(ca), fp(client)])
        self.assertEqual([r["chain_index"] for r in rows], [0, 1, 0])
        self.assertTrue(all(r["gfmx_error"] is None and r["sni"] == "server.test" for r in rows))
        # the packet's own addresses, nothing about which side is the server
        self.assertEqual((rows[0]["src"], rows[0]["src_port"]), ("192.0.2.20", "443"))
        self.assertEqual((rows[2]["src"], rows[2]["src_port"]), ("192.0.2.10", "50000"))
        for r in rows:
            self.assertFalse(ROLE_WORDS & set(r), r)

    def test_mtls(self):
        self.check_mtls(self.rows(fixture("mtls.pcap"))[0])

    @unittest.skipUnless(GFMX_BIN, "GFMX_BIN not set")
    def test_mtls_go(self):
        self.check_mtls(self.rows(fixture("mtls.pcap"), "--gfmx-bin", GFMX_BIN)[0])

    def test_bad_certificate(self):
        rows, _ = self.rows(fixture("badcert.pcap"))
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["gfmx"])
        self.assertTrue(rows[0]["gfmx_error"])

    def test_truncated(self):
        with open(fixture("mtls.pcap"), "rb") as f:
            data = f.read()
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as t:
            t.write(data[:-300])  # cut in the middle of the last packet
        try:
            rows, err = self.rows(t.name)
        finally:
            os.unlink(t.name)
        self.assertIn("stopped early", err)
        self.assertGreaterEqual(len(rows), 2)  # the server's leaf and CA are before the cut

    def test_not_a_capture(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as t:
            t.write(b"not a capture")
        try:
            res = run([self.script, t.name])
        finally:
            os.unlink(t.name)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("could not read", res.stderr)




if __name__ == "__main__":
    unittest.main(verbosity=2)
