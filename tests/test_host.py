#!/usr/bin/env python3
"""--host against local TLS servers: an old appliance that only speaks RSA key
exchange (TLS 1.0 and 1.2), and a server that picks its certificate by SNI.
Needs the openssl command to make throwaway certificates.

    python3 tests/test_host.py
"""
from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import gfmx  # noqa: E402


def make_cert(d: str, cn: str):
    crt, key = os.path.join(d, cn + ".crt"), os.path.join(d, cn + ".key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", crt, "-subj", "/CN=" + cn, "-days", "1"], check=True, capture_output=True)
    with open(crt) as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    return crt, key, der


def server_context(crt, key, ciphers=None, version=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    if version:
        ctx.minimum_version = ctx.maximum_version = version
    if ciphers:
        ctx.set_ciphers(ciphers)
    return ctx


def serve(test, ctx) -> str:
    ls = socket.create_server(("127.0.0.1", 0))
    test.addCleanup(ls.close)

    def loop():
        while True:
            try:
                c, _ = ls.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(c, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=loop, daemon=True).start()
    return "127.0.0.1:%d" % ls.getsockname()[1]


@unittest.skipUnless(shutil.which("openssl"), "openssl command not installed")
class Host(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.default = make_cert(cls.tmp, "default")
        cls.alt = make_cert(cls.tmp, "alt.test")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_rsa_key_exchange_only(self):
        crt, key, der = self.default
        for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2):
            with self.subTest(version=version.name):
                try:
                    ctx = server_context(crt, key, "AES128-SHA:@SECLEVEL=0", version)
                except (ssl.SSLError, ValueError) as e:
                    self.skipTest(f"local OpenSSL cannot serve {version.name}: {e}")
                self.assertEqual(gfmx.fetch_leaf(serve(self, ctx), timeout=5), der)

    def test_sni(self):
        dcrt, dkey, dder = self.default
        acrt, akey, ader = self.alt
        ctx = server_context(dcrt, dkey)
        alt = server_context(acrt, akey)

        def pick(sock, name, _):
            if name == "alt.test":
                sock.context = alt

        ctx.sni_callback = pick
        addr = serve(self, ctx)
        self.assertEqual(gfmx.fetch_leaf(addr, timeout=5), dder)  # IP: no SNI, default certificate
        self.assertEqual(gfmx.fetch_leaf(addr, timeout=5, sni="alt.test"), ader)


if __name__ == "__main__":
    unittest.main(verbosity=2)
