#!/usr/bin/env python3
"""CLI and loader regressions. Runs under pytest or directly."""
import os
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DATA = os.path.join(ROOT, "tests", "data")
sys.path.insert(0, ROOT)
import gfmx  # noqa: E402


def test_trusted_pem_same_as_plain():
    """A TRUSTED CERTIFICATE block (X509_AUX) fingerprints like the plain certificate."""
    plain = gfmx.load_file(os.path.join(DATA, "ca.pem"))
    trusted = gfmx.load_file(os.path.join(DATA, "ca_trusted.pem"))
    assert plain == trusted, "trust settings were not stripped"
    assert "trail" not in gfmx.gfmx(trusted[0])["raw"]["maker"]


def test_trusted_pem_trim_matches_go():
    """Trimming reads only the outer header: a certificate that is broken
    inside is still cut before the trust settings, the same as Go's extract.FirstElement."""
    aux = bytes.fromhex("3006300406022b06")             # trust settings stand-in
    broken = bytes.fromhex("3008") + bytes.fromhex("3080") + b"\x01\x02\x03\x04\x05\x06"
    assert gfmx.first_element(broken + aux) == broken
    long_len = bytes.fromhex("3085") + b"\x00" * 5    # 5 length bytes: left whole, as in Go
    assert gfmx.first_element(long_len + aux) == long_len + aux
    assert gfmx.first_element(b"\x30") == b"\x30"


def run(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "gfmx.py"), *args],
                          capture_output=True, text=True)


def test_unreadable_folder_reported_and_run_continues():
    if os.geteuid() == 0:
        return  # root can read anything; nothing to test
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, "noread")
        os.mkdir(bad)
        os.chmod(bad, 0)
        try:
            r = run(bad, os.path.join(DATA, "ca.pem"))
        finally:
            os.chmod(bad, stat.S_IRWXU)
    assert r.returncode == 2, r
    assert "noread" in r.stderr
    assert r.stdout.count(":") >= 4, "the readable file was not fingerprinted"


def test_csv_write_failure_is_an_error():
    if not os.path.exists("/dev/full"):
        return
    r = run("--csv", "/dev/full", os.path.join(DATA, "ca.pem"))
    assert r.returncode == 2 and "cannot write" in r.stderr and "Traceback" not in r.stderr, r


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
