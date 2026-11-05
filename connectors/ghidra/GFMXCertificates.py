# Find X.509 certificates embedded in the current program (implants, droppers,
# firmware) and fingerprint them with GFMX. Each certificate gets a bookmark
# (category "GFMX") and a plate comment with its fingerprint; a table is printed to
# the console.
#
# Needs Ghidra 11.3+ with PyGhidra (CPython 3). gfmx.py has no dependencies: set
# GFMX_PY_DIR to the folder holding it, or keep this script inside the repository.
# Status: carving logic tested outside Ghidra; not yet run in Ghidra itself.
#
# @category GFMX
# @runtime PyGhidra
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else "."
sys.path.insert(0, os.environ.get("GFMX_PY_DIR", os.path.join(HERE, "..", "..")))
import gfmx  # noqa: E402

MAX_BLOCK = 256 * 1024 * 1024


def _hdr(b, off):
    """(header length, content length) of a definite-length DER element, or None."""
    if off + 2 > len(b):
        return None
    ln = b[off + 1]
    if ln < 0x80:
        return 2, ln
    k = ln & 0x7F
    if k == 0 or k > 3 or off + 2 + k > len(b):
        return None
    return 2 + k, int.from_bytes(b[off + 2:off + 2 + k], "big")


def find_certificates(b):
    """Yield (offset, der) for every SEQUENCE { SEQUENCE, SEQUENCE, BIT STRING } that
    parses as a certificate."""
    i = b.find(b"\x30")
    while i >= 0:
        h = _hdr(b, i) if i + 1 < len(b) and b[i + 1] in (0x81, 0x82, 0x83) else None
        if h and i + h[0] + h[1] <= len(b) and h[1] >= 60:
            body, off, parts, tags = i + h[0], i + h[0], 0, (0x30, 0x30, 0x03)
            end = body + h[1]
            while off < end and parts < 3:
                hh = _hdr(b, off)
                if not hh or b[off] != tags[parts] or off + hh[0] + hh[1] > end:
                    break
                off += hh[0] + hh[1]
                parts += 1
            if parts == 3 and off == end:
                der = bytes(b[i:end])
                try:
                    yield i, der, gfmx.gfmx(der)
                    i = b.find(b"\x30", end)
                    continue
                except gfmx.GFMXError:
                    pass
        i = b.find(b"\x30", i + 1)


def block_bytes(block):
    from jpype import JArray, JByte  # provided by PyGhidra
    buf = JArray(JByte)(int(block.getSize()))
    block.getBytes(block.getStart(), buf)
    try:
        return bytes(memoryview(buf))
    except TypeError:
        return bytes((x & 0xFF) for x in buf)


def run():
    found = 0
    for block in currentProgram.getMemory().getBlocks():  # noqa: F821 (Ghidra global)
        if not block.isInitialized() or block.getSize() > MAX_BLOCK:
            continue
        data = block_bytes(block)
        for off, der, r in find_certificates(data):
            addr = block.getStart().add(off)
            createBookmark(addr, "GFMX", r["gfmx"])  # noqa: F821
            setPlateComment(addr, "X.509 certificate (%d bytes)\nGFMX %s\n%s"  # noqa: F821
                            % (len(der), r["gfmx"], r["raw"]["names"]))
            print("%s  %-44s %s" % (addr, r["gfmx"], block.getName()))
            found += 1
    print("GFMX: %d certificate(s) found" % found)


if "currentProgram" in globals():
    run()
