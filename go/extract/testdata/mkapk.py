"""Build the APK fixtures (test.apk, v1only.jar, bundle.apks, brokencd.apk) from
signer.der, ca.der and sig.p7s. The signing blocks are structurally valid but carry
placeholder digests and signatures: they test extraction, not verification."""
import io, struct, zipfile
sig = open('sig.p7s','rb').read()
signer = open('signer.der','rb').read()
ca = open('ca.der','rb').read()
def lp(b): return struct.pack('<I', len(b)) + b
def lps(items): return b''.join(lp(x) for x in items)
def mkzip(members):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as z:
        for n, d in members.items(): z.writestr(n, d)
    return bio.getvalue()
def add_block(data, pairs):
    eocd = data.rfind(b'PK\x05\x06'); cd = struct.unpack('<I', data[eocd+16:eocd+20])[0]
    body = b''.join(struct.pack('<Q', 4+len(v)) + struct.pack('<I', i) + v for i, v in pairs)
    size = len(body) + 8 + 16
    block = struct.pack('<Q', size) + body + struct.pack('<Q', size) + b'APK Sig Block 42'
    out = data[:cd] + block + data[cd:]
    eocd += len(block)
    return out[:eocd+16] + struct.pack('<I', cd + len(block)) + out[eocd+20:]
signed_v2 = lp(lps([b'digest'])) + lp(lps([signer, ca])) + lp(b'')
v2 = lp(lps([lp(signed_v2) + lp(lps([b'sig'])) + lp(b'pk')]))
rot = struct.pack('<I', 0x3BA06F8C) + struct.pack('<I', 1) + lps([lp(lp(ca) + b'xx')])
signed_v3 = lp(lps([b'digest'])) + lp(lps([signer])) + struct.pack('<II', 28, 0x7fffffff) + lp(lps([rot]))
v3 = lp(lps([lp(signed_v3) + struct.pack('<II', 28, 0x7fffffff) + lp(lps([b'sig'])) + lp(b'pk')]))
stamp = lp(lp(ca) + lp(b'sigs'))
apk = mkzip({'AndroidManifest.xml': b'\x03\x00', 'classes.dex': b'dex\n035', 'META-INF/CERT.RSA': sig, 'META-INF/MANIFEST.MF': b'x'})
open('test.apk','wb').write(add_block(apk, [(0x7109871A, v2), (0xF05368C0, v3), (0x6DFF800D, stamp)]))
open('bundle.apks','wb').write(mkzip({'base.apk': add_block(apk, [(0x7109871A, v2)]), 'split_config.en.apk': apk}))
# broken central directory: drop everything after the local headers
open('brokencd.apk','wb').write(apk[:apk.find(b'PK\x01\x02')])
