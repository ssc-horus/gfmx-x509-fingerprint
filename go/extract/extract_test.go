package extract

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Fixtures: a test CA (ca.der) and an EC code-signing certificate it issued
// (signer.der); sig.p7s is a CMS signature by signer.der that also carries ca.der.
// testdata/mkapk.py builds the APK fixtures from them.

func read(t *testing.T, name string) []byte {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func check(t *testing.T, name string, got []Cert, want map[string][]byte) {
	t.Helper()
	have := map[string][]byte{}
	for _, c := range got {
		have[c.Source] = c.DER
	}
	for src, der := range want {
		if !bytes.Equal(have[src], der) {
			t.Errorf("%s: %s missing or wrong (have %v)", name, src, keys(have))
		}
	}
	if len(have) != len(want) {
		t.Errorf("%s: got %d certificates, want %d: %v", name, len(have), len(want), keys(have))
	}
}

func keys(m map[string][]byte) string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return strings.Join(k, " ")
}

// minimalPE builds a PE32+ header whose security directory holds the given
// WIN_CERTIFICATE entries (each a PKCS#7 SignedData).
func minimalPE(sigs ...[]byte) []byte {
	b := make([]byte, 0x40+4+20+240)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3C:], 0x40)
	copy(b[0x40:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x44:], 0x8664)
	binary.LittleEndian.PutUint16(b[0x44+16:], 240)
	opt := 0x40 + 24
	binary.LittleEndian.PutUint16(b[opt:], 0x20B)
	var blob []byte
	for _, s := range sigs {
		e := make([]byte, 8, 8+len(s)+8)
		binary.LittleEndian.PutUint32(e, uint32(8+len(s)))
		binary.LittleEndian.PutUint16(e[4:], 0x0200)
		binary.LittleEndian.PutUint16(e[6:], 2)
		e = append(e, s...)
		for len(e)%8 != 0 {
			e = append(e, 0)
		}
		blob = append(blob, e...)
	}
	binary.LittleEndian.PutUint32(b[opt+112+32:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[opt+112+36:], uint32(len(blob)))
	return append(b, blob...)
}

func TestContainers(t *testing.T) {
	signer, ca := read(t, "signer.der"), read(t, "ca.der")
	sig := read(t, "sig.p7s")
	v1 := map[string][]byte{"v1:META-INF/CERT.RSA:sd0:cert0:signer": signer, "v1:META-INF/CERT.RSA:sd0:cert1": ca}
	cases := []struct {
		name string
		data []byte
		kind string
		want map[string][]byte
	}{
		{"chain.p7b", read(t, "chain.p7b"), "pem", map[string][]byte{"pkcs7pem0:sd0:cert0": signer, "pkcs7pem0:sd0:cert1": ca}},
		{"sig.p7s", sig, "pkcs7", map[string][]byte{"sd0:cert0:signer": signer, "sd0:cert1": ca}},
		{"sig_ber.p7s (indefinite lengths)", read(t, "sig_ber.p7s"), "pkcs7", map[string][]byte{"sd0:cert0:signer": signer, "sd0:cert1": ca}},
		{"test.apk", read(t, "test.apk"), "zip", merge(v1, map[string][]byte{
			"v2:signer0:cert0": signer, "v2:signer0:cert1": ca, "v3:signer0:cert0": signer,
			"v3:signer0:lineage0": ca, "stamp": ca})},
		{"bundle.apks", read(t, "bundle.apks"), "zip", map[string][]byte{
			"base.apk!v2:signer0:cert0": signer, "base.apk!v2:signer0:cert1": ca,
			"base.apk!v1:META-INF/CERT.RSA:sd0:cert0:signer": signer, "base.apk!v1:META-INF/CERT.RSA:sd0:cert1": ca,
			"split_config.en.apk!v1:META-INF/CERT.RSA:sd0:cert0:signer": signer,
			"split_config.en.apk!v1:META-INF/CERT.RSA:sd0:cert1":        ca}},
		{"brokencd.apk", read(t, "brokencd.apk"), "zip", v1},
		{"pe", minimalPE(sig, sig), "pe", map[string][]byte{
			"authenticode0:sd0:cert0:signer": signer, "authenticode0:sd0:cert1": ca,
			"authenticode1:sd0:cert0:signer": signer, "authenticode1:sd0:cert1": ca}},
	}
	for _, c := range cases {
		if k := Kind(c.data); k != c.kind {
			t.Errorf("%s: kind %s, want %s", c.name, k, c.kind)
		}
		got, ok := Certificates(c.data, Options{})
		if !ok {
			t.Errorf("%s: not recognised", c.name)
		}
		check(t, c.name, got, c.want)
	}
	got, _ := Certificates(read(t, "implant.bin"), Options{Carve: true})
	if len(got) != 2 || !bytes.Equal(got[0].DER, ca) || !strings.HasPrefix(got[0].Source, "carve@0x") {
		t.Errorf("carve: got %d certificates", len(got))
	}
}

func merge(a, b map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func FuzzCertificates(f *testing.F) {
	for _, n := range []string{"chain.p7b", "sig_ber.p7s", "test.apk", "bundle.apks", "brokencd.apk", "implant.bin"} {
		b, _ := os.ReadFile(filepath.Join("testdata", n))
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		Certificates(b, Options{Carve: true})
	})
}

// Regression: binaries that embed PEM text (a bundled CA store) must still be
// opened as executables or APKs, so their signers are not dropped.
func TestEmbeddedPEMDoesNotHideContainer(t *testing.T) {
	signer, ca := read(t, "signer.der"), read(t, "ca.der")
	pemText := []byte("-----BEGIN CERTIFICATE-----\nnot really base64 %s\n-----END CERTIFICATE-----\n")
	pe := minimalPE(read(t, "sig.p7s"))
	pe = append(pe[:len(pe):len(pe)], pemText...) // PEM text after the signature table
	if k := Kind(pe); k != "pe" {
		t.Fatalf("PE with embedded PEM: kind %s", k)
	}
	got, _ := Certificates(pe, Options{})
	check(t, "pe+pem", got, map[string][]byte{"authenticode0:sd0:cert0:signer": signer, "authenticode0:sd0:cert1": ca})

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "assets/cacert.pem", Method: zip.Store})
	w.Write(pemText)
	w, _ = zw.Create("META-INF/CERT.RSA")
	w.Write(read(t, "sig.p7s"))
	zw.Close()
	if k := Kind(buf.Bytes()); k != "zip" {
		t.Fatalf("APK with stored PEM asset: kind %s", k)
	}
	got, _ = Certificates(buf.Bytes(), Options{})
	check(t, "apk+pem", got, map[string][]byte{"v1:META-INF/CERT.RSA:sd0:cert0:signer": signer, "v1:META-INF/CERT.RSA:sd0:cert1": ca})
}

// Regression: many nested .apk members that inflate to a lot of zeros must
// not all be held in memory at once.
func TestZipBombBounded(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zeros := make([]byte, 2<<20)
	for i := 0; i < 100; i++ {
		w, _ := zw.Create(fmt.Sprintf("x%03d.apk", i))
		w.Write(zeros)
	}
	zw.Close()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got, ok := Certificates(buf.Bytes(), Options{})
	runtime.ReadMemStats(&after)
	if !ok || len(got) != 0 {
		t.Fatalf("got %d certificates", len(got))
	}
	if grew := int64(after.HeapInuse) - int64(before.HeapInuse); grew > 64<<20 {
		t.Errorf("heap grew by %d MiB", grew>>20)
	}
}

func tlv(tag byte, body ...[]byte) []byte {
	b := bytes.Join(body, nil)
	n := len(b)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, b...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, b...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, b...)
	}
}

// A certificate nested deeper than the container reader expands (or malformed inside)
// must not hide the other certificates in the same PKCS#7: it is passed on whole and the
// fingerprint parser judges it. Before the fix this file gave one error and no certificate.
func TestDeepCertificateDoesNotHideOthers(t *testing.T) {
	ca := read(t, "ca.der")
	deep := tlv(0x05)
	for i := 0; i < 100; i++ {
		deep = tlv(0x30, deep)
	}
	bad := tlv(0x30, []byte{0x30, 0x7f, 0x00}) // contents that do not parse
	oid := func(h string) []byte { b, _ := hex.DecodeString(h); return tlv(0x06, b) }
	sd := tlv(0x30, tlv(0x02, []byte{1}), tlv(0x31), tlv(0x30, oid("2a864886f70d010701")),
		tlv(0xA0, ca, deep, bad), tlv(0x31))
	p7 := tlv(0x30, oid("2a864886f70d010702"), tlv(0xA0, sd))
	if k := Kind(p7); k != "pkcs7" {
		t.Fatalf("kind %s", k)
	}
	got, _ := Certificates(p7, Options{})
	check(t, "deep.p7b", got, map[string][]byte{"sd0:cert0": ca, "sd0:cert1": deep, "sd0:cert2": bad})
}

// Regression: the same in BER, where certificates [0] and the crafted certificate use
// indefinite lengths and the crafted one goes past the reader's depth limit.
func TestDeepIndefiniteCertificateDoesNotHideOthers(t *testing.T) {
	ca := read(t, "ca.der")
	indef := func(tag byte, body ...[]byte) []byte {
		return append(append([]byte{tag, 0x80}, bytes.Join(body, nil)...), 0, 0)
	}
	deep := tlv(0x05)
	for i := 0; i < 100; i++ {
		deep = indef(0x30, deep)
	}
	bad := indef(0x30, tlv(0x30, []byte{0x30, 0x7f, 0x00})) // malformed inside, end findable
	oid := func(h string) []byte { b, _ := hex.DecodeString(h); return tlv(0x06, b) }
	sd := indef(0x30, tlv(0x02, []byte{1}), tlv(0x31), tlv(0x30, oid("2a864886f70d010701")),
		indef(0xA0, ca, deep, bad), tlv(0x31))
	p7 := indef(0x30, oid("2a864886f70d010702"), indef(0xA0, sd))
	if k := Kind(p7); k != "pkcs7" {
		t.Fatalf("kind %s", k)
	}
	got, _ := Certificates(p7, Options{})
	check(t, "deep-ber.p7b", got, map[string][]byte{"sd0:cert0": ca, "sd0:cert1": deep, "sd0:cert2": bad})
}

// berEnd finds the end of nested indefinite-length elements without recursion, and
// reports failure rather than guessing when the end-of-contents octets are missing.
func TestBerEnd(t *testing.T) {
	full := append(bytes.Repeat([]byte{0x30, 0x80}, 100000), 0x05, 0x00)
	full = append(full, make([]byte, 200000)...) // 100,000 end-of-contents octets
	if n, ok := berEnd(append(full, 0xFF)); !ok || n != len(full) {
		t.Fatalf("berEnd = %d, %v; want %d", n, ok, len(full))
	}
	if _, ok := berEnd(full[:len(full)-2]); ok {
		t.Fatal("berEnd accepted a missing end-of-contents")
	}
}
