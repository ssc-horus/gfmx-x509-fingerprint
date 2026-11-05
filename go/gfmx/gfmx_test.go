package gfmx

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// vector is one line of testdata/vectors.jsonl (produced by the reference
// implementation, gfmx.py). Error vectors only require that parsing fails.
type vector struct {
	Name  string `json:"name"`
	DER   string `json:"der"`
	GFMX  string `json:"gfmx"`
	Raw   Raw    `json:"raw"`
	Info  string `json:"info"`
	Error bool   `json:"error"`
}

func loadVectors(t testing.TB) []vector {
	f, err := os.Open(filepath.Join("..", "..", "testdata", "vectors.jsonl"))
	if err != nil {
		t.Fatalf("open vectors: %v", err)
	}
	defer f.Close()
	var out []vector
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var v vector
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatalf("bad vector line: %v", err)
		}
		out = append(out, v)
	}
	return out
}

func TestVectors(t *testing.T) {
	vs := loadVectors(t)
	if len(vs) < 100 {
		t.Fatalf("only %d vectors", len(vs))
	}
	for _, v := range vs {
		der, err := base64.StdEncoding.DecodeString(v.DER)
		if err != nil {
			t.Fatalf("%s: bad base64", v.Name)
		}
		r, err := Fingerprint(der)
		if v.Error {
			if err == nil {
				t.Errorf("%s: expected a parse error, got %s", v.Name, r.GFMX)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", v.Name, err)
			continue
		}
		if r.GFMX != v.GFMX || r.Raw != v.Raw || r.Info != v.Info {
			t.Errorf("%s:\n got  %s %+v %s\n want %s %+v %s", v.Name, r.GFMX, r.Raw, r.Info, v.GFMX, v.Raw, v.Info)
		}
	}
}

func FuzzFingerprint(f *testing.F) {
	for _, v := range loadVectors(f) {
		der, _ := base64.StdEncoding.DecodeString(v.DER)
		f.Add(der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		fingerprint(der) // no recover: any panic is a bug
	})
}

func BenchmarkFingerprint(b *testing.B) {
	var ders [][]byte
	for _, v := range loadVectors(b) {
		if !v.Error {
			der, _ := base64.StdEncoding.DecodeString(v.DER)
			ders = append(ders, der)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Fingerprint(ders[i%len(ders)]); err != nil {
			b.Fatal(err)
		}
	}
}

// nestNull wraps a NULL in d SEQUENCEs.
func nestNull(d int) []byte {
	b := []byte{0x05, 0x00}
	for i := 0; i < d; i++ {
		n := len(b)
		switch {
		case n < 0x80:
			b = append([]byte{0x30, byte(n)}, b...)
		case n < 0x100:
			b = append([]byte{0x30, 0x81, byte(n)}, b...)
		default:
			b = append([]byte{0x30, 0x82, byte(n >> 8), byte(n)}, b...)
		}
	}
	return b
}

// The Go reader accepts nesting up to maxDepth (64, as the reference) and no deeper.
func TestDepthLimit(t *testing.T) {
	if _, _, err := parseTLV(nestNull(maxDepth), 0, 0); err != nil {
		t.Fatalf("depth %d: %v", maxDepth, err)
	}
	if _, _, err := parseTLV(nestNull(maxDepth+1), 0, 0); err != errDepth {
		t.Fatalf("depth %d: got %v, want %v", maxDepth+1, err, errDepth)
	}
}

func TestErrorKind(t *testing.T) {
	for _, tc := range []struct {
		name string
		der  []byte
		want Kind
	}{
		{"truncated", []byte{0x30, 0x05, 0x02}, KindMalformed},
		{"no tbs", nestNull(1), KindMalformed},
		{"too deep", nestNull(maxDepth + 1), KindDepth},
	} {
		_, err := Fingerprint(tc.der)
		var xe *Error
		if !errors.As(err, &xe) {
			t.Fatalf("%s: got %v, want *Error", tc.name, err)
		}
		if xe.Kind != tc.want {
			t.Errorf("%s: kind %v, want %v", tc.name, xe.Kind, tc.want)
		}
	}
}

// decodeOID's fast path must render exactly as decodeOIDBig, the general decoder.
func TestDecodeOIDFastPath(t *testing.T) {
	cases := [][]byte{
		nil, {0x00}, {0x27}, {0x28}, {0x4F}, {0x50}, {0x81}, {0x2A, 0x86},
		{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F},       // 8-byte first arc
		{0x2A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}, // 9-byte arc
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 200000; i++ {
		b := make([]byte, rng.IntN(24))
		for j := range b {
			b[j] = byte(rng.Uint32())
			if rng.IntN(3) == 0 {
				b[j] &= 0x7F // end arcs often, so most inputs have several
			}
		}
		cases = append(cases, b)
	}
	for _, c := range cases {
		if got, want := decodeOID(c), decodeOIDBig(c); got != want {
			t.Fatalf("% x: fast %q, general %q", c, got, want)
		}
	}
}

// Both decoders apply maxArcs; a 9-byte arc sends the fast path to decodeOIDBig.
func TestDecodeOIDArcLimit(t *testing.T) {
	oid := func(arcs int, long bool) []byte {
		b := []byte{0x55}
		if long {
			b = append(b, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01)
			arcs--
		}
		return append(b, bytes.Repeat([]byte{0x01}, arcs-1)...)
	}
	for _, long := range []bool{false, true} {
		for _, n := range []int{maxArcs, maxArcs + 1} {
			c := oid(n, long)
			got, big := decodeOID(c), decodeOIDBig(c)
			if got != big {
				t.Fatalf("%d arcs, long %v: fast %q, general %q", n, long, got, big)
			}
			if (got == "x") != (n > maxArcs) {
				t.Errorf("%d arcs, long %v: got %q", n, long, got)
			}
		}
	}
}

// derHeader encodes an identifier octet and a definite length.
func derHeader(first byte, n int) []byte {
	if n < 0x80 {
		return []byte{first, byte(n)}
	}
	var l []byte
	for v := n; v > 0; v >>= 8 {
		l = append([]byte{byte(v)}, l...)
	}
	return append([]byte{first, 0x80 | byte(len(l))}, l...)
}

// replaceContent re-encodes t with target's contents replaced, fixing every length
// on the way down; it reports whether target was found under t.
func replaceContent(t, target *tlv, content []byte) ([]byte, bool) {
	if t == target {
		return append(derHeader(t.first, len(content)), content...), true
	}
	if !t.constructed {
		return t.raw, false
	}
	var body []byte
	found := false
	for _, c := range t.children {
		b, ok := replaceContent(c, target, content)
		body = append(body, b...)
		found = found || ok
	}
	if !found {
		return t.raw, false
	}
	return append(derHeader(t.first, len(body)), body...), true
}

func vectorDER(t *testing.T, name string) []byte {
	for _, v := range loadVectors(t) {
		if v.Name == name {
			der, _ := base64.StdEncoding.DecodeString(v.DER)
			return der
		}
	}
	t.Fatalf("no vector %s", name)
	return nil
}

// Inputs that cost seconds and gigabytes before spec 1-draft.2 must now be cheap.
func TestHostileLimitsAreCheap(t *testing.T) {
	const mb = 1 << 20
	edit := func(name string, pick func(tbs *tlv) *tlv, content []byte) []byte {
		der := vectorDER(t, name)
		root, _, err := parseTLV(der, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		out, ok := replaceContent(root, pick(root.children[0]), content)
		if !ok {
			t.Fatalf("%s: target not found", name)
		}
		return out
	}
	serial := func(tbs *tlv) *tlv { return tbs.children[1] }
	dsaG := func(tbs *tlv) *tlv { return tbs.children[6].children[0].children[1].children[2] }
	extOID := func(tbs *tlv) *tlv {
		exts := tbs.children[len(tbs.children)-1].children[0].children
		for _, e := range exts {
			if len(e.children[0].content) > maxArcBytes {
				return e.children[0]
			}
		}
		return nil
	}
	bigG := append([]byte{0x01}, make([]byte, mb)...)
	arcs := append([]byte{0x55, 0x1d}, bytes.Repeat([]byte{0x01}, mb)...)
	for _, tc := range []struct {
		name string
		der  []byte
		ok   func(*Result) bool
	}{
		{"mtc serial 1 MB", edit("pq/mtc_log3.der", serial, append([]byte{0x01}, make([]byte, mb)...)),
			func(r *Result) bool { return strings.HasSuffix(r.Info, ";mtc=x/0") }},
		{"dsa g 1 MB", edit("alg/c_dsa1k.der", dsaG, bigG),
			func(r *Result) bool { return strings.HasPrefix(r.Raw.Key, "iss=u;") }},
		{"oid 1M arcs", edit("hostile/oid_long_arc.der", extOID, arcs),
			func(r *Result) bool { return strings.Contains(r.Raw.Maker, ";ext=x!;") }},
	} {
		start := time.Now()
		r, err := Fingerprint(tc.der)
		took := time.Since(start)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !tc.ok(r) {
			t.Errorf("%s: unexpected result %+v %s", tc.name, r.Raw, r.Info)
		}
		if took > 500*time.Millisecond {
			t.Errorf("%s: took %v", tc.name, took)
		}
	}
}
