// Package extract finds the X.509 certificates inside common containers so they can
// be fingerprinted: PEM files, raw DER, PKCS#7/CMS (.p7b, .p7s), Authenticode-signed
// PE files (.exe, .dll, .sys), APK/JAR/ZIP signatures (v1 PKCS#7 and APK Signature
// Scheme v2/v3/v3.1, key-rotation lineage, source stamps, split-APK bundles), and,
// with Carve, certificates embedded anywhere in a binary (implants, firmware, memory
// dumps). Nothing is executed; files are read as bytes.
package extract

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Cert is one certificate found in an input. Source says where it came from, e.g.
// "v2:signer0:cert0", "authenticode0:cert1:signer", "pem2", "carve@0x1f40".
type Cert struct {
	Source string
	DER    []byte
}

// Options controls extraction.
type Options struct {
	Carve bool // also scan for certificates embedded anywhere in the bytes
}

// Kind names the container format Certificates recognised. Binary magic comes first:
// signed executables and APKs often embed PEM text (a bundled CA store), and must still
// be opened as executables and APKs.
func Kind(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")) || bytes.HasPrefix(data, []byte("PK\x05\x06")):
		return "zip"
	case bytes.HasPrefix(data, []byte("MZ")):
		return "pe"
	case isContentInfo(data):
		return "pkcs7"
	case pemRE.Match(data) || pkcs7PEMRE.Match(data):
		return "pem"
	case len(data) > 0 && data[0] == 0x30:
		return "der"
	}
	return "unknown"
}

var (
	pemRE      = regexp.MustCompile(`(?s)-----BEGIN ((?:X509 |TRUSTED )?)CERTIFICATE-----(.+?)-----END (?:X509 |TRUSTED )?CERTIFICATE-----`)
	pkcs7PEMRE = regexp.MustCompile(`(?s)-----BEGIN (?:PKCS7|CMS)-----(.+?)-----END (?:PKCS7|CMS)-----`)
)

func pemBody(s []byte) ([]byte, error) {
	clean := bytes.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '\v' || r == '\f' {
			return -1
		}
		return r
	}, s)
	clean = bytes.TrimRight(clean, "=")
	return base64.RawStdEncoding.DecodeString(string(clean))
}

// Certificates returns the certificates in data. ok is false when data is not a
// recognised container; the caller can then treat it as a single DER certificate.
func Certificates(data []byte, opt Options) (certs []Cert, ok bool) {
	switch Kind(data) {
	case "pem":
		for i, m := range pemRE.FindAllSubmatch(data, -1) {
			if der, err := pemBody(m[2]); err == nil {
				if string(m[1]) == "TRUSTED " {
					der = FirstElement(der)
				}
				certs = append(certs, Cert{fmt.Sprintf("pem%d", i), der})
			}
		}
		for i, m := range pkcs7PEMRE.FindAllSubmatch(data, -1) {
			if der, err := pemBody(m[1]); err == nil {
				certs = append(certs, prefix(fmt.Sprintf("pkcs7pem%d", i), pkcs7Certs(der))...)
			}
		}
		ok = true
	case "zip":
		certs, ok = apkCerts(data, 0), true
	case "pe":
		certs, ok = peCerts(data), true
	case "pkcs7":
		certs, ok = pkcs7Certs(data), true
	}
	if opt.Carve {
		seen := map[string]bool{}
		for _, c := range certs {
			seen[string(c.DER)] = true
		}
		for _, c := range carve(data) {
			if !seen[string(c.DER)] {
				seen[string(c.DER)] = true
				certs = append(certs, c)
			}
		}
		ok = true
	}
	return certs, ok
}

// FirstElement returns the first DER element of b (definite length), or b unchanged if
// it cannot be read. A TRUSTED CERTIFICATE PEM block (OpenSSL X509_AUX) is the
// certificate followed by trust settings; only the certificate is fingerprinted.
func FirstElement(b []byte) []byte {
	if len(b) < 2 {
		return b
	}
	i := 1
	if b[0]&0x1F == 0x1F {
		for i < len(b) && b[i]&0x80 != 0 {
			i++
		}
		i++
	}
	if i >= len(b) {
		return b
	}
	l := int(b[i])
	i++
	if l&0x80 != 0 {
		k := l & 0x7F
		if k == 0 || k > 4 || i+k > len(b) {
			return b
		}
		l = 0
		for _, c := range b[i : i+k] {
			l = l<<8 | int(c)
		}
		i += k
	}
	if l < 0 || i+l > len(b) {
		return b
	}
	return b[:i+l]
}

func prefix(p string, cs []Cert) []Cert {
	for i := range cs {
		cs[i].Source = p + ":" + cs[i].Source
	}
	return cs
}

// ---- lenient BER reader for containers (certificates themselves stay DER) ----

type node struct {
	cls         byte
	constructed bool
	tag         int
	raw         []byte
	content     []byte
	children    []*node
}

// maxDepth bounds how far the container reader expands. Below it, and wherever an element's
// contents do not parse, an element is kept whole without children (an indefinite-length one
// is measured with berEnd, which does not recurse): the reader
// only needs the outer layers (certificate list, serial, issuer), and a certificate that is
// deep or malformed inside is then judged by the fingerprint parser, instead of hiding every
// other certificate in the same file.
const maxDepth = 48

func parseBER(b []byte, depth int) (*node, int, bool) {
	if depth > maxDepth || len(b) < 2 {
		return nil, 0, false
	}
	n := &node{cls: b[0] >> 6, constructed: b[0]&0x20 != 0, tag: int(b[0] & 0x1F)}
	i := 1
	if n.tag == 0x1F {
		n.tag = 0
		for {
			if i >= len(b) || n.tag > 1<<24 {
				return nil, 0, false
			}
			n.tag = n.tag<<7 | int(b[i]&0x7F)
			i++
			if b[i-1]&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(b) {
		return nil, 0, false
	}
	lb := b[i]
	i++
	if lb == 0x80 { // indefinite length: children up to the end-of-contents octets
		if !n.constructed {
			return nil, 0, false
		}
		start := i
		whole := func() (*node, int, bool) { // past the limit, or a child does not parse
			end, ok := berEnd(b)
			if !ok {
				return nil, 0, false
			}
			n.children = nil
			n.content = b[start : end-2]
			n.raw = b[:end]
			return n, end, true
		}
		if depth >= maxDepth {
			return whole()
		}
		for {
			if i+2 > len(b) {
				return nil, 0, false
			}
			if b[i] == 0 && b[i+1] == 0 {
				n.content = b[start:i]
				n.raw = b[:i+2]
				return n, i + 2, true
			}
			c, used, ok := parseBER(b[i:], depth+1)
			if !ok {
				return whole()
			}
			n.children = append(n.children, c)
			i += used
		}
	}
	length := int(lb)
	if lb > 0x80 {
		k := int(lb & 0x7F)
		if k > 4 || i+k > len(b) {
			return nil, 0, false
		}
		length = 0
		for _, x := range b[i : i+k] {
			length = length<<8 | int(x)
		}
		i += k
	}
	if length < 0 || i+length > len(b) {
		return nil, 0, false
	}
	n.content = b[i : i+length]
	n.raw = b[:i+length]
	if n.constructed && depth < maxDepth {
		for j := 0; j < len(n.content); {
			c, used, ok := parseBER(n.content[j:], depth+1)
			if !ok {
				n.children = nil // keep the element whole
				break
			}
			n.children = append(n.children, c)
			j += used
		}
	}
	return n, i + length, true
}

// berHeader reads one identifier and length: header size, content length, whether the
// length is indefinite. Same rules as parseBER.
func berHeader(b []byte) (hdr, length int, indef, ok bool) {
	if len(b) < 2 {
		return 0, 0, false, false
	}
	i, tag := 1, 0
	if b[0]&0x1F == 0x1F {
		for {
			if i >= len(b) || tag > 1<<24 {
				return 0, 0, false, false
			}
			tag = tag<<7 | int(b[i]&0x7F)
			i++
			if b[i-1]&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(b) {
		return 0, 0, false, false
	}
	lb := b[i]
	i++
	if lb == 0x80 {
		return i, 0, b[0]&0x20 != 0, b[0]&0x20 != 0
	}
	length = int(lb)
	if lb > 0x80 {
		k := int(lb & 0x7F)
		if k > 4 || i+k > len(b) {
			return 0, 0, false, false
		}
		length = 0
		for _, x := range b[i : i+k] {
			length = length<<8 | int(x)
		}
		i += k
	}
	if length < 0 || i+length > len(b) {
		return 0, 0, false, false
	}
	return i, length, false, true
}

// berEnd finds where the element at the start of b ends without building a tree: one
// pass over the headers, counting open indefinite-length elements, no recursion.
func berEnd(b []byte) (int, bool) {
	i, open := 0, 0
	for {
		if open > 0 && i+2 <= len(b) && b[i] == 0 && b[i+1] == 0 {
			i += 2
			if open--; open == 0 {
				return i, true
			}
			continue
		}
		hdr, length, indef, ok := berHeader(b[i:])
		if !ok {
			return 0, false
		}
		if indef {
			i += hdr
			open++
			continue
		}
		i += hdr + length
		if open == 0 {
			return i, true
		}
	}
}

func (n *node) is(cls byte, tag int) bool { return n.cls == cls && n.tag == tag }

var oidSignedData = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}

func isContentInfo(b []byte) bool {
	n, _, ok := parseBER(b, 0)
	return ok && len(n.children) >= 2 && n.children[0].is(0, 6) && bytes.Equal(n.children[0].content, oidSignedData)
}

// pkcs7Certs returns the certificates of every SignedData in a ContentInfo, including
// nested ones (Authenticode dual signatures, RFC 3161 timestamp tokens). Certificates
// named by a SignerInfo are labelled ":signer".
func pkcs7Certs(b []byte) []Cert {
	root, _, ok := parseBER(b, 0)
	if !ok {
		return nil
	}
	var out []Cert
	idx := 0
	var visit func(n *node, path string)
	visit = func(n *node, path string) {
		if n.is(0, 16) && len(n.children) >= 2 && n.children[0].is(0, 6) &&
			bytes.Equal(n.children[0].content, oidSignedData) && n.children[1].is(2, 0) &&
			len(n.children[1].children) > 0 {
			sd := n.children[1].children[0]
			label := fmt.Sprintf("%ssd%d", path, idx)
			idx++
			signers := signerIDs(sd)
			for _, c := range sd.children {
				if c.is(2, 0) && c.constructed { // certificates [0] IMPLICIT
					for i, cert := range c.children {
						if !cert.is(0, 16) {
							continue // attribute certificates and other choices
						}
						src := fmt.Sprintf("%s:cert%d", label, i)
						if isSigner(cert, signers) {
							src += ":signer"
						}
						out = append(out, Cert{src, cert.raw})
					}
				}
			}
			for _, c := range sd.children { // nested signatures and timestamp tokens
				if c.is(0, 17) {
					for _, si := range c.children {
						visit(si, label+"/")
					}
				}
			}
			return
		}
		for _, c := range n.children {
			visit(c, path)
		}
	}
	visit(root, "")
	return out
}

type signerID struct{ issuer, serial, ski []byte }

func signerIDs(sd *node) []signerID {
	var ids []signerID
	if len(sd.children) == 0 {
		return nil
	}
	last := sd.children[len(sd.children)-1]
	if !last.is(0, 17) {
		return nil
	}
	for _, si := range last.children {
		if len(si.children) < 2 {
			continue
		}
		sid := si.children[1]
		switch {
		case sid.is(0, 16) && len(sid.children) == 2:
			ids = append(ids, signerID{issuer: sid.children[0].raw, serial: sid.children[1].content})
		case sid.is(2, 0):
			ids = append(ids, signerID{ski: sid.content})
		}
	}
	return ids
}

var oidSKI = []byte{0x55, 0x1D, 0x0E}

func isSigner(cert *node, ids []signerID) bool {
	if len(cert.children) == 0 {
		return false
	}
	tbs := cert.children[0]
	f := tbs.children
	if len(f) > 0 && f[0].is(2, 0) {
		f = f[1:]
	}
	if len(f) < 3 {
		return false
	}
	serial, issuer := f[0].content, f[2].raw
	for _, id := range ids {
		if id.issuer != nil && bytes.Equal(id.issuer, issuer) && bytes.Equal(id.serial, serial) {
			return true
		}
		if id.ski != nil {
			var walk func(n *node) bool
			walk = func(n *node) bool {
				if n.is(0, 16) && len(n.children) >= 2 && n.children[0].is(0, 6) &&
					bytes.Equal(n.children[0].content, oidSKI) {
					v := n.children[len(n.children)-1].content
					if k, _, ok := parseBER(v, 0); ok && bytes.Equal(k.content, id.ski) {
						return true
					}
				}
				for _, c := range n.children {
					if walk(c) {
						return true
					}
				}
				return false
			}
			if walk(tbs) {
				return true
			}
		}
	}
	return false
}

// ---- PE / Authenticode ----

func peCerts(b []byte) []Cert {
	if len(b) < 0x40 {
		return nil
	}
	lfanew := int(binary.LittleEndian.Uint32(b[0x3C:]))
	if lfanew < 0 || lfanew+24 > len(b) || !bytes.Equal(b[lfanew:lfanew+4], []byte("PE\x00\x00")) {
		return nil
	}
	opt := lfanew + 24
	if opt+2 > len(b) {
		return nil
	}
	var dirs int
	switch binary.LittleEndian.Uint16(b[opt:]) {
	case 0x10B:
		dirs = opt + 96
	case 0x20B:
		dirs = opt + 112
	default:
		return nil
	}
	sec := dirs + 4*8 // IMAGE_DIRECTORY_ENTRY_SECURITY
	if sec+8 > len(b) {
		return nil
	}
	off := int(binary.LittleEndian.Uint32(b[sec:])) // a file offset, not an RVA
	size := int(binary.LittleEndian.Uint32(b[sec+4:]))
	if off <= 0 || size <= 0 || off+size > len(b) || off+size < off {
		return nil
	}
	var out []Cert
	for i, p := 0, off; p+8 <= off+size; i++ {
		l := int(binary.LittleEndian.Uint32(b[p:]))
		typ := binary.LittleEndian.Uint16(b[p+6:])
		if l < 8 || p+l > off+size {
			break
		}
		if typ == 2 { // WIN_CERT_TYPE_PKCS_SIGNED_DATA
			out = append(out, prefix(fmt.Sprintf("authenticode%d", i), pkcs7Certs(b[p+8:p+l]))...)
		}
		p += (l + 7) &^ 7
	}
	return out
}

// ---- ZIP: APK v2/v3/v3.1 signing block, v1/JAR PKCS#7, nested APKs ----

var (
	apkSigBlocks   = map[uint32]string{0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1"}
	apkStampBlocks = map[uint32]bool{0x6DFF800D: true, 0x2B09189E: true}
	apkOrder       = map[string]int{"v3.1": 0, "v3": 1, "v2": 2, "v1": 3}
)

const apkRotationAttr = 0x3BA06F8C

func lp(b []byte, off int) ([]byte, int, bool) {
	if off < 0 || off+4 > len(b) {
		return nil, 0, false
	}
	n := int(binary.LittleEndian.Uint32(b[off:]))
	if n < 0 || off+4+n > len(b) || off+4+n < off {
		return nil, 0, false
	}
	return b[off+4 : off+4+n], off + 4 + n, true
}

func lpSeq(b []byte) ([][]byte, bool) {
	var out [][]byte
	for off := 0; off < len(b); {
		v, next, ok := lp(b, off)
		if !ok {
			return out, false
		}
		out = append(out, v)
		off = next
	}
	return out, true
}

func signingBlock(data []byte) [][2][]byte {
	lo := len(data) - 65557
	if lo < 0 {
		lo = 0
	}
	eocd := bytes.LastIndex(data[lo:], []byte("PK\x05\x06"))
	if eocd < 0 {
		return nil
	}
	eocd += lo
	if eocd+20 > len(data) {
		return nil
	}
	cd := int(binary.LittleEndian.Uint32(data[eocd+16:]))
	if cd < 32 || cd > len(data) || string(data[cd-16:cd]) != "APK Sig Block 42" {
		return nil
	}
	size := int(binary.LittleEndian.Uint64(data[cd-24:]))
	start := cd - size - 8
	if size < 0 || start < 0 || int(binary.LittleEndian.Uint64(data[start:])) != size {
		return nil
	}
	var pairs [][2][]byte
	for off, end := start+8, cd-24; off+12 <= end; {
		n := int(binary.LittleEndian.Uint64(data[off:]))
		if n < 4 || off+8+n > end || off+8+n < off {
			break
		}
		pairs = append(pairs, [2][]byte{data[off+8 : off+12], data[off+12 : off+8+n]})
		off += 8 + n
	}
	return pairs
}

func schemeCerts(value []byte, scheme string) []Cert {
	var out []Cert
	signers, _, ok := lp(value, 0)
	if !ok {
		return nil
	}
	list, _ := lpSeq(signers)
	for si, signer := range list {
		signed, _, ok := lp(signer, 0)
		if !ok {
			continue
		}
		_, off, ok := lp(signed, 0) // digests
		if !ok {
			continue
		}
		certs, off, ok := lp(signed, off)
		if !ok {
			continue
		}
		ders, _ := lpSeq(certs)
		for ci, der := range ders {
			out = append(out, Cert{fmt.Sprintf("%s:signer%d:cert%d", scheme, si, ci), der})
		}
		if strings.HasPrefix(scheme, "v3") {
			off += 8 // minSdkVersion, maxSdkVersion
		}
		attrs, _, ok := lp(signed, off)
		if !ok {
			continue
		}
		al, _ := lpSeq(attrs)
		for _, attr := range al {
			if len(attr) < 8 || binary.LittleEndian.Uint32(attr) != apkRotationAttr {
				continue
			}
			nodes, _ := lpSeq(attr[8:]) // lineage version, then nodes, oldest first
			for ni, nd := range nodes {
				ns, _, ok := lp(nd, 0)
				if !ok {
					continue
				}
				if der, _, ok := lp(ns, 0); ok {
					out = append(out, Cert{fmt.Sprintf("%s:signer%d:lineage%d", scheme, si, ni), der})
				}
			}
		}
	}
	return out
}

var v1Name = regexp.MustCompile(`(?i)^META-INF/[^/]+\.(RSA|DSA|EC)$`)

const (
	maxMember     = 64 << 20  // one member, inflated
	maxZipTotal   = 256 << 20 // all members read from one ZIP, inflated
	maxV1Member   = 4 << 20   // a v1 signature block is a few KiB
	maxNestedAPKs = 64
)

func isV1(name string) bool  { return v1Name.MatchString(name) }
func isAPK(name string) bool { return strings.HasSuffix(strings.ToLower(name), ".apk") }

// zipMembers reads the members `want` selects, within a total budget, so a crafted
// archive cannot make it hold more than maxZipTotal bytes. A ZIP whose central
// directory is broken (common in malware) is read through its local file headers.
func zipMembers(data []byte, want func(string) bool, limit int) map[string][]byte {
	out := map[string][]byte{}
	budget := maxZipTotal
	take := func(name string, r io.Reader) {
		if _, dup := out[name]; dup || budget <= 0 {
			return
		}
		n := limit
		if n > budget {
			n = budget
		}
		if b, err := io.ReadAll(io.LimitReader(r, int64(n)+1)); err == nil && len(b) <= n {
			out[name] = b
			budget -= len(b)
		}
	}
	if z, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
		for _, f := range z.File {
			if want(f.Name) && f.UncompressedSize64 <= uint64(limit) {
				if rc, err := f.Open(); err == nil {
					take(f.Name, rc)
					rc.Close()
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	for h := bytes.Index(data, []byte("PK\x03\x04")); h >= 0; {
		if h+30 <= len(data) {
			method := binary.LittleEndian.Uint16(data[h+8:])
			csize := int(binary.LittleEndian.Uint32(data[h+18:]))
			nlen := int(binary.LittleEndian.Uint16(data[h+26:]))
			xlen := int(binary.LittleEndian.Uint16(data[h+28:]))
			st := h + 30 + nlen + xlen
			if st <= len(data) && h+30+nlen <= len(data) && csize >= 0 && st+csize <= len(data) {
				name := string(data[h+30 : h+30+nlen])
				if want(name) {
					body := data[st : st+csize]
					if method == 8 {
						take(name, flate.NewReader(bytes.NewReader(body)))
					} else if method == 0 {
						take(name, bytes.NewReader(body))
					}
				}
			}
		}
		n := bytes.Index(data[h+4:], []byte("PK\x03\x04"))
		if n < 0 {
			break
		}
		h += 4 + n
	}
	return out
}

// zipNames lists member names `want` selects (central directory, else local headers),
// sorted and without reading any contents.
func zipNames(data []byte, want func(string) bool) []string {
	seen := map[string]bool{}
	if z, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
		for _, f := range z.File {
			if want(f.Name) {
				seen[f.Name] = true
			}
		}
	} else {
		for h := bytes.Index(data, []byte("PK\x03\x04")); h >= 0; {
			if h+30 <= len(data) {
				nlen := int(binary.LittleEndian.Uint16(data[h+26:]))
				if h+30+nlen <= len(data) && want(string(data[h+30:h+30+nlen])) {
					seen[string(data[h+30:h+30+nlen])] = true
				}
			}
			n := bytes.Index(data[h+4:], []byte("PK\x03\x04"))
			if n < 0 {
				break
			}
			h += 4 + n
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func apkCerts(data []byte, depth int) []Cert {
	var found []Cert
	for _, p := range signingBlock(data) {
		id := binary.LittleEndian.Uint32(p[0])
		if s, ok := apkSigBlocks[id]; ok {
			found = append(found, schemeCerts(p[1], s)...)
		} else if apkStampBlocks[id] {
			if stamp, _, ok := lp(p[1], 0); ok {
				if der, _, ok := lp(stamp, 0); ok {
					found = append(found, Cert{"stamp", der})
				}
			}
		}
	}
	v1 := zipMembers(data, isV1, maxV1Member)
	names := make([]string, 0, len(v1))
	for n := range v1 {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		found = append(found, prefix("v1:"+n, pkcs7Certs(v1[n]))...)
	}
	if len(found) == 0 && depth == 0 { // split-APK bundles (.apks, .xapk), one at a time
		apks := zipNames(data, isAPK)
		if len(apks) > maxNestedAPKs {
			apks = apks[:maxNestedAPKs]
		}
		for _, n := range apks {
			one := zipMembers(data, func(m string) bool { return m == n }, maxMember)
			for _, c := range apkCerts(one[n], 1) {
				found = append(found, Cert{n + "!" + c.Source, c.DER})
			}
		}
	}
	rank := func(c Cert) (int, int) {
		src := c.Source[strings.LastIndex(c.Source, "!")+1:]
		kind := strings.SplitN(src, ":", 2)[0]
		a := 1
		if strings.Contains(src, ":cert") {
			a = 0
		}
		o, ok := apkOrder[kind]
		if !ok {
			o = 4
		}
		return a, o
	}
	sort.SliceStable(found, func(i, j int) bool {
		a1, o1 := rank(found[i])
		a2, o2 := rank(found[j])
		return a1 < a2 || (a1 == a2 && o1 < o2)
	})
	return found
}

// ---- carving ----

// carve finds DER certificates anywhere in b (Certificate ::= SEQUENCE { tbs SEQUENCE,
// sigAlg SEQUENCE, sig BIT STRING }) and PEM blocks in text.
func carve(b []byte) []Cert {
	var out []Cert
	for i, m := range pemRE.FindAllSubmatchIndex(b, -1) {
		if der, err := pemBody(b[m[4]:m[5]]); err == nil {
			if string(b[m[2]:m[3]]) == "TRUSTED " {
				der = FirstElement(der)
			}
			out = append(out, Cert{fmt.Sprintf("carve-pem%d@0x%x", i, m[0]), der})
		}
	}
	for i := 0; i+4 < len(b); i++ {
		if b[i] != 0x30 || b[i+1] < 0x81 || b[i+1] > 0x83 {
			continue
		}
		if c, ok := certShape(b[i:]); ok {
			out = append(out, Cert{fmt.Sprintf("carve@0x%x", i), c})
			i += len(c) - 1
		}
	}
	return out
}

func certShape(b []byte) ([]byte, bool) {
	// top level and the TBS must be definite-length DER-looking SEQUENCEs
	if len(b) < 64 || b[0] != 0x30 {
		return nil, false
	}
	hdr := func(x []byte) (int, int, bool) {
		if len(x) < 2 {
			return 0, 0, false
		}
		l := int(x[1])
		h := 2
		if l&0x80 != 0 {
			k := l & 0x7F
			if k == 0 || k > 3 || len(x) < 2+k {
				return 0, 0, false
			}
			l = 0
			for _, c := range x[2 : 2+k] {
				l = l<<8 | int(c)
			}
			h += k
		}
		return h, l, h+l <= len(x)
	}
	h, l, ok := hdr(b)
	if !ok {
		return nil, false
	}
	body := b[h : h+l]
	parts := 0
	for off := 0; off < len(body); parts++ {
		if parts > 2 {
			return nil, false
		}
		hh, ll, ok := hdr(body[off:])
		if !ok {
			return nil, false
		}
		want := []byte{0x30, 0x30, 0x03}[parts]
		if body[off] != want {
			return nil, false
		}
		off += hh + ll
	}
	if parts != 3 {
		return nil, false
	}
	return b[:h+l], true
}
