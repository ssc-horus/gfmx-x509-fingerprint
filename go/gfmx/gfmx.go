// Package gfmx computes GFMX, an X.509 certificate template fingerprint:
//
//	KEY:SPAN:MAKER:AUDIENCE:NAMES      e.g. 2116e00d:dc34f8dc:96d5c677::e52bbfa2
//
// Each segment is the first 8 hex characters of SHA-256 over a canonical pre-hash
// string (docs/SPEC.md). This package is a port of the reference implementation
// (gfmx.py) and must give byte-identical output; the conformance vectors in
// testdata/ and the cross-check in the repository enforce that.
package gfmx

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Version of this implementation; SpecVersion is the pre-hash definition it follows.
const (
	Version     = "0.9.10"
	SpecVersion = "1-draft.3"
)

// Result is one certificate's fingerprint.
type Result struct {
	GFMX string `json:"gfmx"`
	Raw  Raw    `json:"raw"`
	Info string `json:"info"` // unhashed: string-type choice, exact span, serial sign/padding
}

// Raw holds the pre-hash string of each segment.
type Raw struct {
	Key      string `json:"key"`
	Span     string `json:"span"`
	Maker    string `json:"maker"`
	Audience string `json:"audience"`
	Names    string `json:"names"`
}

// Kind classifies an Error, for callers that count failures (a metric label must
// not carry the free-text message).
type Kind int

const (
	// KindMalformed: the input is not a parseable X.509 certificate.
	KindMalformed Kind = iota
	// KindDepth: DER nesting exceeds maxDepth.
	KindDepth
	// KindInternal: a bug was caught; the input may well be a valid certificate.
	KindInternal
)

// String returns a short, stable name for the kind.
func (k Kind) String() string {
	switch k {
	case KindDepth:
		return "depth"
	case KindInternal:
		return "internal"
	default:
		return "malformed"
	}
}

// Error is returned when the input is not a parseable X.509 certificate.
type Error struct {
	Kind Kind
	msg  string
}

func (e *Error) Error() string { return e.msg }

const (
	oidSAN        = "2.5.29.17"
	oidSKI        = "2.5.29.14"
	oidAKI        = "2.5.29.35"
	oidKU         = "2.5.29.15"
	oidEKU        = "2.5.29.37"
	oidBC         = "2.5.29.19"
	oidPolicies   = "2.5.29.32"
	oidCDP        = "2.5.29.31"
	oidAIA        = "1.3.6.1.5.5.7.1.1"
	oidMSTmplName = "1.3.6.1.4.1.311.20.2"
	oidMSTmplInfo = "1.3.6.1.4.1.311.21.7"
	oidRSA        = "1.2.840.113549.1.1.1"
	oidCTPoison   = "1.3.6.1.4.1.11129.2.4.3"
	oidCTSCTs     = "1.3.6.1.4.1.11129.2.4.2"
	oidAltSPKI    = "2.5.29.72"          // subjectAltPublicKeyInfo (X.509 hybrid)
	oidAltSigAlg  = "2.5.29.73"          // altSignatureAlgorithm (X.509 hybrid)
	oidMTC        = "1.3.6.1.5.5.7.6.67" // id-alg-mtcProof (Merkle Tree Certificates)
)

var extListExcluded = map[string]bool{oidSAN: true, oidCTPoison: true, oidCTSCTs: true}

// Attributes whose string type the standards fix (a wrong type is an encoding flag).
var fixedStringAttrs = map[string]byte{
	"2.5.4.6": 0x13, "2.5.4.5": 0x13, "2.5.4.46": 0x13,
	"1.2.840.113549.1.9.1": 0x16, "0.9.2342.19200300.100.1.25": 0x16,
}

var stringTags = map[byte]string{0x13: "P", 0x0C: "U", 0x16: "I", 0x1E: "B", 0x14: "T", 0x1C: "V"}

func h8(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

// Fingerprint computes the GFMX of one DER-encoded certificate.
func Fingerprint(der []byte) (res *Result, err error) {
	defer func() { // a bug must never take a scanner down: report it as a parse error
		if r := recover(); r != nil {
			res, err = nil, &Error{KindInternal, fmt.Sprint("internal error: ", r)}
		}
	}()
	return fingerprint(der)
}

func perr(msg string) error { return &Error{KindMalformed, msg} }

// derErr wraps a TLV reader error, keeping the depth limit distinguishable.
func derErr(err error) error {
	if errors.Is(err, errDepth) {
		return &Error{KindDepth, err.Error()}
	}
	return perr(err.Error())
}

func mustChild(t *tlv, i int) (*tlv, error) {
	if t == nil || i >= len(t.children) {
		return nil, perr("list index out of range")
	}
	return t.children[i], nil
}

// parseNameTails is the lenient parse for a certificate that failed the strict one.
// Data after the value is accepted only inside an issuer or subject attribute (seen
// from firmware that patched the outer lengths but not the value's own, e.g. 2Wire
// gateways). It returns nil when anything else is wrong, and the caller then reports
// the strict-parse error.
func parseNameTails(der []byte) (*tlv, int) {
	p := parser{lax: true}
	root, end, err := p.parse(der, 0, 0)
	if err != nil || len(p.tails) == 0 || len(root.children) == 0 {
		return nil, 0
	}
	f := root.children[0].children
	idx := 0
	if len(f) > 0 && isContext(f[0], 0) {
		idx = 1
	}
	if len(f) <= idx+4 {
		return nil, 0
	}
	atvs := map[*tlv]bool{}
	for _, name := range []*tlv{f[idx+2], f[idx+4]} {
		for _, rdn := range name.children {
			for _, atv := range rdn.children {
				atvs[atv] = true
			}
		}
	}
	for _, t := range p.tails {
		if !atvs[t] {
			return nil, 0
		}
	}
	return root, end
}

func fingerprint(der []byte) (*Result, error) {
	var p parser
	p.nodes = make([]tlv, 0, 64) // a typical certificate has 60-110 elements
	root, end, err := p.parse(der, 0, 0)
	if err != nil {
		// Second pass only for input that fails the strict parse, so every certificate
		// that parses strictly is processed exactly as before (SPEC 3.1.1). If the
		// lenient pass fails anywhere later, the strict-parse error is reported.
		if root, end = parseNameTails(der); root == nil {
			return nil, derErr(err)
		}
		res, ferr := fingerprintTree(&p, der, root, end, map[string]bool{"atvtrail": true})
		if ferr != nil {
			return nil, derErr(err)
		}
		return res, nil
	}
	return fingerprintTree(&p, der, root, end, map[string]bool{})
}

// fingerprintTree computes the segments from a parsed certificate. p is a strict
// parser (extension values are always parsed strictly).
func fingerprintTree(p *parser, der []byte, root *tlv, end int, flags map[string]bool) (*Result, error) {
	if end != len(der) {
		flags["trail"] = true
	}
	if len(root.children) < 2 {
		return nil, perr("list index out of range")
	}
	tbs, sigAlgOuter := root.children[0], root.children[1]
	f := tbs.children
	if len(f) == 0 {
		return nil, perr("list index out of range")
	}

	// version
	version := "1"
	idx := 0
	if isContext(f[0], 0) {
		vint, err := mustChild(f[0], 0)
		if err != nil {
			return nil, err
		}
		version = "x"
		if len(vint.content) <= 8 {
			version = new(big.Int).Add(unsignedInt(vint.content), big.NewInt(1)).String()
		}
		if version == "1" {
			flags["v1x"] = true
		}
		idx = 1
	}
	if len(f) < idx+6 {
		return nil, perr("list index out of range")
	}
	serialT := f[idx]
	walk(root, flags, serialT)
	sigAlgTBS, issuer, validity, subject, spki := f[idx+1], f[idx+2], f[idx+3], f[idx+4], f[idx+5]
	rest := f[idx+6:]

	if string(sigAlgTBS.raw) != string(sigAlgOuter.raw) {
		flags["sigmm"] = true
	}

	type ext struct {
		oid      string
		critical bool
		val      *tlv
	}
	var exts []ext
	for _, r := range rest {
		if isContext(r, 1) || isContext(r, 2) {
			flags["uid"] = true
		} else if isContext(r, 3) {
			seq, err := mustChild(r, 0)
			if err != nil {
				return nil, err
			}
			if len(seq.children) == 0 {
				flags["extempty"] = true
			}
			for _, e := range seq.children {
				c0, err := mustChild(e, 0)
				if err != nil {
					return nil, err
				}
				oid := decodeOID(c0.content)
				critical := false
				if len(e.children) == 3 {
					critical = string(e.children[1].content) != "\x00"
					if !critical {
						flags["critF"] = true
					}
				}
				octet := e.children[len(e.children)-1]
				val, _, err := p.parse(octet.content, 0, 0)
				if err != nil {
					val = nil
					flags["extbad"] = true
				} else {
					walk(val, flags, nil)
				}
				exts = append(exts, ext{oid, critical, val})
			}
		}
	}
	extByOID := map[string]ext{}
	for _, e := range exts {
		if _, ok := extByOID[e.oid]; !ok {
			extByOID[e.oid] = e
		}
	}
	if len(extByOID) != len(exts) {
		flags["dupext"] = true
	}
	extVal := func(oid string) *tlv {
		if e, ok := extByOID[oid]; ok {
			return e.val
		}
		return nil
	}

	// ---- names ----
	var choices []string
	nameInfo := func(name *tlv) ([]string, error) {
		var groups []string
		for _, rdn := range name.children {
			var oids []string
			for _, atv := range rdn.children {
				a0, err := mustChild(atv, 0)
				if err != nil {
					return nil, err
				}
				oid := decodeOID(a0.content)
				oids = append(oids, oid)
				v, err := mustChild(atv, 1)
				if err != nil {
					return nil, err
				}
				tag := v.first
				if want, ok := fixedStringAttrs[oid]; ok {
					if tag != want {
						flags["strspec"] = true
					}
					continue
				}
				if code, ok := stringTags[tag]; ok {
					if text, ok := decodeString(v.content, tag); ok && printable(text) {
						choices = append(choices, code)
					}
				} else {
					choices = append(choices, "X")
				}
			}
			groups = append(groups, strings.Join(oids, "+"))
		}
		return groups, nil
	}
	iGroups, err := nameInfo(issuer)
	if err != nil {
		return nil, err
	}
	sGroups, err := nameInfo(subject)
	if err != nil {
		return nil, err
	}
	strPolicy := joinSortedSet(choices, ",")
	if strPolicy == "" {
		strPolicy = "-"
	}

	sameName := string(issuer.raw) == string(subject.raw)
	rel := "df"
	switch {
	case sameName:
		rel = "eq"
	case len(issuer.children) == 0:
		rel = "ie"
	case len(subject.children) == 0:
		rel = "se"
	}

	// ---- validity ----
	v0, err := mustChild(validity, 0)
	if err != nil {
		return nil, err
	}
	v1, err := mustChild(validity, 1)
	if err != nil {
		return nil, err
	}
	nb, nbKind, nbStd, nbOK := parseTime(v0)
	na, naKind, naStd, naOK := parseTime(v1)
	if !(nbStd && naStd) {
		flags["tfmt"] = true
	}
	for _, x := range []struct {
		c  civil
		k  byte
		ok bool
	}{{nb, nbKind, nbOK}, {na, naKind, naOK}} {
		if x.ok && x.k == 'G' && x.c.year < 2050 {
			flags["gt2050"] = true
		}
		if x.ok && x.k == 'U' && x.c.year >= 2050 {
			flags["ut2050"] = true
		}
	}
	if nbOK && naOK && na.unix() < nb.unix() {
		flags["negval"] = true
	}
	length, kind, construction, spanInfo := "?", "?", "?", "?"
	if nbOK && naOK {
		length, kind = spanLength(nb, na)
		spanInfo = spanText(nb, na)
		dur := na.unix() - nb.unix()
		align := "any"
		if nb.hour == 0 && nb.min == 0 && nb.sec == 0 {
			align = "mid"
		}
		cons := ""
		switch {
		case strings.HasPrefix(kind, "end"):
			cons = "end"
		case dur < 0:
			cons = "neg"
		default:
			for _, o := range []struct {
				off  int64
				code string
			}{{0, "x"}, {1, "m1"}} {
				t := dur + o.off
				if r := t % 86400; t >= 82800 && (r == 0 || r == 3600 || r == 82800) {
					cons = "day." + o.code
					break
				}
				if t%3600 == 0 {
					cons = "hr." + o.code
					break
				}
				if t%60 == 0 && t < 2*86400 {
					cons = "min." + o.code
					break
				}
			}
			if cons == "" {
				cons = "oth"
			}
		}
		construction = cons + "." + align
	}

	// ---- serial (magnitude classes; sign and padding go to info) ----
	sc := serialT.content
	sval := signedInt(sc)
	serNeg := sval.Sign() < 0
	serPad := len(sc) > 1 && ((sc[0] == 0x00 && sc[1] < 0x80) || (sc[0] == 0xFF && sc[1] >= 0x80))
	var serInfoParts []string
	if serNeg {
		serInfoParts = append(serInfoParts, "neg")
	}
	if serPad {
		serInfoParts = append(serInfoParts, "pad")
	}
	sval.Abs(sval)
	ser := ""
	// Merkle Tree Certificates: serial = (log number << 48) | index; own class, the
	// log number and index go to the unhashed info. A log number over 8 bytes is
	// rendered as "x" (decimal rendering of a huge serial costs quadratic time).
	isMTC := false
	if so, err := mustChild(sigAlgOuter, 0); err == nil && decodeOID(so.content) == oidMTC {
		isMTC = true
	}
	mtcInfo := ""
	if isMTC {
		ser = "mtc"
		idx := new(big.Int).And(sval, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 48), big.NewInt(1)))
		logNum, logStr := new(big.Int).Rsh(sval, 48), "x"
		if logNum.BitLen() <= 64 {
			logStr = logNum.String()
		}
		mtcInfo = logStr + "/" + idx.String()
	} else if sval.Sign() == 0 {
		ser = "z"
	} else {
		bl := sval.BitLen()
		if nbOK && bl >= 28 && bl <= 64 {
			ts := big.NewInt(nb.unix())
			for _, scale := range []int64{1, 1000, 1_000_000_000} {
				sc := big.NewInt(scale)
				diff := new(big.Int).Sub(sval, new(big.Int).Mul(ts, sc))
				lim := new(big.Int).Mul(big.NewInt(2*86400), sc)
				if diff.Abs(diff).Cmp(lim) <= 0 {
					ser = "t"
					break
				}
			}
		}
		if ser == "" {
			if bl <= 32 {
				ser = "s"
			} else {
				ser = "r" + strconv.Itoa((bl+31)/32*4)
			}
		}
	}

	// ---- KEY ----
	pkAlg, err := mustChild(spki, 0)
	if err != nil {
		return nil, err
	}
	pk0, err := mustChild(pkAlg, 0)
	if err != nil {
		return nil, err
	}
	pkOID := decodeOID(pk0.content)
	pkBS, err := mustChild(spki, 1)
	if err != nil {
		return nil, err
	}
	pkBits := bitStringBody(pkBS)
	pkDetail := keyDetail(pkAlg, pkBits)
	so0, err := mustChild(sigAlgOuter, 0)
	if err != nil {
		return nil, err
	}
	sigOID := decodeOID(so0.content)

	issuance := "i"
	if sameName {
		if len(root.children) < 3 {
			return nil, perr("list index out of range")
		}
		ok, err := selfSigned(spki, tbs, sigAlgOuter, root.children[2])
		switch {
		case err == errUnverifiable:
			issuance = "u"
		case err == errMalformed:
			return nil, perr(err.Error())
		case err != nil:
			return nil, perr(err.Error())
		case ok:
			issuance = "s"
		default:
			issuance = "n"
		}
	}

	// ---- key identifiers ----
	skiCode, akiCode := "-", "-"
	if v := extVal(oidSKI); v != nil {
		kid := string(v.content)
		s1 := sha1.Sum(pkBits)
		m2 := append([]byte{(s1[12] & 0x0F) | 0x40}, s1[13:]...)
		s256 := sha256.Sum256(pkBits)
		s384 := sha512.Sum384(pkBits)
		s512 := sha512.Sum512(pkBits)
		spki1 := sha1.Sum(spki.raw)
		spki256 := sha256.Sum256(spki.raw)
		cands := []struct{ name, v string }{
			{"m1", string(s1[:])}, {"m2", string(m2)}, {"s256", string(s256[:20])},
			{"s384", string(s384[:20])}, {"s512", string(s512[:20])},
			{"spki1", string(spki1[:])}, {"spki256", string(spki256[:20])},
		}
		skiCode = "o" + strconv.Itoa(len(kid))
		for _, c := range cands {
			if c.v == kid {
				skiCode = c.name
				break
			}
		}
	}
	if v := extVal(oidAKI); v != nil {
		var sb strings.Builder
		for _, c := range v.children {
			if c.cls == 2 {
				switch c.tagnum {
				case 0:
					sb.WriteByte('k')
				case 1:
					sb.WriteByte('i')
				case 2:
					sb.WriteByte('s')
				default:
					sb.WriteByte('?')
				}
			}
		}
		akiCode = sb.String()
		if akiCode == "" {
			akiCode = "e"
		}
	}

	// ---- AUDIENCE ----
	var aud []string
	if v := extVal(oidEKU); v != nil {
		ekus := make([]string, 0, len(v.children))
		for _, c := range v.children {
			ekus = append(ekus, decodeOID(c.content))
		}
		sort.Strings(ekus)
		aud = append(aud, "eku="+strings.Join(ekus, ","))
	}
	if v := extVal(oidKU); v != nil {
		var bits []byte
		if len(v.content) > 0 {
			bits = v.content[1:]
		}
		mask := 0
		lim := len(bits) * 8
		if lim > 9 {
			lim = 9
		}
		for i := 0; i < lim; i++ {
			if bits[i/8]&(0x80>>(i%8)) != 0 {
				mask |= 1 << i
			}
		}
		aud = append(aud, fmt.Sprintf("ku=%03x", mask))
	}
	if v := extVal(oidBC); v != nil {
		ca := false
		pl := ""
		for _, c := range v.children {
			if isUniversal(c, 1) {
				ca = string(c.content) != "\x00"
			} else if isUniversal(c, 2) {
				pl = smallUint(c.content)
			}
		}
		s := "e"
		if ca {
			s = "c"
			s += pl
		}
		aud = append(aud, "bc="+s)
	}
	var pol []string
	if v := extVal(oidPolicies); v != nil {
		for _, pi := range v.children {
			c0, err := mustChild(pi, 0)
			if err != nil {
				return nil, err
			}
			pol = append(pol, decodeOID(c0.content))
		}
	}
	if v := extVal(oidMSTmplInfo); v != nil && len(v.children) > 0 {
		pol = append(pol, "tmpl:"+decodeOID(v.children[0].content))
	}
	if v := extVal(oidMSTmplName); v != nil {
		name := "?"
		if v.first == 0x1E {
			if s, ok := decodeUTF16BE(v.content); ok {
				name = s
			}
		} else if utf8.Valid(v.content) {
			name = string(v.content)
		}
		pol = append(pol, "tmplname:"+name)
	}
	if len(pol) > 0 {
		sort.Strings(pol)
		aud = append(aud, "pol="+strings.Join(pol, ","))
	}
	var ptr []string
	for _, x := range []struct{ oid, label string }{{oidAIA, "aia"}, {oidCDP, "cdp"}} {
		if v := extVal(x.oid); v != nil {
			var uris [][]byte
			findURIs(v, &uris)
			set := map[string]bool{}
			for _, u := range uris {
				set[uriScheme(u)] = true
			}
			schemes := make([]string, 0, len(set))
			for k := range set {
				schemes = append(schemes, k)
			}
			sort.Strings(schemes)
			if len(schemes) == 0 {
				schemes = []string{"-"}
			}
			ptr = append(ptr, x.label+":"+strings.Join(schemes, "+"))
		}
	}
	if len(ptr) > 0 {
		aud = append(aud, "ptr="+strings.Join(ptr, ","))
	}
	sort.Strings(aud)
	audiencePre := strings.Join(aud, ";")

	// ---- assemble pre-hash strings ----
	var el []string
	for _, e := range exts {
		if extListExcluded[e.oid] {
			continue
		}
		if e.critical {
			el = append(el, e.oid+"!")
		} else {
			el = append(el, e.oid)
		}
	}
	var devs []string
	algs := []*tlv{sigAlgTBS, pkAlg, sigAlgOuter}
	if v := extVal(oidAltSPKI); v != nil && len(v.children) > 0 && len(v.children[0].children) > 0 {
		algs = append(algs, v.children[0])
	}
	if v := extVal(oidAltSigAlg); v != nil && len(v.children) > 0 {
		algs = append(algs, v)
	}
	for _, a := range algs {
		d, err := algDeviation(a)
		if err != nil {
			return nil, err
		}
		if d != "" {
			devs = append(devs, d)
		}
	}
	algp := strings.Join(devs, ",")
	if algp == "" {
		algp = "std"
	}
	flagList := make([]string, 0, len(flags))
	for k := range flags {
		flagList = append(flagList, k)
	}
	sort.Strings(flagList)
	enc := strings.Join(flagList, ",")
	if enc == "" {
		enc = "-"
	}

	keyPre := "iss=" + issuance + ";pk=" + pkOID + pkDetail + ";sig=" + sigOID
	altPK, altSig := extVal(oidAltSPKI), extVal(oidAltSigAlg)
	if altPK != nil || altSig != nil {
		keyPre += ";alt=" + altKeyPart(altPK) + "/" + altSigPart(altSig)
	}
	spanPre := "len=" + length + ";kind=" + kind
	makerPre := "ver=" + version + ";enc=" + enc + ";algp=" + algp + ";rel=" + rel +
		";ext=" + strings.Join(el, ",") + ";ser=" + ser + ";kid=" + skiCode + "/" + akiCode +
		";vc=" + construction + ";mtc="
	if isMTC {
		makerPre += "log"
	}
	namesPre := ""
	if len(iGroups) > 0 || len(sGroups) > 0 {
		namesPre = "i=" + strings.Join(iGroups, ",") + "|s=" + strings.Join(sGroups, ",")
	}
	info := "str=" + strPolicy + ";span=" + spanInfo
	if len(serInfoParts) > 0 {
		info += ";ser=" + strings.Join(serInfoParts, ",")
	}
	if isMTC {
		info += ";mtc=" + mtcInfo
	}
	return &Result{
		GFMX: strings.Join([]string{h8(keyPre), h8(spanPre), h8(makerPre), h8(audiencePre), h8(namesPre)}, ":"),
		Raw:  Raw{keyPre, spanPre, makerPre, audiencePre, namesPre},
		Info: info,
	}, nil
}

// keyDetail: RSA and RSA-PSS modulus size, EC named curve, DSA p size ("/-" inherited).
func keyDetail(alg *tlv, bits []byte) string {
	if len(alg.children) == 0 {
		return ""
	}
	oid := decodeOID(alg.children[0].content)
	switch {
	case oid == oidRSA || oid == oidRSAPSS:
		if rsa, _, err := parseTLV(bits, 0, 0); err == nil && len(rsa.children) > 0 {
			return "/" + strconv.Itoa(unsignedInt(rsa.children[0].content).BitLen())
		}
		return "/?"
	case oid == oidEC && len(alg.children) > 1 && isUniversal(alg.children[1], 6):
		return "/" + decodeOID(alg.children[1].content)
	case oid == oidDSA:
		if len(alg.children) < 2 || len(alg.children[1].children) == 0 ||
			!isUniversal(alg.children[1].children[0], 2) {
			return "/-"
		}
		return "/" + strconv.Itoa(unsignedInt(alg.children[1].children[0].content).BitLen())
	}
	return ""
}

// altKeyPart and altSigPart render the hybrid (alternative) key and signature algorithm:
// "-" when absent, "?" when malformed.
func altKeyPart(v *tlv) string {
	if v == nil {
		return "-"
	}
	if len(v.children) < 2 || len(v.children[0].children) == 0 {
		return "?"
	}
	alg := v.children[0]
	return decodeOID(alg.children[0].content) + keyDetail(alg, bitStringBody(v.children[1]))
}

func altSigPart(v *tlv) string {
	if v == nil {
		return "-"
	}
	if len(v.children) == 0 {
		return "?"
	}
	return decodeOID(v.children[0].content)
}

// walk collects DER rule violations. The serial is left out of the INTEGER check:
// whether a padded serial is minimal depends on its random value.
func walk(t *tlv, flags map[string]bool, serial *tlv) {
	if t.nonminimalLen {
		flags["len"] = true
	}
	if isUniversal(t, 1) && (len(t.content) != 1 || (t.content[0] != 0x00 && t.content[0] != 0xFF)) {
		flags["bool"] = true
	}
	if isUniversal(t, 2) && len(t.content) > 1 && t != serial {
		c0, c1 := t.content[0], t.content[1]
		if (c0 == 0x00 && c1 < 0x80) || (c0 == 0xFF && c1 >= 0x80) {
			flags["int"] = true
		}
	}
	for _, c := range t.children {
		walk(c, flags, serial)
	}
}

func algParamsCode(alg *tlv) string {
	if len(alg.children) < 2 {
		return "a"
	}
	p := alg.children[1]
	switch {
	case isUniversal(p, 5):
		return "n"
	case isUniversal(p, 6):
		return "o"
	case isUniversal(p, 16):
		return "s"
	}
	return "x"
}

func expectedParams(oid string) string {
	switch {
	case oid == "1.2.840.113549.1.1.10":
		return "s"
	case strings.HasPrefix(oid, "1.2.840.113549.1.1."):
		return "n"
	case oid == oidEC:
		return "o"
	case strings.HasPrefix(oid, "1.2.840.10045.4."):
		return "a"
	case oid == "1.3.101.112" || oid == "1.3.101.113":
		return "a"
	case strings.HasPrefix(oid, "2.16.840.1.101.3.4.3."):
		return "a"
	case strings.HasPrefix(oid, "2.16.840.1.101.3.4.4."): // ML-KEM
		return "a"
	case oid == oidMTC:
		return "a"
	}
	return ""
}

func algDeviation(alg *tlv) (string, error) {
	a0, err := mustChild(alg, 0)
	if err != nil {
		return "", err
	}
	got := algParamsCode(alg)
	want := expectedParams(decodeOID(a0.content))
	if want == "" {
		return "?" + got, nil
	}
	if got == want {
		return "", nil
	}
	return want + ">" + got, nil
}

func findURIs(t *tlv, out *[][]byte) {
	if isContext(t, 6) && !t.constructed {
		*out = append(*out, t.content)
	}
	for _, c := range t.children {
		findURIs(c, out)
	}
}

func isAlpha(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

func uriScheme(u []byte) string {
	if len(u) == 0 || !isAlpha(u[0]) {
		return "?"
	}
	for i := 1; i < len(u); i++ {
		c := u[i]
		if c == ':' {
			return strings.ToLower(string(u[:i]))
		}
		if !(isAlpha(c) || (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-') {
			return "?"
		}
	}
	return "?"
}

func joinSortedSet(xs []string, sep string) string {
	set := map[string]bool{}
	for _, x := range xs {
		set[x] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, sep)
}

// ---- string decoding (as Python's strict codecs) ----

func decodeUTF16BE(b []byte) (string, bool) {
	if len(b)%2 != 0 {
		return "", false
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	for i := 0; i < len(u); i++ { // reject unpaired surrogates
		switch {
		case u[i] >= 0xD800 && u[i] < 0xDC00:
			if i+1 >= len(u) || u[i+1] < 0xDC00 || u[i+1] >= 0xE000 {
				return "", false
			}
			i++
		case u[i] >= 0xDC00 && u[i] < 0xE000:
			return "", false
		}
	}
	return string(utf16.Decode(u)), true
}

func decodeUTF32BE(b []byte) (string, bool) {
	if len(b)%4 != 0 {
		return "", false
	}
	var sb strings.Builder
	for i := 0; i < len(b); i += 4 {
		r := uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
		if r > 0x10FFFF || (r >= 0xD800 && r < 0xE000) {
			return "", false
		}
		sb.WriteRune(rune(r))
	}
	return sb.String(), true
}

func decodeString(b []byte, tag byte) (string, bool) {
	switch tag {
	case 0x1E:
		return decodeUTF16BE(b)
	case 0x1C:
		return decodeUTF32BE(b)
	}
	if !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

// printable mirrors re.match(r"^[A-Za-z0-9 '()+,\-./:=?]*$", text), including `$`
// matching just before one final newline.
func printable(s string) bool {
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(isAlpha(c) || (c >= '0' && c <= '9') || strings.IndexByte(" '()+,-./:=?", c) >= 0) {
			return false
		}
	}
	return true
}
