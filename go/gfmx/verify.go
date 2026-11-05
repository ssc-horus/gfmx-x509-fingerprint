package gfmx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"errors"
	"math/big"
)

// Self-signature check. Every algorithm is verified with plain integer math so the
// issuance class never depends on a crypto library's algorithm policy. An algorithm,
// digest or curve that cannot be checked gives "u".

var errUnverifiable = errors.New("unverifiable")

// errInvalid stands for the reference's caught exceptions (DERError, IndexError,
// ValueError, ZeroDivisionError): the signature counts as not verifying.
var errInvalid = errors.New("invalid")

// errMalformed: the certificate itself is malformed where the reference raises
// outside its try block, so the whole certificate fails to parse.
var errMalformed = errors.New("malformed signature algorithm or public key")

const (
	dgPrefix  = "2.16.840.1.101.3.4.2."
	rsaArc    = "1.2.840.113549.1.1."
	sigArc    = "2.16.840.1.101.3.4.3."
	oidDSA    = "1.2.840.10040.4.1"
	oidRSAPSS = rsaArc + "10"
)

var digestOIDs = map[string]string{
	"1.2.840.113549.2.5": "md5", "1.3.14.3.2.26": "sha1",
	dgPrefix + "4": "sha224", dgPrefix + "1": "sha256", dgPrefix + "2": "sha384", dgPrefix + "3": "sha512",
	dgPrefix + "5": "sha512_224", dgPrefix + "6": "sha512_256", dgPrefix + "7": "sha3_224",
	dgPrefix + "8": "sha3_256", dgPrefix + "9": "sha3_384", dgPrefix + "10": "sha3_512",
}

type sigAlg struct{ fam, hash string }

var sigAlgs = map[string]sigAlg{
	rsaArc + "4": {"rsa", "md5"}, rsaArc + "5": {"rsa", "sha1"}, "1.3.14.3.2.29": {"rsa", "sha1"},
	rsaArc + "14": {"rsa", "sha224"}, rsaArc + "11": {"rsa", "sha256"}, rsaArc + "12": {"rsa", "sha384"},
	rsaArc + "13": {"rsa", "sha512"}, rsaArc + "15": {"rsa", "sha512_224"}, rsaArc + "16": {"rsa", "sha512_256"},
	sigArc + "13": {"rsa", "sha3_224"}, sigArc + "14": {"rsa", "sha3_256"},
	sigArc + "15": {"rsa", "sha3_384"}, sigArc + "16": {"rsa", "sha3_512"},
	rsaArc + "10":       {"pss", ""},
	"1.2.840.10040.4.3": {"dsa", "sha1"}, "1.3.14.3.2.27": {"dsa", "sha1"},
	sigArc + "1": {"dsa", "sha224"}, sigArc + "2": {"dsa", "sha256"}, sigArc + "3": {"dsa", "sha384"},
	sigArc + "4": {"dsa", "sha512"}, sigArc + "5": {"dsa", "sha3_224"}, sigArc + "6": {"dsa", "sha3_256"},
	sigArc + "7": {"dsa", "sha3_384"}, sigArc + "8": {"dsa", "sha3_512"},
	"1.2.840.10045.4.1": {"ecdsa", "sha1"}, "1.2.840.10045.4.3.1": {"ecdsa", "sha224"},
	"1.2.840.10045.4.3.2": {"ecdsa", "sha256"}, "1.2.840.10045.4.3.3": {"ecdsa", "sha384"},
	"1.2.840.10045.4.3.4": {"ecdsa", "sha512"}, sigArc + "9": {"ecdsa", "sha3_224"},
	sigArc + "10": {"ecdsa", "sha3_256"}, sigArc + "11": {"ecdsa", "sha3_384"},
	sigArc + "12": {"ecdsa", "sha3_512"},
	"1.3.101.112": {"eddsa", ""}, "1.3.101.113": {"eddsa", ""},
	sigArc + "17": {"mldsa", ""}, sigArc + "18": {"mldsa", ""}, sigArc + "19": {"mldsa", ""},
}

const (
	maxModulusBits = 16384
	maxRSAExpBits  = 64
	maxDSAPBits    = 4096
	maxDSAQBits    = 512
)

func digest(name string, data []byte) ([]byte, error) {
	switch name {
	case "md5":
		h := md5.Sum(data)
		return h[:], nil
	case "sha1":
		h := sha1.Sum(data)
		return h[:], nil
	case "sha224":
		h := sha256.Sum224(data)
		return h[:], nil
	case "sha256":
		h := sha256.Sum256(data)
		return h[:], nil
	case "sha384":
		h := sha512.Sum384(data)
		return h[:], nil
	case "sha512":
		h := sha512.Sum512(data)
		return h[:], nil
	case "sha512_224":
		h := sha512.Sum512_224(data)
		return h[:], nil
	case "sha512_256":
		h := sha512.Sum512_256(data)
		return h[:], nil
	case "sha3_224":
		h := sha3.Sum224(data)
		return h[:], nil
	case "sha3_256":
		h := sha3.Sum256(data)
		return h[:], nil
	case "sha3_384":
		h := sha3.Sum384(data)
		return h[:], nil
	case "sha3_512":
		h := sha3.Sum512(data)
		return h[:], nil
	}
	return nil, errUnverifiable
}

func digestLen(name string) int {
	d, err := digest(name, nil)
	if err != nil {
		return 0
	}
	return len(d)
}

func child(t *tlv, i int) (*tlv, error) {
	if t == nil || i < 0 || i >= len(t.children) {
		return nil, errInvalid
	}
	return t.children[i], nil
}

func bitStringBody(t *tlv) []byte {
	if len(t.content) == 0 {
		return nil
	}
	return t.content[1:]
}

func rsaKey(spki *tlv) (*big.Int, *big.Int, error) {
	bs, err := child(spki, 1)
	if err != nil {
		return nil, nil, err
	}
	key, _, err := parseTLV(bitStringBody(bs), 0, 0)
	if err != nil {
		return nil, nil, errInvalid
	}
	nt, err := child(key, 0)
	if err != nil {
		return nil, nil, err
	}
	et, err := child(key, 1)
	if err != nil {
		return nil, nil, err
	}
	n, e := signedInt(nt.content), signedInt(et.content)
	if n.BitLen() > maxModulusBits || e.BitLen() > maxRSAExpBits {
		return nil, nil, errUnverifiable
	}
	return n, e, nil
}

func i2osp(v *big.Int, k int) ([]byte, bool) {
	if v.Sign() < 0 || v.BitLen() > 8*k {
		return nil, false
	}
	out := make([]byte, k)
	v.FillBytes(out)
	return out, true
}

func verifyRSA(spki *tlv, tbs, sig []byte, h string) (bool, error) {
	n, e, err := rsaKey(spki)
	if err != nil {
		return false, err
	}
	k := (n.BitLen() + 7) / 8
	s := new(big.Int).SetBytes(sig)
	if !(s.Sign() > 0 && s.Cmp(n) < 0) || e.Sign() <= 0 {
		return false, nil
	}
	em, _ := i2osp(new(big.Int).Exp(s, e, n), k)
	if len(em) < 2 || em[0] != 0 || em[1] != 1 {
		return false, nil
	}
	sep := bytes.IndexByte(em[2:], 0)
	if sep >= 0 {
		sep += 2
	}
	if sep < 10 {
		return false, nil
	}
	for _, b := range em[2:sep] {
		if b != 0xFF {
			return false, nil
		}
	}
	t := em[sep+1:]
	// DigestInfo: use the digest the signer actually embedded
	if di, end, err := parseTLV(t, 0, 0); err == nil && end == len(t) && len(di.children) == 2 &&
		isUniversal(di.children[1], 4) {
		if len(di.children[0].children) > 0 {
			if name, ok := digestOIDs[decodeOID(di.children[0].children[0].content)]; ok {
				d, err := digest(name, tbs)
				if err != nil {
					return false, err
				}
				return bytes.Equal(di.children[1].content, d), nil
			}
		}
	}
	if h == "" {
		return false, errUnverifiable
	}
	d, err := digest(h, tbs)
	if err != nil {
		return false, err
	}
	return bytes.Equal(t, d), nil // bare digest without DigestInfo (very old signers)
}

func pssHashes(params *tlv) (string, string, error) {
	h, mgf := "sha1", "sha1"
	if params != nil {
		for _, p := range params.children {
			if p.cls == 2 && p.tagnum == 0 {
				a, err := child(p, 0)
				if err != nil {
					return "", "", err
				}
				o, err := child(a, 0)
				if err != nil {
					return "", "", err
				}
				if v, ok := digestOIDs[decodeOID(o.content)]; ok {
					h = v
				} else {
					h = "?"
				}
			} else if p.cls == 2 && p.tagnum == 1 {
				mgfAlg, err := child(p, 0)
				if err != nil {
					return "", "", err
				}
				if len(mgfAlg.children) < 2 {
					return "", "", errUnverifiable
				}
				o, err := child(mgfAlg.children[1], 0)
				if err != nil {
					return "", "", err
				}
				if v, ok := digestOIDs[decodeOID(o.content)]; ok {
					mgf = v
				} else {
					mgf = "?"
				}
			}
		}
	}
	if h == "?" || mgf == "?" {
		return "", "", errUnverifiable
	}
	return h, mgf, nil
}

func mgf1(seed []byte, length int, h string) ([]byte, error) {
	var out []byte
	for c := uint32(0); len(out) < length; c++ {
		d, err := digest(h, append(append([]byte{}, seed...), byte(c>>24), byte(c>>16), byte(c>>8), byte(c)))
		if err != nil {
			return nil, err
		}
		out = append(out, d...)
	}
	return out[:length], nil
}

func verifyPSS(spki *tlv, tbs, sig []byte, params *tlv) (bool, error) {
	h, mh, err := pssHashes(params)
	if err != nil {
		return false, err
	}
	n, e, err := rsaKey(spki)
	if err != nil {
		return false, err
	}
	s := new(big.Int).SetBytes(sig)
	if !(s.Sign() > 0 && s.Cmp(n) < 0) {
		return false, nil
	}
	emBits := n.BitLen() - 1
	emLen := (emBits + 7) / 8
	m := new(big.Int).Exp(s, e, n) // negative e: modular inverse, as Python's pow
	if m == nil {
		return false, nil
	}
	em, ok := i2osp(m, emLen)
	if !ok {
		return false, nil
	}
	hLen := digestLen(h)
	if len(em) == 0 || em[len(em)-1] != 0xBC || emLen < hLen+2 {
		return false, nil
	}
	masked, hh := em[:emLen-hLen-1], em[emLen-hLen-1:len(em)-1]
	top := uint(8*emLen - emBits)
	if top != 0 {
		if len(masked) == 0 {
			return false, nil
		}
		if masked[0]>>(8-top) != 0 {
			return false, nil
		}
	}
	mask, err := mgf1(hh, len(masked), mh)
	if err != nil {
		return false, err
	}
	db := make([]byte, len(masked))
	for i := range masked {
		db[i] = masked[i] ^ mask[i]
	}
	if top != 0 {
		db[0] &= 0xFF >> top
	}
	i := 0
	for i < len(db) && db[i] == 0 {
		i++
	}
	if i == len(db) || db[i] != 1 {
		return false, nil
	}
	salt := db[i+1:]
	mh2, err := digest(h, tbs)
	if err != nil {
		return false, err
	}
	d, err := digest(h, append(append(make([]byte, 8), mh2...), salt...))
	if err != nil {
		return false, err
	}
	return bytes.Equal(d, hh), nil
}

func verifyDSA(spki *tlv, tbs, sig []byte, h string) (bool, error) {
	alg, err := child(spki, 0)
	if err != nil {
		return false, err
	}
	if len(alg.children) < 2 || len(alg.children[1].children) == 0 {
		return false, errUnverifiable // parameters inherited from the issuer
	}
	pc := alg.children[1].children
	if len(pc) < 3 {
		return false, errInvalid
	}
	p, q, g := signedInt(pc[0].content), signedInt(pc[1].content), signedInt(pc[2].content)
	if p.BitLen() > maxDSAPBits || q.BitLen() > maxDSAQBits || g.BitLen() > p.BitLen() {
		return false, errUnverifiable
	}
	if p.Cmp(big.NewInt(2)) < 0 || q.Cmp(big.NewInt(2)) < 0 {
		return false, nil
	}
	bs, err := child(spki, 1)
	if err != nil {
		return false, err
	}
	yt, _, err := parseTLV(bitStringBody(bs), 0, 0)
	if err != nil {
		return false, errInvalid
	}
	y := signedInt(yt.content)
	if y.BitLen() > p.BitLen() { // g and y longer than p cost time, never verify more
		return false, errUnverifiable
	}
	rs, _, err := parseTLV(sig, 0, 0)
	if err != nil {
		return false, errInvalid
	}
	if len(rs.children) < 2 {
		return false, errInvalid
	}
	r, s := signedInt(rs.children[0].content), signedInt(rs.children[1].content)
	if !(r.Sign() > 0 && r.Cmp(q) < 0 && s.Sign() > 0 && s.Cmp(q) < 0) {
		return false, nil
	}
	d, err := digest(h, tbs)
	if err != nil {
		return false, err
	}
	qBytes := (q.BitLen() + 7) / 8
	if len(d) > qBytes {
		d = d[:qBytes]
	}
	z := new(big.Int).SetBytes(d)
	if digestLen(h)*8 > q.BitLen() {
		if sh := qBytes*8 - q.BitLen(); sh > 0 {
			z.Rsh(z, uint(sh))
		}
	}
	w := new(big.Int).ModInverse(s, q)
	if w == nil {
		return false, errInvalid
	}
	u1 := new(big.Int).Mul(z, w)
	u1.Mod(u1, q)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, q)
	gm := new(big.Int).Mod(g, p)
	ym := new(big.Int).Mod(y, p)
	v := new(big.Int).Exp(gm, u1, p)
	v.Mul(v, new(big.Int).Exp(ym, u2, p))
	v.Mod(v, p)
	v.Mod(v, q)
	return v.Cmp(r) == 0, nil
}

// ---- ECDSA ----

func sqrtMod(v, p *big.Int) *big.Int {
	v = new(big.Int).Mod(v, p)
	if v.Sign() == 0 {
		return new(big.Int)
	}
	r := new(big.Int).ModSqrt(v, p)
	return r // nil when v is not a square
}

func ecPoint(data []byte, c *ecCurve) (*big.Int, *big.Int) {
	flen := (c.p.BitLen() + 7) / 8
	var x, y *big.Int
	rhs := func(x *big.Int) *big.Int {
		v := new(big.Int).Mul(x, x)
		v.Mul(v, x)
		v.Add(v, new(big.Int).Mul(c.a, x))
		v.Add(v, c.b)
		return v.Mod(v, c.p)
	}
	switch {
	case len(data) == 1+2*flen && data[0] == 4:
		x = new(big.Int).SetBytes(data[1 : 1+flen])
		y = new(big.Int).SetBytes(data[1+flen:])
	case len(data) == 1+flen && (data[0] == 2 || data[0] == 3):
		x = new(big.Int).SetBytes(data[1:])
		if x.Cmp(c.p) >= 0 {
			return nil, nil
		}
		y = sqrtMod(rhs(x), c.p)
		if y == nil {
			return nil, nil
		}
		if y.Bit(0) != uint(data[0]&1) {
			y.Sub(c.p, y)
			y.Mod(y, c.p)
		}
	default:
		return nil, nil
	}
	if x.Cmp(c.p) >= 0 || y.Cmp(c.p) >= 0 {
		return nil, nil
	}
	yy := new(big.Int).Mul(y, y)
	yy.Mod(yy, c.p)
	if yy.Cmp(rhs(x)) != 0 {
		return nil, nil
	}
	return x, y
}

func derSigPair(sig []byte) (*big.Int, *big.Int, bool) {
	t, end, err := parseTLV(sig, 0, 0)
	if err != nil || end != len(sig) || !isUniversal(t, 16) || len(t.children) != 2 || t.nonminimalLen {
		return nil, nil, false
	}
	var out [2]*big.Int
	for i, c := range t.children {
		b := c.content
		if !isUniversal(c, 2) || c.nonminimalLen || len(b) == 0 || b[0]&0x80 != 0 ||
			(len(b) > 1 && b[0] == 0 && b[1] < 0x80) {
			return nil, nil, false
		}
		out[i] = new(big.Int).SetBytes(b)
	}
	return out[0], out[1], true
}

// jac is a point in Jacobian coordinates (x = X/Z^2, y = Y/Z^3); Z == 0 is infinity.
// The group law is the same as the reference's affine arithmetic, without an inversion
// per step.
type jac struct{ x, y, z *big.Int }

func (c *ecCurve) mod(v *big.Int) *big.Int { return v.Mod(v, c.p) }

func (c *ecCurve) double(P jac) jac {
	if P.z.Sign() == 0 || P.y.Sign() == 0 {
		return jac{big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	}
	xx := c.mod(new(big.Int).Mul(P.x, P.x))
	yy := c.mod(new(big.Int).Mul(P.y, P.y))
	yyyy := c.mod(new(big.Int).Mul(yy, yy))
	zz := c.mod(new(big.Int).Mul(P.z, P.z))
	s := new(big.Int).Add(P.x, yy)
	s.Mul(s, s)
	s.Sub(s, xx)
	s.Sub(s, yyyy)
	s.Lsh(s, 1)
	c.mod(s)
	m := new(big.Int).Mul(xx, big.NewInt(3))
	m.Add(m, new(big.Int).Mul(c.a, new(big.Int).Mul(zz, zz)))
	c.mod(m)
	x3 := new(big.Int).Mul(m, m)
	x3.Sub(x3, new(big.Int).Lsh(s, 1))
	c.mod(x3)
	y3 := new(big.Int).Sub(s, x3)
	y3.Mul(y3, m)
	y3.Sub(y3, new(big.Int).Lsh(yyyy, 3))
	c.mod(y3)
	z3 := new(big.Int).Add(P.y, P.z)
	z3.Mul(z3, z3)
	z3.Sub(z3, yy)
	z3.Sub(z3, zz)
	c.mod(z3)
	return jac{x3, y3, z3}
}

func (c *ecCurve) add(P, Q jac) jac {
	if P.z.Sign() == 0 {
		return Q
	}
	if Q.z.Sign() == 0 {
		return P
	}
	z1z1 := c.mod(new(big.Int).Mul(P.z, P.z))
	z2z2 := c.mod(new(big.Int).Mul(Q.z, Q.z))
	u1 := c.mod(new(big.Int).Mul(P.x, z2z2))
	u2 := c.mod(new(big.Int).Mul(Q.x, z1z1))
	s1 := c.mod(new(big.Int).Mul(P.y, c.mod(new(big.Int).Mul(Q.z, z2z2))))
	s2 := c.mod(new(big.Int).Mul(Q.y, c.mod(new(big.Int).Mul(P.z, z1z1))))
	h := c.mod(new(big.Int).Sub(u2, u1))
	r := c.mod(new(big.Int).Sub(s2, s1))
	if h.Sign() == 0 {
		if r.Sign() == 0 {
			return c.double(P)
		}
		return jac{big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	c.mod(i)
	j := c.mod(new(big.Int).Mul(h, i))
	r.Lsh(r, 1)
	v := c.mod(new(big.Int).Mul(u1, i))
	x3 := new(big.Int).Mul(r, r)
	x3.Sub(x3, j)
	x3.Sub(x3, new(big.Int).Lsh(v, 1))
	c.mod(x3)
	y3 := new(big.Int).Sub(v, x3)
	y3.Mul(y3, r)
	y3.Sub(y3, new(big.Int).Lsh(new(big.Int).Mul(s1, j), 1))
	c.mod(y3)
	z3 := new(big.Int).Add(P.z, Q.z)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	c.mod(z3)
	return jac{x3, y3, z3}
}

// mul2 returns the affine x of k1*P + k2*Q (Shamir's trick), or nil at infinity.
func (c *ecCurve) mul2(k1 *big.Int, px, py *big.Int, k2 *big.Int, qx, qy *big.Int) *big.Int {
	P := jac{px, py, big.NewInt(1)}
	Q := jac{qx, qy, big.NewInt(1)}
	PQ := c.add(P, Q)
	R := jac{big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	bl := k1.BitLen()
	if k2.BitLen() > bl {
		bl = k2.BitLen()
	}
	for i := bl - 1; i >= 0; i-- {
		R = c.double(R)
		b1, b2 := k1.Bit(i), k2.Bit(i)
		switch {
		case b1 == 1 && b2 == 1:
			R = c.add(R, PQ)
		case b1 == 1:
			R = c.add(R, P)
		case b2 == 1:
			R = c.add(R, Q)
		}
	}
	if R.z.Sign() == 0 {
		return nil
	}
	zi := new(big.Int).ModInverse(R.z, c.p)
	zi.Mul(zi, zi)
	x := new(big.Int).Mul(R.x, zi)
	return x.Mod(x, c.p)
}

var stdCurves = map[string]elliptic.Curve{
	"1.3.132.0.33": elliptic.P224(), "1.2.840.10045.3.1.7": elliptic.P256(),
	"1.3.132.0.34": elliptic.P384(), "1.3.132.0.35": elliptic.P521(),
}

const oidEC = "1.2.840.10045.2.1"

func verifyECDSA(spki *tlv, tbs, sig []byte, h string) (bool, error) {
	alg, err := child(spki, 0)
	if err != nil {
		return false, err
	}
	a0, err := child(alg, 0)
	if err != nil {
		return false, err
	}
	if decodeOID(a0.content) != oidEC {
		return false, nil
	}
	if len(alg.children) < 2 || !isUniversal(alg.children[1], 6) {
		return false, errUnverifiable // explicit or inherited curve parameters
	}
	coid := decodeOID(alg.children[1].content)
	c, ok := ecCurves[coid]
	if !ok {
		return false, errUnverifiable
	}
	bs, err := child(spki, 1)
	if err != nil {
		return false, err
	}
	qx, qy := ecPoint(bitStringBody(bs), c)
	r, s, ok := derSigPair(sig)
	if qx == nil || !ok {
		return false, nil
	}
	if !(r.Sign() > 0 && r.Cmp(c.n) < 0 && s.Sign() > 0 && s.Cmp(c.n) < 0) {
		return false, nil
	}
	d, err := digest(h, tbs)
	if err != nil {
		return false, err
	}
	if std, ok := stdCurves[coid]; ok { // same math, constant-time and much faster
		return ecdsa.Verify(&ecdsa.PublicKey{Curve: std, X: qx, Y: qy}, d, r, s), nil
	}
	e := new(big.Int).SetBytes(d)
	if sh := 8*len(d) - c.n.BitLen(); sh > 0 {
		e.Rsh(e, uint(sh))
	}
	w := new(big.Int).ModInverse(s, c.n)
	u1 := new(big.Int).Mul(e, w)
	u1.Mod(u1, c.n)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, c.n)
	x := c.mul2(u1, c.gx, c.gy, u2, qx, qy)
	if x == nil {
		return false, nil
	}
	return x.Mod(x, c.n).Cmp(r) == 0, nil
}

// ---- EdDSA (RFC 8032) ----

type edCurve struct {
	p, a, d, L, bx, by *big.Int
	n                  int // encoded length
}

func decInt(s string) *big.Int { v, _ := new(big.Int).SetString(s, 10); return v }

var edCurves = func() map[string]*edCurve {
	p25519 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	d25519 := new(big.Int).ModInverse(big.NewInt(121666), p25519)
	d25519.Mul(d25519, big.NewInt(-121665))
	d25519.Mod(d25519, p25519)
	l25519 := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252), decInt("27742317777372353535851937790883648493"))
	p448 := new(big.Int).Lsh(big.NewInt(1), 448)
	p448.Sub(p448, new(big.Int).Lsh(big.NewInt(1), 224))
	p448.Sub(p448, big.NewInt(1))
	l448 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 446),
		decInt("13818066809895115352007386748515426880336692474882178609894547503885"))
	return map[string]*edCurve{
		"1.3.101.112": {p25519, big.NewInt(-1), d25519, l25519,
			hexInt("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"),
			hexInt("6666666666666666666666666666666666666666666666666666666666666658"), 32},
		"1.3.101.113": {p448, big.NewInt(1), new(big.Int).Sub(p448, big.NewInt(39081)), l448,
			decInt("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710"),
			decInt("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660"), 57},
	}
}()

// edPoint is projective (x = X/Z, y = Y/Z). The unified addition law is complete on
// both curves (d is not a square), so it gives the reference's affine results.
type edPoint struct{ x, y, z *big.Int }

func edAdd(P, Q edPoint, c *edCurve) edPoint {
	p := c.p
	A := new(big.Int).Mul(P.z, Q.z)
	A.Mod(A, p)
	B := new(big.Int).Mul(A, A)
	B.Mod(B, p)
	C := new(big.Int).Mul(P.x, Q.x)
	C.Mod(C, p)
	D := new(big.Int).Mul(P.y, Q.y)
	D.Mod(D, p)
	E := new(big.Int).Mul(c.d, C)
	E.Mul(E, D)
	E.Mod(E, p)
	F := new(big.Int).Sub(B, E)
	G := new(big.Int).Add(B, E)
	x3 := new(big.Int).Add(P.x, P.y)
	x3.Mul(x3, new(big.Int).Add(Q.x, Q.y))
	x3.Sub(x3, C)
	x3.Sub(x3, D)
	x3.Mul(x3, F)
	x3.Mul(x3, A)
	x3.Mod(x3, p)
	y3 := new(big.Int).Mul(c.a, C)
	y3.Sub(D, y3)
	y3.Mul(y3, G)
	y3.Mul(y3, A)
	y3.Mod(y3, p)
	z3 := new(big.Int).Mul(F, G)
	z3.Mod(z3, p)
	return edPoint{x3, y3, z3}
}

func edMul(k *big.Int, P edPoint, c *edCurve) edPoint {
	R := edPoint{big.NewInt(0), big.NewInt(1), big.NewInt(1)}
	for i := k.BitLen() - 1; i >= 0; i-- {
		R = edAdd(R, R, c)
		if k.Bit(i) == 1 {
			R = edAdd(R, P, c)
		}
	}
	return R
}

func leInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func edEncode(P edPoint, c *edCurve) []byte {
	zi := new(big.Int).ModInverse(P.z, c.p)
	x := new(big.Int).Mul(P.x, zi)
	x.Mod(x, c.p)
	v := new(big.Int).Mul(P.y, zi)
	v.Mod(v, c.p)
	if x.Bit(0) == 1 {
		v.SetBit(v, 8*c.n-1, 1)
	}
	out := make([]byte, c.n)
	v.FillBytes(out)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func edDecode(b []byte, c *edCurve) (edPoint, bool) {
	if len(b) != c.n {
		return edPoint{}, false
	}
	v := leInt(b)
	sign := v.Bit(8*c.n - 1)
	y := new(big.Int).SetBit(v, 8*c.n-1, 0)
	if y.Cmp(c.p) >= 0 {
		return edPoint{}, false
	}
	y2 := new(big.Int).Mul(y, y)
	num := new(big.Int).Sub(y2, big.NewInt(1))
	den := new(big.Int).Mul(c.d, y2)
	den.Sub(den, c.a)
	den.Mod(den, c.p)
	if den.ModInverse(den, c.p) == nil {
		return edPoint{}, false
	}
	x := sqrtMod(num.Mul(num, den), c.p)
	if x == nil || (x.Sign() == 0 && sign == 1) {
		return edPoint{}, false
	}
	if x.Bit(0) != sign {
		x.Sub(c.p, x)
	}
	return edPoint{x, y, big.NewInt(1)}, true
}

func verifyEdDSA(spki *tlv, tbs, sig []byte, oid string) (bool, error) {
	alg, err := child(spki, 0)
	if err != nil {
		return false, err
	}
	a0, err := child(alg, 0)
	if err != nil {
		return false, err
	}
	if decodeOID(a0.content) != oid {
		return false, nil
	}
	c := edCurves[oid]
	bs, err := child(spki, 1)
	if err != nil {
		return false, err
	}
	pk := bitStringBody(bs)
	if c.n == 32 {
		return verifyEd25519(pk, tbs, sig, c), nil
	}
	A, ok := edDecode(pk, c)
	if !ok || len(sig) != 2*c.n {
		return false, nil
	}
	S := leInt(sig[c.n:])
	if S.Cmp(c.L) >= 0 {
		return false, nil
	}
	msg := append(append(append([]byte{}, sig[:c.n]...), pk...), tbs...)
	var hk []byte
	if c.n == 32 {
		h := sha512.Sum512(msg)
		hk = h[:]
	} else {
		hk = sha3.SumSHAKE256(append([]byte("SigEd448\x00\x00"), msg...), 114)
	}
	k := leInt(hk)
	k.Mod(k, c.L)
	SB := edMul(S, edPoint{c.bx, c.by, big.NewInt(1)}, c)
	negA := edPoint{new(big.Int).Mod(new(big.Int).Sub(c.p, A.x), c.p), A.y, big.NewInt(1)}
	R := edAdd(SB, edMul(k, negA, c), c)
	return bytes.Equal(edEncode(R, c), sig[:c.n]), nil
}

// verifyEd25519 uses crypto/ed25519 after rejecting the public-key encodings it accepts
// but the reference does not (y >= p, and x = 0 with the sign bit set), so both give
// the same answer; S >= L, the hash input and the comparison of R are already the same.
func verifyEd25519(pk, tbs, sig []byte, c *edCurve) bool {
	if len(pk) != 32 || len(sig) != 64 {
		return false
	}
	v := leInt(pk)
	sign := v.Bit(255)
	y := v.SetBit(v, 255, 0)
	if y.Cmp(c.p) >= 0 {
		return false
	}
	if sign == 1 && (y.Cmp(big.NewInt(1)) == 0 || y.Cmp(new(big.Int).Sub(c.p, big.NewInt(1))) == 0) {
		return false
	}
	return ed25519.Verify(pk, tbs, sig)
}

// selfSigned reports whether the signature verifies under the certificate's own key.
// errUnverifiable means the algorithm cannot be checked ("u").
func selfSigned(spki, tbs, sigAlgT, sigBits *tlv) (bool, error) {
	a0, err := child(sigAlgT, 0)
	if err != nil {
		return false, errMalformed // raised outside the reference's try block
	}
	oid := decodeOID(a0.content)
	sa, ok := sigAlgs[oid]
	if !ok {
		return false, errUnverifiable
	}
	sig := bitStringBody(sigBits)
	pa, err := child(spki, 0)
	if err != nil {
		return false, errMalformed
	}
	pa0, err := child(pa, 0)
	if err != nil {
		return false, errMalformed
	}
	pkOID := decodeOID(pa0.content)
	var res bool
	switch sa.fam {
	case "rsa", "pss":
		if pkOID != oidRSA && pkOID != oidRSAPSS {
			return false, nil
		}
		if sa.fam == "pss" {
			var params *tlv
			if len(sigAlgT.children) > 1 {
				params = sigAlgT.children[1]
			}
			res, err = verifyPSS(spki, tbs.raw, sig, params)
		} else {
			res, err = verifyRSA(spki, tbs.raw, sig, sa.hash)
		}
	case "dsa":
		if pkOID != oidDSA {
			return false, nil
		}
		res, err = verifyDSA(spki, tbs.raw, sig, sa.hash)
	case "ecdsa":
		res, err = verifyECDSA(spki, tbs.raw, sig, sa.hash)
	case "mldsa":
		if pkOID != oid {
			return false, nil
		}
		bs, e := child(spki, 1)
		if e != nil {
			return false, nil
		}
		res = mldsaVerify(oid, bitStringBody(bs), tbs.raw, sig)
	default:
		res, err = verifyEdDSA(spki, tbs.raw, sig, oid)
	}
	if err == errInvalid {
		return false, nil
	}
	return res, err
}
