package gfmx

import (
	"errors"
	"math/big"
	"strconv"
	"strings"
)

// tlv is one DER element with the encoding details GFMX needs.
type tlv struct {
	first         byte // identifier octet
	cls           byte // 0 universal, 1 application, 2 context, 3 private
	constructed   bool
	tagnum        uint64 // hugeTag when the high-tag number does not fit
	content       []byte
	raw           []byte
	children      []*tlv
	nonminimalLen bool
}

const hugeTag = ^uint64(0)

// maxDepth bounds recursion on attacker-controlled input: 64, as in the reference (gfmx.py)
// and SPEC 3.1, so a certificate gets the same value, or the same parse error, in both.
const maxDepth = 64

var (
	errTruncHeader  = errors.New("truncated header")
	errTruncTag     = errors.New("truncated tag")
	errIndefinite   = errors.New("indefinite length (BER)")
	errTruncLength  = errors.New("truncated length")
	errTruncContent = errors.New("truncated content")
	errDepth        = errors.New("nesting too deep")
)

// parser hands out tlv nodes and child slices from slabs, so a certificate costs a
// few allocations instead of two per element. Nodes are never freed individually;
// the slabs die with the parser.
type parser struct {
	nodes []tlv
	ptrs  []*tlv
	// lax enables the second pass of SPEC 3.1.1: a SEQUENCE holding an OID and one
	// value followed by bytes that do not parse keeps those two children and is
	// recorded in tails. Off for the first (strict) pass.
	lax   bool
	tails []*tlv
}

func (p *parser) node() *tlv {
	if len(p.nodes) == cap(p.nodes) {
		p.nodes = make([]tlv, 0, min(max(2*cap(p.nodes), 4), 64))
	}
	p.nodes = p.nodes[:len(p.nodes)+1]
	return &p.nodes[len(p.nodes)-1]
}

func (p *parser) keep(cs []*tlv) []*tlv {
	if len(cs) == 0 {
		return nil
	}
	if cap(p.ptrs)-len(p.ptrs) < len(cs) {
		p.ptrs = make([]*tlv, 0, max(min(2*cap(p.ptrs), 128), 8, len(cs)))
	}
	start := len(p.ptrs)
	p.ptrs = append(p.ptrs, cs...)
	return p.ptrs[start:len(p.ptrs):len(p.ptrs)]
}

func parseTLV(buf []byte, off, depth int) (*tlv, int, error) {
	var p parser
	return p.parse(buf, off, depth)
}

func (p *parser) parse(buf []byte, off, depth int) (*tlv, int, error) {
	if depth > maxDepth {
		return nil, 0, errDepth
	}
	if off+2 > len(buf) {
		return nil, 0, errTruncHeader
	}
	t := p.node()
	first := buf[off]
	t.first = first
	t.cls = first >> 6
	t.constructed = first&0x20 != 0
	tagnum := uint64(first & 0x1F)
	i := off + 1
	if tagnum == 0x1F {
		tagnum = 0
		for {
			if i >= len(buf) {
				return nil, 0, errTruncTag
			}
			b := buf[i]
			i++
			if tagnum != hugeTag {
				if tagnum>>57 != 0 {
					tagnum = hugeTag
				} else {
					tagnum = tagnum<<7 | uint64(b&0x7F)
				}
			}
			if b&0x80 == 0 {
				break
			}
		}
	}
	t.tagnum = tagnum
	if i >= len(buf) {
		return nil, 0, errTruncHeader
	}
	lb := buf[i]
	i++
	var length int
	if lb < 0x80 {
		length = int(lb)
	} else if lb == 0x80 {
		return nil, 0, errIndefinite
	} else {
		n := int(lb & 0x7F)
		if i+n > len(buf) {
			return nil, 0, errTruncLength
		}
		lbytes := buf[i : i+n]
		i += n
		// value may exceed int: anything beyond the buffer is truncated content anyway
		var v uint64
		huge := false
		for _, b := range lbytes {
			if v>>55 != 0 {
				huge = true
				break
			}
			v = v<<8 | uint64(b)
		}
		if huge || v > uint64(len(buf)) {
			return nil, 0, errTruncContent
		}
		length = int(v)
		if length < 0x80 || lbytes[0] == 0 {
			t.nonminimalLen = true
		}
	}
	end := i + length
	if end > len(buf) {
		return nil, 0, errTruncContent
	}
	t.content = buf[i:end]
	t.raw = buf[off:end]
	if t.constructed {
		var stack [16]*tlv
		kids := stack[:0]
		j := 0
		for j < len(t.content) {
			c, nj, err := p.parse(t.content, j, depth+1)
			if err != nil {
				if p.lax && first == 0x30 && len(kids) == 2 && kids[0].first == 0x06 {
					p.tails = append(p.tails, t)
					break
				}
				return nil, 0, err
			}
			kids = append(kids, c)
			j = nj
		}
		t.children = p.keep(kids)
	}
	return t, end, nil
}

func isUniversal(t *tlv, num uint64) bool { return t.cls == 0 && t.tagnum == num }
func isContext(t *tlv, num uint64) bool   { return t.cls == 2 && t.tagnum == num }

// maxArcBytes: an OID arc encoded in more bytes is rendered as "x" (see the reference).
const maxArcBytes = 64

// maxArcs: an OID with more arcs is rendered as "x" as a whole (see the reference).
const maxArcs = 128

// decodeOID renders an OBJECT IDENTIFIER's content in dotted form. An unterminated
// final arc is dropped; arcs longer than maxArcBytes are rendered as "x", and an OID
// with more than maxArcs arcs is "x" as a whole.
//
// Fast path: every terminated arc fits in 8 bytes (56 bits), which covers all real
// OIDs; one allocation (the result) and no big.Int. Anything else takes decodeOIDBig.
func decodeOID(content []byte) string {
	var buf [96]byte
	out := buf[:0]
	var v uint64
	n, arcs := 0, 0
	for _, b := range content {
		n++
		if n > 8 {
			return decodeOIDBig(content)
		}
		v = v<<7 | uint64(b&0x7F)
		if b&0x80 == 0 {
			if arcs == maxArcs {
				return "x"
			}
			if arcs == 0 {
				switch {
				case v < 40:
					out = append(out, '0', '.')
				case v < 80:
					out = append(out, '1', '.')
					v -= 40
				default:
					out = append(out, '2', '.')
					v -= 80
				}
			} else {
				out = append(out, '.')
			}
			out = strconv.AppendUint(out, v, 10)
			arcs++
			v, n = 0, 0
		}
	}
	return string(out)
}

func decodeOIDBig(content []byte) string {
	if len(content) == 0 {
		return ""
	}
	var arcs []string
	var first *big.Int
	var v uint64
	var bv *big.Int
	n := 0
	for _, b := range content {
		n++
		if n <= maxArcBytes {
			if bv == nil && v>>56 != 0 {
				bv = new(big.Int).SetUint64(v)
			}
			if bv != nil {
				bv.Lsh(bv, 7)
				bv.Or(bv, big.NewInt(int64(b&0x7F)))
			} else {
				v = v<<7 | uint64(b&0x7F)
			}
		}
		if b&0x80 == 0 {
			if len(arcs) == maxArcs {
				return "x"
			}
			var s string
			var val *big.Int
			switch {
			case n > maxArcBytes:
				s = "x"
			case bv != nil:
				val = bv
				s = bv.String()
			default:
				if len(arcs) == 0 { // only the first arc's value is needed
					val = new(big.Int).SetUint64(v)
				}
				s = strconv.FormatUint(v, 10)
			}
			if len(arcs) == 0 && first == nil {
				first = val
				if val == nil {
					first = big.NewInt(-1) // huge first arc
				}
			}
			arcs = append(arcs, s)
			v, bv, n = 0, nil, 0
		}
	}
	if len(arcs) == 0 {
		return ""
	}
	var head string
	switch {
	case first.Sign() < 0:
		head = "2.x"
	case first.Cmp(big.NewInt(40)) < 0:
		head = "0." + first.String()
	case first.Cmp(big.NewInt(80)) < 0:
		head = "1." + new(big.Int).Sub(first, big.NewInt(40)).String()
	default:
		head = "2." + new(big.Int).Sub(first, big.NewInt(80)).String()
	}
	if len(arcs) == 1 {
		return head
	}
	return head + "." + strings.Join(arcs[1:], ".")
}

// smallUint renders a small unsigned INTEGER; "x" when the content exceeds 8 bytes.
func smallUint(content []byte) string {
	if len(content) > 8 {
		return "x"
	}
	return unsignedInt(content).String()
}

// unsignedInt and signedInt mirror Python's int.from_bytes(b, "big"[, signed=True]).
func unsignedInt(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

func signedInt(b []byte) *big.Int {
	v := new(big.Int).SetBytes(b)
	if len(b) > 0 && b[0]&0x80 != 0 {
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(8*len(b))))
	}
	return v
}
