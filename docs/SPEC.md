# GFMX specification (version 1-draft.3)

This document defines how a GFMX value is computed from a certificate, precisely enough to write an independent implementation. [DESIGN.md](DESIGN.md) explains why each element is there; this document only says what it is.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Conformance

An implementation conforms if, for every entry in `testdata/vectors.jsonl`, it produces exactly the `gfmx`, `raw` and `info` values recorded there, and reports a parse error for every entry marked `"error": true`. The reference implementation is `gfmx.py`; where this text and the reference disagree, the reference and the vectors decide, and the text is corrected.

Two implementations exist today and agree on all vectors and on more than 200,000 mutated certificates: `gfmx.py` (Python, standard library only) and `go/gfmx` (Go).

## 2. Output

```
KEY:SPAN:MAKER:AUDIENCE:NAMES
```

Each segment is `h8(pre-hash)`: the first 8 lowercase hex characters of SHA-256 over the UTF-8 encoding of the segment's pre-hash string, or the empty string when the pre-hash string is empty. The five segments are joined with `:`. Colons are always written, so an empty segment appears as `::`. Only AUDIENCE and NAMES can be empty.

Implementations SHOULD also expose the five pre-hash strings (`raw`) and the unhashed `info` string (section 10), and SHOULD store them next to the value.

## 3. Reading the input

The input is the DER encoding of one X.509 certificate (RFC 5280). Containers (PEM, PKCS#7, APK, PE) are opened first; that step is not part of this specification.

### 3.1 TLV reader

Elements are read as identifier, length, contents:

- Identifier: class = top two bits, constructed = bit 6, tag number = low five bits, or, when they are all ones, the base-128 number in the following bytes (high bit = more bytes follow). Tag numbers that do not fit in 64 bits only need to compare unequal to small numbers.
- Length: short form (< 0x80); long form 0x81 to 0xFF followed by that many big-endian length bytes. **0x80 (indefinite length) is an error.** A long-form length is flagged *non-minimal* when its value is below 0x80 or its first length byte is 0x00.
- An element whose header or contents run past the end of the available bytes is an error.
- Constructed elements are parsed into children until their contents are used up. Primitive elements have no children (an OCTET STRING or BIT STRING is never parsed implicitly).
- Nesting deeper than 64 levels below the element being parsed is an error. Real certificates nest about a dozen levels.

An error while reading the certificate makes the whole certificate a parse error, except where a section below says the error is caught, and except as in 3.1.1.

#### 3.1.1 Data after a name attribute's value

Some device firmware writes an issuer or subject attribute whose outer lengths include a value that the value's own length leaves out (seen on 2Wire home gateways: `30 14 06 03 55 04 03 16 00` followed by the device's IP address, a commonName of length 0 with 13 more bytes inside the attribute). Such a certificate is read a second time, leniently, **only when the strict reading of 3.1 fails**:

- In the lenient reading, when a child of a SEQUENCE (0x30) cannot be read and that SEQUENCE already has exactly two children, the first an OBJECT IDENTIFIER (0x06), the SEQUENCE keeps those two children and the rest of its contents is ignored (the *tail*).
- The certificate is accepted only if at least one tail was found and every tail is an AttributeTypeAndValue of `issuer` or `subject` (a child of one of their RDN sets). MAKER then gets the `atvtrail` flag, and all other rules apply unchanged; extension values are still read strictly (section 4).
- Otherwise, or if anything later fails for the leniently read certificate, the result is the strict reading's parse error.

A certificate that the strict reading accepts is never read leniently, so its value is the same as under 1-draft.2. The tail never enters a pre-hash string: names contribute only attribute types (section 9).

### 3.2 Certificate layout

- `root` = the first element of the input. If bytes remain after it, MAKER gets the `trail` flag.
- `tbs` = root.children[0], `sigAlg` = root.children[1]. Missing children are a parse error.
- In tbs: if children[0] is context-specific [0], it holds the version and the remaining fields start at index 1; otherwise at index 0. From that index: `serial`, `tbsSigAlg`, `issuer`, `validity`, `subject`, `spki`, then optional fields. Fewer than six fields is a parse error.
- `sigValue` = root.children[2] is only needed when issuer and subject are identical (section 5.1); its absence is then a parse error.

### 3.3 Helpers

- **OID rendering.** Read the contents as base-128 arcs (a byte with the high bit clear ends an arc). An unterminated final arc is dropped; no arcs gives `""`. The first arc *v* becomes two components: `0.v` if v < 40, `1.(v−40)` if v < 80, else `2.(v−80)`. Components are decimal, joined with `.`. **An arc encoded in more than 64 bytes is rendered as `x`** (a first arc of that size renders as `2.x`). **An OID with more than 128 arcs is rendered as `x`** as a whole (an unterminated final arc does not count).
- **Small unsigned integer.** Contents read as an unsigned big-endian integer and written in decimal; **contents longer than 8 bytes are written as `x`**.
- **Signed integer.** Two's complement big-endian (used inside signature checks).
- **BIT STRING body** = contents without the first (unused-bits) byte.

## 4. Extensions

For each element in the optional tbs fields:

- context [1] or [2] (unique identifiers): flag `uid`.
- context [3]: its first child is the extensions SEQUENCE (a missing child is a parse error). An empty SEQUENCE sets flag `extempty`. For each extension (a missing first child is a parse error):
  - `oid` = rendering of children[0].
  - `critical` = false; if the extension has exactly 3 children, `critical` = (contents of children[1] ≠ the single byte 0x00), and when that is false the flag `critF` is set (DEFAULT FALSE encoded).
  - The value is the last child's contents, read as one TLV (section 3.1, depth counted from 0). If that read fails, the value is *absent* and flag `extbad` is set; otherwise the value is walked for flags (section 7.2, all INTEGERs checked).
- Other fields are ignored.

The extension list keeps every extension in order. If an OID occurs more than once, flag `dupext` is set and only its **first** occurrence is used where a section below looks an extension up by OID. An extension whose value is absent counts as not present for those lookups.

## 5. KEY

```
iss=<issuance>;pk=<public key OID><detail>;sig=<signature OID>[;alt=<alt key>/<alt signature>]
```

- `public key OID` = rendering of spki.children[0].children[0]; `signature OID` = rendering of sigAlg.children[0]. Missing children are a parse error.
- `detail`:
  - rsaEncryption (1.2.840.113549.1.1.1) or RSASSA-PSS (1.2.840.113549.1.1.10) keys: `/<bit length of the modulus>`, the modulus being the first INTEGER of the RSAPublicKey in the BIT STRING body, read as unsigned; `/?` if that cannot be read.
  - id-ecPublicKey (1.2.840.10045.2.1) with an OID parameter: `/<curve OID>`. Other EC parameters: no detail.
  - id-dsa (1.2.840.10040.4.1): `/<bit length of p>` (first INTEGER of the parameters, unsigned), or `/-` when the parameters are absent or do not start with an INTEGER.
  - anything else: no detail. (ML-DSA, SLH-DSA and ML-KEM name their parameter set in the OID itself.)
- `alt` (hybrid certificates) is appended only when the subjectAltPublicKeyInfo (2.5.29.72) or altSignatureAlgorithm (2.5.29.73) extension is present. `alt key` = the algorithm OID of the subjectAltPublicKeyInfo value followed by its detail (same rules as above), `-` when that extension is absent, `?` when it lacks the algorithm or the key; `alt signature` = the altSignatureAlgorithm value's OID, `-` when absent, `?` when malformed. The alternative signature is not verified.

### 5.1 Issuance

If the issuer and subject encodings are not byte-identical, `iss=i`. (A certificate for a KEM key such as ML-KEM is never self-signed: the key cannot sign.) Otherwise the signature is checked under the certificate's own public key:

- `s`: it verifies.
- `n`: it does not verify (including malformed keys and signatures).
- `u`: the algorithm, digest, curve or key size is outside what this specification checks.

The check uses sigAlg (the outer algorithm) and the BIT STRING body of sigValue, over the full encoding of tbs. The signature OID MUST be in Appendix A, else `u`. Reading the signature algorithm OID or the public key algorithm OID failing is a parse error; any other failure inside the check gives `n`. The exact procedures are in Appendix B. They are deliberately independent of any crypto library's policy: SHA-1, MD5 and DSA signatures are checked like any other.

## 6. SPAN

```
len=<length>;kind=<kind>
```

### 6.1 Times

notBefore and notAfter are validity.children[0] and [1] (missing children are a parse error).

- UTCTime (tag 23): `YYMMDDhhmm[ss]Z` (10 or 12 ASCII digits then `Z`). Years 50–99 are 1950–1999, 00–49 are 2000–2049. Standard form is exactly 12 digits + `Z`.
- GeneralizedTime (tag 24): `YYYYMMDDhhmm[ss][.f+]Z`. Fractions are ignored. Standard form is exactly 14 digits + `Z`.
- Anything else, or an impossible date or time (month 1–12, day valid for the month in the proleptic Gregorian calendar, hour ≤ 23, minute ≤ 59, second ≤ 59, year 1–9999), makes that time *unusable*.

If either time is unusable: `len=?;kind=?`.

### 6.2 Length and kind

Let `end` = notAfter, `dur` = notAfter − notBefore in seconds.

1. Fixed end dates, checked in this order: notAfter on 9999-12-31 (any time of day) → `-`, `end9999`; exactly 2049-12-31 23:59:59 → `-`, `end2049`; exactly 2038-01-19 03:14:07 → `-`, `end2038`.
2. dur < 0 → `-`, `neg`.
3. dur < 60 → `PT<dur>S`, `exact`.
4. dur < 3570 → `PT<⌊(dur+30)/60⌋>M`, `exact`.
5. dur < 172800 → `PT<⌊(dur+1800)/3600⌋>H`, `exact`.
6. `days` = ⌊(dur + 43200) / 86400⌋. If 28 ≤ days ≤ 2,000,000: `n0` = ⌊days / (146097/4800) + 0.5⌋ computed in IEEE-754 double precision; for n in n0−1, n0, n0+1 (n ≥ 1), if `days` lies in `calendar_days(n)` (inclusive), the result is `P<n÷12>Y<n mod 12>M` with zero parts omitted (`P1Y`, `P6M`, `P1Y1M`), kind `cal`.
7. Otherwise `P<days>D`, `exact`.

`calendar_days(n)` is the smallest and largest number of days that n calendar months can span: over every start date with year 2000–2399, month 1–12 and day 1, 29, 30 or 31 (days that exist in that month), with the end date being day *d* of the month n months later, either clamped to that month's last day or rolled over (day *d* counted from day 1 of that month, i.e. first-of-month + d − 1), the span being end − start in days.

## 7. MAKER

```
ver=<version>;enc=<flags>;algp=<params>;rel=<relation>;ext=<list>;ser=<serial>;kid=<ski>/<aki>;vc=<construction>;mtc=<merkle>
```

### 7.1 Version
`1` when the [0] field is absent. Otherwise the small unsigned integer of its first child plus one (`x` when longer than 8 bytes). A first child that is missing is a parse error. A value of 1 encoded explicitly sets flag `v1x`.

### 7.2 Flags (`enc`)
The set of flags below, sorted and joined with `,`; `-` when empty.

| Flag | Set when |
|---|---|
| `trail` | bytes follow the certificate |
| `atvtrail` | the certificate was read under 3.1.1 (data after a name attribute's value) |
| `len` | any element (certificate tree or extension values) has a non-minimal long-form length |
| `bool` | a BOOLEAN's contents are not exactly one byte 0x00 or 0xFF |
| `int` | an INTEGER of 2+ bytes starts 0x00 followed by < 0x80, or 0xFF followed by ≥ 0x80. The serial number is exempt |
| `v1x` | version 1 encoded explicitly |
| `sigmm` | tbsSigAlg and sigAlg are not byte-identical |
| `uid` | issuerUniqueID or subjectUniqueID present |
| `extempty`, `critF`, `extbad`, `dupext` | section 4 |
| `strspec` | in issuer or subject, countryName (2.5.4.6), serialNumber (2.5.4.5) or dnQualifier (2.5.4.46) is not a PrintableString (0x13), or emailAddress (1.2.840.113549.1.9.1) or domainComponent (0.9.2342.19200300.100.1.25) is not an IA5String (0x16) |
| `tfmt` | notBefore or notAfter is not in standard form (section 6.1) |
| `gt2050` | a usable GeneralizedTime with a year before 2050 |
| `ut2050` | a usable UTCTime with a year 2050 or later (cannot occur with the year mapping above) |
| `negval` | both times usable and notAfter < notBefore |

The INTEGER, BOOLEAN and length checks walk the whole certificate tree and each extension value.

### 7.3 Algorithm parameters (`algp`)
For tbsSigAlg, the public key algorithm, sigAlg, and (when present and holding an algorithm) the subjectAltPublicKeyInfo algorithm and the altSignatureAlgorithm, in that order: the parameter code is `a` (no second child), `n` (NULL), `o` (OID), `s` (SEQUENCE) or `x` (other). The expected code is `s` for 1.2.840.113549.1.1.10; `n` for any other OID under 1.2.840.113549.1.1.; `o` for 1.2.840.10045.2.1; `a` for OIDs under 1.2.840.10045.4., for 1.3.101.112, 1.3.101.113, for OIDs under 2.16.840.1.101.3.4.3. (ML-DSA, SLH-DSA) and 2.16.840.1.101.3.4.4. (ML-KEM), and for id-alg-mtcProof (1.3.6.1.5.5.7.6.67); unknown otherwise. Each algorithm contributes `?<code>` when the expected code is unknown, `<expected>><code>` when they differ, and nothing when they match. Contributions are joined with `,`; `std` when there are none. A missing algorithm OID is a parse error.

### 7.4 Relation (`rel`)
`eq` if issuer and subject are byte-identical; else `ie` if the issuer has no RDNs; else `se` if the subject has no RDNs; else `df`.

### 7.5 Extension list (`ext`)
The extension OIDs in order, each followed by `!` when critical, joined with `,`, leaving out subjectAltName (2.5.29.17), the CT precertificate poison (1.3.6.1.4.1.11129.2.4.3) and the CT SCT list (1.3.6.1.4.1.11129.2.4.2).

### 7.6 Serial (`ser`)
Let `v` = |serial| (two's complement). `mtc` if sigAlg is id-alg-mtcProof (1.3.6.1.5.5.7.6.67): a Merkle Tree Certificate's serial is (log number << 48) | index, so its size says nothing about the template. Otherwise `z` if v = 0. Otherwise with `bl` = bit length of v: if notBefore is usable, 28 ≤ bl ≤ 64, and for some scale in (1, 1000, 10⁹) |v − t·scale| ≤ 172800·scale where t is notBefore in Unix seconds, `t`. Else `s` if bl ≤ 32, else `r<⌈bl/32⌉·4>` (`r8`, `r16`, `r20` …).

### 7.7 Key identifiers (`kid`)
SKI (2.5.29.14): `kid` = contents of the extension value (the inner OCTET STRING). The first match in this order names the method: `m1` SHA-1(BIT STRING body of spki); `m2` 0x4 followed by the low 60 bits of that SHA-1 (RFC 5280 method 2); `s256`, `s384`, `s512` the first 20 bytes of SHA-256/384/512 of the BIT STRING body; `spki1` SHA-1 of the whole spki encoding; `spki256` the first 20 bytes of SHA-256 of it. No match: `o<length of kid>`. Absent: `-`.

AKI (2.5.29.35): for each context-specific child of the value, `k` (tag 0), `i` (tag 1), `s` (tag 2) or `?`, concatenated; `e` if there are none. Absent: `-`.

### 7.8 Validity construction (`vc`)
`?` when a time is unusable. Otherwise `<cons>.<align>`, where `align` is `mid` when notBefore is 00:00:00 and `any` otherwise, and `cons` is:
- `end` when SPAN's kind starts with `end`;
- `neg` when dur < 0;
- otherwise the first match for `t` = dur, then dur + 1 (codes `x` and `m1`): `day.<code>` if t ≥ 82800 and t mod 86400 is 0, 3600 or 82800; `hr.<code>` if t mod 3600 = 0; `min.<code>` if t mod 60 = 0 and t < 172800;
- `oth` when nothing matches.

### 7.9 Merkle Tree Certificates (`mtc`)
`log` when sigAlg is id-alg-mtcProof (1.3.6.1.5.5.7.6.67, draft-ietf-plants-merkle-tree-certs), empty otherwise. The log number and index are not hashed (section 10).

## 8. AUDIENCE

Collect the items below that apply, sort them, join with `;`. Empty when none apply.

- `eku=<OIDs>`: extKeyUsage (2.5.29.37) value's children, rendered, sorted, joined with `,`.
- `ku=<mask>`: keyUsage (2.5.29.15): over the first min(8 × len(body), 9) bits of the BIT STRING body, bit *i* (most significant bit of byte 0 is bit 0) sets 2^i; written as at least three lowercase hex digits.
- `bc=<…>`: basicConstraints (2.5.29.19): over the value's children, a BOOLEAN sets cA (contents ≠ 0x00), an INTEGER sets pathLen (small unsigned integer). `bc=c<pathLen>` when cA (`bc=c` without pathLen), else `bc=e`.
- `pol=<items>`: the rendered policyIdentifier of each certificatePolicies (2.5.29.32) entry (a missing one is a parse error); `tmpl:<OID>` from the first child of the Microsoft certificate template information extension (1.3.6.1.4.1.311.21.7); `tmplname:<name>` from the Microsoft template name extension (1.3.6.1.4.1.311.20.2), decoded as UTF-16BE when the value is a BMPString (0x1E) and as UTF-8 otherwise, `?` when it does not decode. Sorted, joined with `,`.
- `ptr=<items>`: for authorityInfoAccess (1.3.6.1.5.5.7.1.1) then cRLDistributionPoints (2.5.29.31) when present: `aia:` / `cdp:` followed by the distinct URI schemes found in primitive context [6] elements anywhere in the value, sorted and joined with `+` (`-` when there are none). A scheme is the leading `[A-Za-z][A-Za-z0-9+.-]*` before `:`, lowercased; `?` when there is none. The two items are joined with `,`.

## 9. NAMES

```
i=<issuer groups>|s=<subject groups>
```

Each RDN of the issuer (then the subject) becomes a group: the rendered OIDs of its attributes, in encoded order, joined with `+`. Groups are joined with `,`. The pre-hash string is empty when neither name has any RDN. An attribute without both a type and a value is a parse error.

## 10. Info (unhashed)

```
str=<choices>;span=<exact span>[;ser=<serial notes>]
```

- `str`: for every issuer or subject attribute not in the `strspec` list: if the value's identifier byte is PrintableString (0x13 → `P`), UTF8String (0x0C → `U`), IA5String (0x16 → `I`), BMPString (0x1E → `B`), TeletexString (0x14 → `T`) or UniversalString (0x1C → `V`), and its contents decode (UTF-16BE for BMP, UTF-32BE for Universal, UTF-8 otherwise; strict) to text made only of `A–Z a–z 0–9 space ' ( ) + , - . / : = ?` (optionally followed by one final newline), the code is recorded; any other identifier records `X`. Distinct codes, sorted, joined with `,`; `-` when none.
- `span`: `<days>d<hh>:<mm>:<ss>` of notAfter − notBefore, `neg` when negative, `?` when a time is unusable.
- `ser`: `neg` when the serial is negative, `pad` when it is not minimally encoded (same test as the `int` flag), joined with `,`; the item is omitted when neither applies.
- `mtc`: for Merkle Tree Certificates only, `<log number>/<index>` decoded from |serial|; the log number is `x` when it needs more than 64 bits.

## 11. Versioning

This is specification `1-draft.3`. It differs from `1-draft.2` only for certificates that 1-draft.2 rejects with a parse error (section 3.1.1); `1-draft.2` differs from `1-draft` only on hostile input (OIDs over 128 arcs, Merkle Tree log numbers over 64 bits, DSA g or y longer than p; see [DESIGN.md](DESIGN.md)). Any change that can alter an output for some input gets a new version number, a new set of vectors, and an entry in [DESIGN.md](DESIGN.md). Implementations report the version they follow (`gfmx --version`). Stores SHOULD keep the version with each value.

## Appendix A. Signature algorithms checked

| Family | Signature OIDs | Digest |
|---|---|---|
| RSA PKCS#1 v1.5 | 1.2.840.113549.1.1.4 / .5 / .14 / .11 / .12 / .13 / .15 / .16, 1.3.14.3.2.29, 2.16.840.1.101.3.4.3.13–16 | MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA-1, SHA3-224…512 |
| RSASSA-PSS | 1.2.840.113549.1.1.10 | from the parameters |
| DSA | 1.2.840.10040.4.3, 1.3.14.3.2.27, 2.16.840.1.101.3.4.3.1–8 | SHA-1, SHA-1, SHA-224…512, SHA3-224…512 |
| ECDSA | 1.2.840.10045.4.1, 1.2.840.10045.4.3.1–4, 2.16.840.1.101.3.4.3.9–12 | SHA-1, SHA-224…512, SHA3-224…512 |
| EdDSA | 1.3.101.112 (Ed25519), 1.3.101.113 (Ed448) | – |
| ML-DSA | 2.16.840.1.101.3.4.3.17 / .18 / .19 (ML-DSA-44 / 65 / 87) | – |

ECDSA curves (all cofactor 1): prime192v1, secp224r1, prime256v1, secp384r1, secp521r1, secp256k1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1. Digest OIDs recognised inside RSA DigestInfo and PSS parameters: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224…512.

## Appendix B. Verification procedures

All integers are read as signed big-endian two's complement unless stated. "Invalid" means the result is `n`.

**Key family check.** RSA and PSS signatures need an rsaEncryption or RSASSA-PSS key, DSA signatures an id-dsa key, ECDSA an id-ecPublicKey key, EdDSA and ML-DSA a key with the same OID as the signature; anything else is invalid.

**RSA key.** The BIT STRING body is read as a TLV; n = children[0], e = children[1]. If n has more than 16,384 bits or e more than 64 bits: `u`.

**RSA PKCS#1 v1.5.** s = signature as unsigned; invalid unless 0 < s < n and e > 0. EM = s^e mod n as k = ⌈bitlen(n)/8⌉ bytes. EM MUST start 0x00 0x01, followed by at least eight 0xFF bytes and a 0x00 separator; T = the rest. If T is exactly one DER SEQUENCE of two children whose second is an OCTET STRING and whose first child's first child is a recognised digest OID, the signature verifies iff that OCTET STRING equals that digest of tbs. Otherwise it verifies iff T equals the signature algorithm's digest of tbs.

**RSASSA-PSS.** Digest and MGF1 digest from the parameters ([0] hashAlgorithm, [1] maskGenAlgorithm whose parameters name the MGF1 digest), default SHA-1; an unrecognised digest, or a maskGenAlgorithm without parameters, is `u`. s as unsigned; invalid unless 0 < s < n. m = s^e mod n (a negative e uses the modular inverse; no inverse is invalid). emBits = bitlen(n) − 1, emLen = ⌈emBits/8⌉; m needing more than emLen bytes is invalid. Then RFC 8017 EMSA-PSS-VERIFY with the salt length taken from the encoding.

**DSA.** Parameters absent or empty: `u`. p, q, g = the first three INTEGERs (fewer is invalid). p over 4,096 bits, q over 512 bits, or g longer than p (in bits): `u`. p < 2 or q < 2: invalid. y from the BIT STRING body; y longer than p (in bits): `u`. r, s from the signature SEQUENCE; invalid unless 0 < r < q and 0 < s < q. z = the leftmost min(bitlen(q), digest bits) bits of the digest. Standard verification with w = s⁻¹ mod q (no inverse is invalid), v = ((g^(z·w mod q) · y^(r·w mod q)) mod p) mod q, bases reduced mod p.

**ECDSA.** Parameters not a named-curve OID: `u`; a curve outside Appendix A: `u`. The public key point is uncompressed (0x04 ‖ X ‖ Y) or compressed (0x02/0x03 ‖ X) with field-length coordinates; coordinates MUST be below p and on the curve; anything else is invalid. The signature MUST be a strictly DER SEQUENCE of exactly two positive, minimally encoded INTEGERs with no trailing bytes. Invalid unless 0 < r, s < n. e = the leftmost bitlen(n) bits of the digest. Standard verification: (u1·G + u2·Q).x mod n = r, the point at infinity being invalid.

**EdDSA (RFC 8032).** The public key (BIT STRING body) MUST decode canonically: 32 or 57 bytes, y < p, x recoverable, and not x = 0 with the sign bit set. The signature MUST be 64 or 114 bytes with S < L. k = SHA-512(R ‖ A ‖ tbs) for Ed25519, SHAKE256("SigEd448" ‖ 0x00 ‖ 0x00 ‖ R ‖ A ‖ tbs, 114) for Ed448, little-endian mod L. The signature verifies iff the encoding of [S]B − [k]A equals R byte for byte (cofactorless).

**ML-DSA (FIPS 204, RFC 9881).** ML-DSA.Verify with an empty context string, i.e. M' = 0x00 ‖ 0x00 ‖ tbs. The public key (BIT STRING body) MUST be 32 + 320·k bytes and the signature exactly λ/4 + 32·l·(1 + bitlen(γ1 − 1)) + ω + k bytes; a malformed hint encoding, ‖z‖∞ ≥ γ1 − β, or a challenge that does not match is invalid. Parameter sets (k, l, τ, γ1, γ2, β, ω, λ): ML-DSA-44 (4, 4, 39, 2^17, (q−1)/88, 78, 80, 128); ML-DSA-65 (6, 5, 49, 2^19, (q−1)/32, 196, 55, 192); ML-DSA-87 (8, 7, 60, 2^19, (q−1)/32, 120, 75, 256); q = 8380417. HashML-DSA, SLH-DSA and composite signatures give `u`.
