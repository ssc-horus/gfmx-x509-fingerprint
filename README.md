# GFMX

**X.509 certificate fingerprinting for hunting, built for the post-quantum era.**

GFMX identifies the **tool or template that produced a certificate**, not the certificate itself. A C2 framework, a malware builder, an appliance firmware or a signing pipeline that regenerates certificates with random names, serial numbers, dates and keys keeps the same GFMX, so one value finds the whole family across internet scans, packet captures, CT logs, APKs and signed executables.

```
KEY:SPAN:MAKER:AUDIENCE:NAMES
2116e00d:86395ff9:28505f23:d3da824d:30215ccd
```

Post-quantum certificates need no new format: ML-DSA self-signatures are verified, ML-KEM keys, hybrid (alternative-key) certificates and Merkle Tree Certificates are all fingerprinted, and new algorithms are just new OIDs ([details below](#post-quantum-certificates)).

## The five segments

| Segment | Answers | Built from |
|---|---|---|
| **KEY** | What it is | Issuance (issued, or self-signed with the signature verified, failing or not checkable), public key algorithm with its size or curve, signature algorithm, and the alternative key and signature of hybrid certificates |
| **SPAN** | How long it lives | Validity length and kind (exact, calendar months, or a fixed end date such as 9999-12-31) |
| **MAKER** | Who built it | Encoding traces of the generating library, algorithm-parameter encoding, extension order and criticality, serial construction, key-identifier methods, how the validity dates were built, Merkle Tree Certificate marker |
| **AUDIENCE** | Who it is for | Extended Key Usage, Key Usage, Basic Constraints, policies and Microsoft template names, revocation and CA-info pointer types |
| **NAMES** | Which fields the template fills | Issuer and subject attribute types and their grouping (not their values) |

Each segment is the first 8 hex characters of SHA-256 over that segment's pre-hash string. An empty segment means the component is absent. Instance data (names, serials, keys, exact dates, subject alternative names) never enters the value, so it stays available as a separate, exact pivot.

Every value can be explained. `--raw` prints what was hashed:

```
$ gfmx --raw ca.der
2116e00d:86395ff9:28505f23:d3da824d:30215ccd ca.der
    key      iss=s;pk=1.2.840.113549.1.1.1/2048;sig=1.2.840.113549.1.1.11
    span     len=P3650D;kind=exact
    maker    ver=3;enc=-;algp=std;rel=eq;ext=2.5.29.14,2.5.29.35,2.5.29.19!;ser=r20;kid=m1/k;vc=day.x.any;mtc=
    audience bc=c
    names    i=2.5.4.3|s=2.5.4.3
    info     str=U;span=3650d00:00:00  (not hashed)
```

## Hunting with wildcards

Because each segment is hashed separately, any segment can be left out. `KEY:*:MAKER:AUDIENCE:NAMES` finds a builder that randomizes the validity period.

In a study of 9,531 Android malware samples (two runs: 4,607 samples, then 4,924 from unseen families), msfvenom's APK signing template `a1371c39:*:65fa07e6::6bc11ca7` matched 317 signing certificates, 167 in the first run and 150 in the second (see [DESIGN.md](docs/DESIGN.md), "validity is its own segment"). Each certificate had its own key, so no certificate hash or key hash links them, and every one was labelled Metasploit (metasploit, meterpreter or the misspelt mesploit) and nothing else.

Typical pivots:

| Pattern | Finds |
|---|---|
| full value | the same template: same tool, same configuration |
| `KEY:*:MAKER:AUDIENCE:NAMES` | the same builder with randomized validity |
| `*:*:MAKER:*:*` | the same builder code path, whatever the key type and purpose |
| `*:SPAN:MAKER:AUDIENCE:*` | the same template filled with different name fields |

### What a shared segment tells you

Each segment answers its own question, so two certificates can share some segments and not others. How much a shared segment says depends on how common its value is. Measured on 999,866 certificates from one day of Driftnet scanning (35,623 distinct values):

| Segment | Distinct values | Most common value covers | Values covering 90% of certificates |
|---|---|---|---|
| KEY | 156 | 54% | 6 |
| SPAN | 6,323 | 30% | 30 |
| MAKER | 4,187 | 26% | 108 |
| AUDIENCE | 2,383 | 26% | 37 |
| NAMES | 2,215 | 39% | 23 |

- **KEY match:** the same kind of key and signature, issued the same way (by a CA, or self-signed). A handful of values cover almost everything, so KEY alone says almost nothing; it narrows, it does not identify.
- **SPAN match:** the same validity policy. The common lengths (3 months for automated CAs, 1 year, 10 years) are shared by whole industries; an unusual one (40,000 days, or a fixed end such as 2038-01-19) comes close to naming one tool or one setting. A different SPAN is often just a different setting of the same tool, which makes it the first segment to wildcard when a builder randomizes the validity or lets its operator choose it.
- **MAKER match:** the same generating code path: library encoding habits, extension order, serial and key-identifier construction. It carries the most information about which software made the certificate. A different MAKER usually means different software, or a different version or configuration of it.
- **AUDIENCE match:** the same declared purpose (server, client, CA, code signing; key usages, policies, revocation pointers). Wildcard it when one tool issues several profiles.
- **NAMES match:** the same name fields filled in, not their contents. A different NAMES often means an operator edited the subject (added an O or an OU); wildcard it when operators fill the template by hand.

### Choosing wildcards

1. Start from the full value of a certificate you have confirmed.
2. Compare it with a few related samples segment by segment (`--raw` shows what each segment was built from) and wildcard only the segments that differ between them.
3. Keep MAKER whenever you can. A pattern left with only KEY, or KEY and NAMES, matches too much to pivot on.
4. Count the hits on benign data before alerting. A pattern that lands on thousands of unrelated organisations is a commodity template (a CA or a product default), not a lead.

### A match is a template, not an owner

GFMX matches the template that made a certificate. Builds, appliances and CAs reuse their template for every certificate they produce, so a shared value says the certificates came out of the same factory, never that they belong to the same owner. Two people can own the same car model, made in the same year at the same factory and sold by the same dealer in the same country, and still be two owners. In the Driftnet study the most common value, Let's Encrypt's RSA certificates, was on 218,203 hosts belonging to 19,044 organisations, and 82% of the values seen on 2 to 9 hosts already spanned more than one organisation. Who owns a certificate is in the instance data GFMX leaves out (names, keys, serials, subject alternative names), which stays available as exact pivots of its own.

## Post-quantum certificates

KEY is built from algorithm OIDs rather than "key size plus hash", so post-quantum and hybrid certificates fit the same format, and the next algorithm will too.

| Certificate | What GFMX does | Example (conformance vectors) |
|---|---|---|
| **ML-DSA-44 / 65 / 87** (FIPS 204, RFC 9881) | The parameter set is in the OID. Self-signatures are verified with plain integer math (`iss=s` or `iss=n`), independently of any crypto library | `pq/mldsa65.der` → `bc6ec4ba:74bc6287:9777a13a:9d828fa4:30215ccd`; the three parameter sets differ only in KEY |
| **ML-KEM-512 / 768 / 1024** | A KEM key cannot sign, so these certificates are always issued (`iss=i`); the OID names the parameter set | `pq/leaf_mlkem768_by_mldsa.der` → KEY `iss=i;pk=2.16.840.1.101.3.4.4.2;sig=2.16.840.1.101.3.4.3.18` |
| **Hybrid (alternative-key) certificates** (X.509 extensions 2.5.29.72–74) | KEY gains `alt=<alternative key>/<alternative signature>`, so a classical certificate carrying an ML-DSA key is told apart from a purely classical one. The alternative signature is recorded, not verified | `pq/hybrid.der` → KEY `…;alt=2.16.840.1.101.3.4.3.18/2.16.840.1.101.3.4.3.18` |
| **Merkle Tree Certificates** (draft-ietf-plants-merkle-tree-certs, id-alg-mtcProof) | The serial is a log number and index, not a template property, so it gets its own class (`ser=mtc`) and the log and index go to the unhashed info field. One template keeps one value across logs and indexes | `pq/mtc_log0.der`, `pq/mtc_log3.der`, `pq/mtc_log3b.der` → all `fa68d3f4:767524e5:e996e586::30215ccd`, info `mtc=0/77`, `mtc=3/12345`, `mtc=3/987654` |
| **SLH-DSA, composite signatures** | OIDs recorded in KEY; the self-signature is not checked (`iss=u`) | |

MAKER also checks how each algorithm's parameters are encoded, including the post-quantum and alternative algorithms. Early PQC libraries that add a NULL parameter where the standard says "absent" get their own value: `pq/hybrid.der` and `pq/hybrid_nullparams.der` differ only in MAKER (`algp=std` vs `algp=a>n`).

Self-signatures are checked for RSA (PKCS#1 v1.5 and PSS), DSA, ECDSA on nine named curves, Ed25519, Ed448 and ML-DSA, all with integer math, so weak or retired algorithms (MD5, SHA-1, DSA) are checked like any other and the result never depends on what a crypto library is willing to verify.

## What it reads

Any X.509 certificate: TLS and QUIC servers, client and device certificates, CT log entries (a precertificate and its final certificate get the same value), code signing, APK and JAR signing, S/MIME, CA certificates.

The Go command-line tool also opens the containers certificates live in:

| Input | Details |
|---|---|
| PEM, DER, folders, stdin | Any number of certificates per file; `TRUSTED CERTIFICATE` blocks; one hex or base64 certificate per line on stdin |
| PKCS#7 / CMS | `.p7b`, `.p7s`, Windows `.cat`; DER, BER and PEM; signer certificates are labelled |
| APK / JAR | Signature schemes v1, v2, v3 and v3.1, key-rotation lineage, source stamp, split bundles (`.apks`, `.xapk`), archives with a broken central directory |
| Authenticode | Signed `.exe`, `.dll`, `.sys`, including nested (dual) signatures and RFC 3161 timestamp tokens |
| Anything else | `--carve` finds certificates embedded anywhere in a binary, firmware image or memory dump |
| Live servers | `--host example.com:443` fingerprints the certificate a server presents (see [Live servers](#live-servers)) |

## Install

Go command-line tool (fast, opens containers, parallel):

```bash
go install github.com/ssc-horus/gfmx-x509-fingerprint/go/cmd/gfmx@latest
```

Prebuilt binaries for Linux, macOS and Windows, and the C library for Linux, are attached to each [release](https://github.com/ssc-horus/gfmx-x509-fingerprint/releases), with SHA-256 checksums.

Python reference implementation (standard library only, Python 3.11 or later): run `python3 gfmx.py` from a clone, or `pip install .` for a `gfmx` command and an importable module. It reads certificates (PEM, DER, folders, stdin, live hosts) but not containers.

C library for native plugins (Zeek, YARA, sandboxes):

```bash
go build -buildmode=c-shared -o libgfmx.so ./go/capi    # gfmx_fingerprint(), gfmx_json()
```

## Use

```bash
gfmx server.crt chain.pem certs/            # PEM (any number of certs), DER, folders
gfmx app.apk signed.exe bundle.p7b          # APK/JAR, Authenticode, PKCS#7/CMS
gfmx --carve implant.bin firmware.img       # certificates embedded anywhere in a binary
gfmx --host example.com:443                 # certificate a live server presents
gfmx --host 192.0.2.7:8443 --sni vpn.example.com  # an IP, asking for one name's certificate
some-feed | gfmx -                          # stdin: PEM, DER, or one hex/base64 cert per line
gfmx --raw server.crt                       # also print each segment's pre-hash input
gfmx --json certs/ > out.jsonl              # source, sha256, gfmx, raw, info, error
gfmx --csv out.csv certs/                   # table: file, gfmx, raw segments, info, sha256
```

Each certificate in a container is reported with its location:

```
$ gfmx app.apk
f481fe7a:74bc6287:501b0445:3d7148d3:737d5af0 app.apk!v3:signer0:cert0
2116e00d:86395ff9:28505f23:d3da824d:30215ccd app.apk!v3:signer0:lineage0
f481fe7a:74bc6287:501b0445:3d7148d3:737d5af0 app.apk!v1:META-INF/CERT.RSA:sd0:cert0:signer
2116e00d:86395ff9:28505f23:d3da824d:30215ccd app.apk!stamp
```

Exit status is 0 when every certificate was fingerprinted, 1 when at least one could not be parsed, and 2 for unreadable input or an output that could not be written; the rest of the run still completes.

As a library:

```python
import gfmx
r = gfmx.gfmx(der)           # {"gfmx": ..., "raw": {...}, "info": ...}; raises gfmx.GFMXError
```

```go
r, err := gfmx.Fingerprint(der)   // github.com/ssc-horus/gfmx-x509-fingerprint/go/gfmx
```

### Live servers

`--host` fingerprints the certificate a server sends at that address and port. It does not validate it, and it reads only that certificate, not the chain. Every TLS version and cipher suite the build still has is offered, so old appliances that speak only TLS 1.0 or RSA key exchange answer too.

A host name is sent as the server name (SNI). An IP address sends none, and the server answers with its default certificate for that port, which can differ from the one it serves for a name; `--sni NAME` asks for that name's certificate. This only matters when you pull from an IP directly. Driftnet records the certificate per IP and port it scanned, so a Driftnet value is what that IP and port presented, the same as `gfmx --host IP:PORT`.

## Connectors

| Tool | What it adds |
|---|---|
| **PCAP files** | Script writing one row per certificate with its packet's addresses, ports, TCP stream, chain position and SNI; JSON lines or CSV |
| **Suricata** | eve.json enricher adding `tls.gfmx` and `tls.gfmx_chain`, plus the config that makes Suricata log certificates |
| **Zeek** | Script logging certificate DER with Zeek's file and connection IDs, and an enricher adding the fingerprint column |
| **Ghidra** | Finds certificates embedded in the loaded program, bookmarks them and comments each with its fingerprint |
| **MISP** | `gfmx` object template: fingerprint, wildcard pattern, segments, raw strings, certificate hashes, attributed tool |

Every connector reports each certificate with its fingerprint, or with `gfmx_error` saying why there is none, and leaves deciding which side is the server or the client to the platform reading the output. Details, test status and planned integrations (ZGrab2, CT streams, Arkime, CAPE, YARA, IDA, binwalk, Velociraptor, Elastic, OpenCTI) are in [connectors/](connectors/). TLS 1.3 and QUIC encrypt the server certificate, so passive capture sees it only for TLS 1.2 and earlier or with decryption keys; active scanning and file sources are not affected.

## Built for hostile input

Scan data and malware are attacker-controlled. Both implementations bound everything a crafted certificate could inflate:

- DER nesting depth: 64 levels in both implementations ([SPEC 3.1](docs/SPEC.md)). One deep or malformed certificate inside a PKCS#7, APK or Authenticode signature does not hide the other certificates in it.
- OID arcs over 64 bytes, OIDs with more than 128 arcs, and integers over 8 bytes (including the Merkle Tree log number) are rendered as `x`, never expanded.
- Self-signature checks stop at RSA moduli of 16,384 bits, RSA exponents of 64 bits, DSA p of 4,096 bits, DSA q of 512 bits, and DSA g or y longer than p (`iss=u` beyond).
- ZIP members are read within a memory budget; nested APKs are opened one at a time.
- The Go library recovers from any internal panic and reports it as a parse error. The Go parsers are fuzzed, and both implementations are cross-checked on mutated certificates.

Encoding mistakes are not errors: they become MAKER flags (`trail`, `atvtrail`, `len`, `int`, `bool`, `dupext`, `extbad`, `tfmt` and others), because how a library gets DER wrong is one of the best signs of which library it is.

## Specification and conformance

- [docs/SPEC.md](docs/SPEC.md): the exact computation, precise enough for an independent implementation (specification 1-draft.3).
- [docs/DESIGN.md](docs/DESIGN.md): why each element is in or out, and the test results behind each decision.
- [testdata/vectors.jsonl](testdata/vectors.jsonl): 448 conformance vectors, including post-quantum, hybrid, Merkle Tree, hostile and malformed-device certificates. An implementation conforms when it reproduces every one exactly.

The Python reference and the Go implementation produce identical output on the vectors, the test bench and more than 200,000 mutated certificates.

The Go implementation runs at about 9,000 certificates per second per core (`--workers` sets the parallelism), which covers an internet scanner at 1,000 certificates per second on one core.

## Status

Specification 1-draft.3, version 0.9.10. Open items are tracked in [docs/DESIGN.md](docs/DESIGN.md) and [CHANGELOG.md](CHANGELOG.md).

Security reports: see [SECURITY.md](SECURITY.md). Running the tests, and why the public repository takes no contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GFMX is source-available under the [Sustainable Use License 1.0](LICENSE.md) (SPDX `SUL-1.0`). You may use and modify it for your own internal business purposes or for non-commercial or personal use, and share it free of charge for non-commercial purposes. Any other use, such as selling it or providing it to others commercially, requires a commercial license from SecurityScorecard: contact [Gilad Friedenriech Maizles](mailto:gilad.maizles@securityscorecard.io).

GFMX is patent pending.
