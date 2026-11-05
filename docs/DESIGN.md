# GFMX — design

This document explains why GFMX is built the way it is. The exact computation is defined in [SPEC.md](SPEC.md) (version 1-draft.3) and fixed by the conformance vectors in `testdata/`.

GFMX is an X.509 certificate fingerprint built for active scanning (Driftnet) and for hunting at the level of the tool or template that produced a certificate. It is designed to survive per-instance randomization: certificates regenerated with random names, serials, dates and keys keep the same fingerprint as long as they come from the same template.

It reads only the X.509 structure, so it works on any X.509 certificate, not just TLS server certificates.

## Principles
- **Fingerprint the template, not the instance.** Values that change per certificate (names, SAN entries, serial value, key, exact dates, URLs) are excluded; they remain raw pivots in Driftnet.
- **Every element must pass a stability test:** constant across all certificates one tool/template produces, and still discriminating between tools. If analysts would routinely wildcard it, it is out.
- **Every hashed element must be observable in every certificate the template produces.** An element that only shows up for some instance values (e.g. the string-type choice, which random names can hide) splits the fingerprint and is kept out of the hash.
- **Segments ordered from most stable to most volatile**, so most hunts are a prefix match with a trailing `*`.
- **Empty segment = component absent** (an empty segment is a signal, not filler).
- Computed from the certificate alone, so the same value results from scans, CT logs, PCAPs or files. Endpoint behavior (served chain, SNI handling, QUIC transport) is out of scope and belongs in a separate companion fingerprint.

## Scope
Works on any X.509 v1/v3 certificate (RFC 5280). There is no TLS-specific certificate format; TLS, QUIC, DTLS and other protocols all carry standard X.509.

| Source | Notes |
|---|---|
| TLS / QUIC / DTLS servers (HTTPS, SMTPS, IMAPS, LDAPS, RDP, VPN portals, appliance UIs) | Leaf from the handshake |
| mTLS client certs, VPN/IKE, EAP-TLS (Wi-Fi), device and IoT identity certs | Same structure; AUDIENCE shows clientAuth etc. |
| CT logs | Precertificates and final certs get the same GFMX (see normalization) |
| Code signing (Authenticode, macOS, drivers) | Extract the signer cert from the PKCS#7/CMS signature first |
| Android APK signing certs | Usually self-signed (keytool/apksigner); extract from the signing block |
| S/MIME, document signing, WebAuthn attestation | Extract from the CMS/attestation structure |
| CA certificates (roots, intermediates) | Work as is |

Not supported (not X.509): OpenSSH certificates, PGP keys, card-verifiable certificates (e-passports), raw public keys (RFC 7250), attribute certificates, CRLs. CSRs (PKCS#10) share name and extension encoding and could get a partial value (no serial, validity or issuer), but that is not defined yet.

Container formats need the certificate extracted first. The Go command-line tool opens PKCS#7/CMS, Authenticode PE and APK/JAR signatures and can carve certificates out of arbitrary binaries; PCAPs go through tshark (see `connectors/`). PKCS#12 is not opened (it is usually password-protected; `openssl pkcs12 -nokeys` converts it).

## Input requirements
- Input is the **certificate's DER bytes** (the Certificate message in the handshake, or any stored copy). Nothing from the ServerHello is used.
- Raw DER is required for MAKER: encoding traces, parameter encoding and extension order are lost once a certificate is parsed into fields. KEY, SPAN, AUDIENCE and NAMES could be rebuilt from detailed parsed fields, MAKER cannot.

## Format
```
KEY:SPAN:MAKER:AUDIENCE:NAMES
9f1c2a7b:51d0e3aa:3e8d0f14:c03d8e11:4f1a9c02
```
- 5 segments, each the first **8 hex** characters of SHA-256 over a canonical pre-hash string. 40 hex characters + 4 colons.
- Empty segment is written as nothing between delimiters (e.g. `9f1c2a7b:51d0e3aa:3e8d0f14::4f1a9c02`). Positional, never compressed.
- Always keep the colons. A bare 40-hex string is indistinguishable from a SHA-1 hash.
- 8-hex groups are not valid IPv6 groups, so the string will not be mistaken for an IPv6 address.
- Each segment is indexed as its own field, plus the full string. Store the pre-hash (raw) form alongside for debugging and near-match search, plus the unhashed info field (string-type choice, exact span, serial sign/padding).

## Segments
| # | Segment | Answers | Pre-hash contents | Empty when |
|---|---|---|---|---|
| 1 | KEY | What it is | Issuance class (self-signed / private CA / public CA; see "Issuance is checked for every algorithm"), public-key algorithm OID plus size or curve where applicable, signature algorithm OID (see "KEY is defined by algorithm OIDs") | Never |
| 2 | SPAN | How long it lives | Validity length and kind (see "Validity = length + kind" and "Validity is its own segment") | Never |
| 3 | MAKER | Who built it | X.509 version; encoding-rule violations (DER violations, time-encoding violations, wrong string type on fixed-type attributes); algorithm-parameter encoding *only where it deviates from the standard for that algorithm* (keeps MAKER independent of key type); issuer/subject relation (identical / issuer empty / different); extension OID list in order with critical flags (SAN and CT extensions excluded); serial construction; Subject/Authority Key ID methods; validity construction (whole days ±1 h / whole hours / whole minutes below 2 days / other, or `end` for a fixed end date; end offset such as −1 s; notBefore midnight-aligned or not) | Never |
| 4 | AUDIENCE | Who it is for | Sorted: EKU set, Key Usage bits, Basic Constraints (CA flag, path length), certificate policy OIDs and vendor template IDs, AIA/CDP presence and URI scheme | None of these extensions present |
| 5 | NAMES | Which fields the template fills | Issuer and subject attribute OIDs in order (multi-valued RDNs grouped) | Issuer and subject both empty |

Unhashed info (stored, not part of the string): the string-type choice (PrintableString vs UTF8String) where a name value allowed one, the exact validity span (e.g. `span=180d23:00:00`), and whether the serial was negative or non-minimally padded (`ser=neg`, `ser=pad`, or `ser=neg,pad` when both).

KEY and SPAN have small input spaces, so lookup tables can decode their hashes back to a readable form (e.g. "self-signed, RSA-2048, SHA-256" and "P1Y cal"). Ship that table with the spec.

## Decision: validity = length + kind
Tools compute notAfter in one of three ways:
- **Fixed duration:** `openssl -days`, `keytool -validity`, Go `time.Duration`, Python `timedelta`. Always the same number of days.
- **Calendar units:** Go `AddDate`, .NET `AddYears`/`AddMonths`, AD CS templates, Windows' RDP certificate (six months), mkcert (2 years 3 months). The day count depends on the start date: 1 year is 365 or 366 days, 6 months 181–184, 10 years 3651–3653.
- **Fixed end date:** RFC 5280's `99991231235959Z` ("no well-defined expiration", common on device certificates), the last UTCTime second, the 32-bit `time_t` limit.

SPAN carries two elements, `len` and `kind`:

| kind | When | len | Examples |
|---|---|---|---|
| `cal` | The day count is one that N calendar months can produce (any start date in a 400-year cycle, clamp or roll-over month-end convention) | `P…Y…M` | 365 or 366 → `P1Y`; 181–184 → `P6M`; 89–92 (incl. 90) → `P3M`; 393–397 (incl. 397) → `P1Y1M`; 3651–3653 → `P10Y` |
| `exact` | No calendar span produces it | Days, or hours/minutes/seconds below 2 days | 180 → `P180D`; 825 → `P825D`; 3650 → `P3650D`; 10 min → `PT10M` |
| `end9999` / `end2049` / `end2038` | notAfter is a known fixed end date | `-` | Device identity certs |
| `neg` | notAfter before notBefore | `-` | Broken 2050+ dates in UTCTime |

Lengths are rounded to the nearest unit (half up), which absorbs a −1 s end offset and the DST hour.

Why the kind is decided by the day count and not by the certificate's dates: a per-certificate test ("did this span need rounding?", "is notAfter the same calendar date N years later?") flips with the start date. A calendar-year tool gives 365 days in most years and 366 when the span contains Feb 29; a 365-day tool lands on the same calendar date unless the span contains Feb 29. Either test splits one of the two tools. Deciding by day count gives every certificate of a tool the same `len` and `kind`, whatever its start date.

The cost: a fixed-duration tool whose count calendar months can also produce (30, 90, 365, 397, 730 days) is labeled `cal` and merges with the matching calendar tool. One certificate cannot separate them, so no stable rule can. Every other count stays exact, which separates more than the old ±1-day year rounding did (`openssl -days 3650` is `P3650D`, a calendar 10-year tool is `P10Y`).

In MAKER, "whole days" accepts ±1 h because calendar math done in local time gains or loses the DST hour when the span crosses a DST change, and a fixed end date sets the construction to `end` (its span depends only on the start time).

## Decision: validity is its own segment (Oct 2026)
Validity used to be part of WHAT together with issuance, key and signature algorithm. A test on Android malware signing certificates (4,607 malicious APKs, 1,035 distinct signing certificates, family labels from a commercial malware feed) showed two things:
- **Validity is the single most informative element.** Without the shared public keys, the validity length alone agreed with the feed's family labels as well as the whole NAMES segment (V-measure 0.46 each; 234 distinct lengths). Most APK signers are Java keytool with default settings (one MAKER value across 28 families), and `-validity` is often the only setting the operator chose: the banbra and smsreg builders produce identical KEY, MAKER, AUDIENCE and NAMES and differ only in SPAN (40,000 vs 1,000 days).
- **Some builders randomize it.** msfvenom gives every APK signing cert a random period: its 161 certs spread over 168 WHAT values, while MAKER, AUDIENCE and NAMES stayed constant. With validity inside WHAT, the only way to recover the family was to skip WHAT and lose the key and signature algorithm with it.

So validity stays in the fingerprint as its own segment. A random period breaks SPAN only, and `KEY:*:MAKER:AUDIENCE:NAMES` matches all 161 msfvenom certs and nothing else in the set. Without the shared public keys, skipping SPAN keeps 120 clusters at 65% homogeneity, against 95 clusters at 59% when the old WHAT had to be skipped.

`kind` stays with `len` in SPAN. It is derived from the same day count, so a random length makes it random too: msfvenom's certs are 126 `exact` and 35 `cal`. Moving it to MAKER would have split MAKER.

Full matches are unaffected: re-fingerprinting the 1,035 Android signing certificates mapped every old value to exactly one new value and back (395 values before and after).

Recount with the current code (specification 1-draft, 15 Oct 2026): the figures above come from the prototype. With the current code, `a1371c39:*:65fa07e6::6bc11ca7` matches 167 signing certificates in this first run (4,607 samples), all labelled metasploit, and 150 in a second run on 4,924 samples from unseen families (labelled meterpreter or mesploit), and nothing else in either set. Every one of the 317 certificates has its own key. Other Metasploit-labelled samples in both runs were signed by different tools (mostly keytool defaults) and do not match, as expected.

## Decision: issuance is checked for every algorithm (Oct 2026)
The issuance class `s` requires the certificate's signature to verify under its own public key. The prototype first used `cryptography`'s `verify_directly_issued_by`, which refuses SHA-1, MD5 and DSA by policy. On the Android signing certificates that turned 2,774 of 4,607 rows (60%) into `n` ("same name, not self-signed") although every one of them was validly self-signed, so the KEY hash depended on the library and its version.

The check now verifies the signature directly with plain integer math: RSA PKCS#1 v1.5 (any digest, taken from the DigestInfo the signer embedded), RSA-PSS (hash and MGF from the parameters, salt length from the encoding), DSA, ECDSA on nine named curves, Ed25519 and Ed448. A signature algorithm, curve or digest that cannot be checked (e.g. GOST, SM2, ML-DSA today, binary or explicit-parameter EC curves) gives `u`, the same answer on every machine. After the change all 1,020 self-signed Android signing certificates are `s` and agree with an independent check; `testbench/selfsig_test.py` covers 34 algorithm and curve cases, wrong-key and damaged-signature cases, and two curves that must give `u`.

ECDSA and EdDSA first went through `cryptography`'s raw primitives. That still tied `u` versus `s` to the curves a given OpenSSL build supports (binary curves, for instance, come and go between builds), and it kept a third-party dependency in a tool meant to be embedded everywhere. Since Oct 15 they are verified with integer math too: the reference implementation has no dependency outside the Python standard library, and the curve list is part of the specification instead of a property of the library.

## Decision: KEY is defined by algorithm OIDs (post-quantum ready)
KEY's crypto inputs are the exact algorithm identifiers, not "key size + signature hash":
- `subjectPublicKeyInfo.algorithm` OID, plus RSA modulus size or EC named curve where those apply.
- `signatureAlgorithm` OID.

Why:
- "Size + hash" assumes RSA/ECDSA. ML-DSA (RFC 9881) has no separate hash and three fixed parameter sets; composite ML-DSA certs pair two algorithms under one OID; Merkle Tree Certificates replace the CA signature with `id-alg-mtcProof`. With OID inputs, each of these is just a new lookup-table entry, with no format change.
- Pre-standard (draft-era) Dilithium and composite OIDs hash differently from the final NIST OIDs (ML-DSA-44/65/87 = 2.16.840.1.101.3.4.3.17/18/19), so KEY also records library vintage.
- RSA-PSS vs PKCS#1 v1.5 is distinguished for free (different signature OIDs).

Post-quantum outlook for the other segments:
- NAMES and AUDIENCE: unchanged. ML-DSA certs only allow signing Key Usage bits (keyEncipherment is forbidden), so bit patterns shift but the segment works as is.
- MAKER: gains signal. ML-DSA AlgorithmIdentifier parameters MUST be absent, so libraries writing NULL out of RSA habit stand out; hybrid "alternative key" extensions land in the extension list; MTC serials follow a fixed `log_number << 48 | index` pattern (one new serial class).
- Long term, KEY will discriminate less once deployments converge on a few ML-DSA parameter sets; hunting weight should stay on MAKER, AUDIENCE and NAMES.
- Tooling/C2 certs are unlikely to migrate soon (their clients don't validate certs), so a post-quantum or composite cert on a non-web port is itself a rarity signal for years.

## Deliberately excluded
- SAN types and counts: depend on how the operator invokes the tool.
- Name values, value shapes, tool-default strings: instance data.
- CA identity: already a raw pivot.
- RSA exponent: too rare to earn space.
- Calendar vs fixed-duration counting as a per-certificate flag: failed the stability test. A one-year span only tells them apart when it crosses Feb 29, so the same tool flips with its creation date. The `kind` element replaces it with a rule that depends on the day count only (see "Validity = length + kind").
- Time types (UTCTime vs GeneralizedTime): failed the stability test. RFC 5280 switches type at 2050, so the type depends on creation date and validity, not on the library (a keytool 1-year cert and a keytool 27-year cert got different MAKERs). Only violations of the rule are flagged.
- String-type choice (PrintableString vs UTF8String): failed the test bench. It is only visible when a name value fits PrintableString; when every value in a cert contains `_`, `@`, `&` or non-ASCII, the choice is hidden and MAKER split (15 split blueprints across the first 20 runs). Moved to unhashed info. Removing it did not merge any of the real tools tested (OpenSSL, Go, Python, keytool still have distinct MAKERs).
- Serial sign: failed the stability test. A tool that writes raw random bytes as the serial gets a negative serial whenever the top bit is set, so one template gave two MAKER values (11 `r8`, 9 `n8` in a 20-cert test). Serial classes now use the magnitude; a negative serial is recorded as `ser=neg` in the unhashed info.
- Serial padding: failed the stability test for the same reason. Whether a serial's INTEGER is minimally encoded depends on its random value: a tool that writes 8 raw random bytes was non-minimal (`enc=int`) for 12 of 2,000 certs, and one that always prefixes 0x00 for 1,033 of 2,000. The serial is left out of the INTEGER check and a padded serial is recorded as `ser=pad` in the unhashed info. Non-minimal INTEGERs elsewhere in the certificate still set `enc=int`.
- Whole minutes on spans of 2 days or more: failed on real data. When a CA's notBefore and notAfter seconds are unrelated (reissue to a fixed end date, random backdating), one cert in 60 has a whole-minute span by chance (twice that with the −1 s variant), which gave ~3% of such certs a different MAKER (Sectigo DV E36: 7 of 225 in a CT sample). The minute class is kept below 2 days, where short-lived tools (e.g. Fulcio's 10 minutes) use it on purpose. The whole-hour class has the same effect at 1 in 1,800, which was left in.
- Served chain, SNI/serving behavior, QUIC transport: endpoint properties, not template properties.

## Normalization rules (to keep segments stable)
- Extension list (MAKER) skips SAN and both CT extensions: the precertificate poison (1.3.6.1.4.1.11129.2.4.3) and the embedded SCT list (1.3.6.1.4.1.11129.2.4.2). A CT precertificate carries one, the final certificate the other; skipping both gives the same GFMX whether the cert came from a CT log or a scan.
- Serial: classes are taken from the magnitude, so the sign does not count (see "Deliberately excluded"): `z` zero, `t` timestamp-like (seconds, ms or ns within 2 days of notBefore), `s` small (≤32 bits), otherwise `r` + width, where width is the bit length rounded up to a multiple of 32 bits, in bytes (`r8`, `r16`, `r20`). Random serials of any value land in the same class.
- Attributes with a string type fixed by the standards (C, serialNumber, dnQualifier, emailAddress, DC): a wrong type is an encoding flag in MAKER.
- notBefore alignment: coarse classes only (midnight-aligned vs not).
- SPAN is `len` + `kind`, see "Validity = length + kind". The exact span goes to unhashed info.

## Decision: two implementations, one set of vectors (Oct 15 2026)
A fingerprint is only useful if every tool computes the same value. Two implementations exist: the reference `gfmx.py` (Python standard library only, readable, importable in Ghidra, sandboxes and notebooks) and `go/gfmx` (Go, for scanners: about 9,000 certificates per second per core on real certificates, against about 140 for the reference). The Go package is also built as a C library (`go/capi`) for native plugins.

They are held together by `testdata/vectors.jsonl` (448 certificates with their expected fingerprint, pre-hash strings and info, 45 of them parse errors) and by differential testing: the two implementations agreed on every one of more than 200,000 structurally mutated certificates (all differential runs combined) (duplicated and deleted elements, wrong tags, non-minimal lengths, odd times, hostile OIDs), the 1,035 Android signing certificates, the system root store and the test bench output. Porting found the following, all fixed in both implementations and in the vectors:

- **KEY ignored DSA and RSA-PSS key sizes.** Only rsaEncryption keys got a size, so DSA-1024 and DSA-2048 certificates shared a KEY (old and new `keytool` defaults differ exactly there). KEY now records p's size for DSA keys and the modulus size for RSA-PSS keys. On the Android set this changed 24 DSA-1024 values one-to-one, with no merges or splits.
- **Unbounded numbers in pre-hash strings.** Python refuses to print integers over 4,300 digits and its big-integer handling is quadratic, so a crafted OID arc, version or pathLen could either fail the certificate in Python only or cost seconds. OID arcs encoded in more than 64 bytes now render as `x` (UUID arcs under 2.25 need 19), and version and pathLen contents over 8 bytes render as `x`.
- **DSA cost.** With p up to 16,384 bits one crafted certificate cost about 0.1 s even in Go. FIPS 186 DSA stops at 3,072 bits, so p over 4,096 bits now gives `u`.
- **RSA-PSS.** An encoded message longer than emLen raised an exception (a parse error for the whole certificate); RFC 8017 calls it an invalid signature, so it now gives `n`.
- **Duplicate extensions** (forbidden by RFC 5280) silently used the last copy. They now set the `enc` flag `dupext` and the first copy is used, as most validators do.
- The CLI's input handling (PEM variants, hex and base64 lines, what counts as a line) was aligned so both tools split the same input into the same certificates.

## Decision: post-quantum certificates (Oct 15 2026)
ML-DSA, ML-KEM, hybrid and Merkle Tree certificates were generated (ML-DSA-44/65/87 self-signed, ML-DSA-signed EC and ML-KEM leaves, ECDSA certificates carrying an ML-DSA alternative key, Merkle Tree Certificates with different logs and indexes) and run through both implementations. KEY told the three ML-DSA parameter sets apart and MAKER stayed the same across them, as designed. Four changes followed:

- **ML-DSA self-signatures are verified.** Every self-signed ML-DSA certificate was `iss=u`, so a valid and a damaged self-signature looked the same. ML-DSA.Verify (FIPS 204, empty context as RFC 9881 requires) is now implemented with integer math in both implementations, like every other algorithm: 5 to 10 ms in Python, 0.2 to 0.4 ms in Go. It agreed with an independent implementation (`cryptography` 50) on 300 certificates (self-signed, signed by another key, corrupted signatures including the hint encoding) and on 75 valid and 225 invalid raw signatures. HashML-DSA, SLH-DSA and composite signatures still give `u`.
- **ML-KEM keys are in the parameter table.** Their parameters must be absent; they used to read `algp=?a` (no expectation), now `std`, and a library writing NULL shows `a>n`. A KEM key cannot sign, so an ML-KEM certificate is always issued by another key (`iss=i`).
- **Hybrid certificates show both algorithm pairs.** With the X.509 alternative-key extensions (2.5.29.72, 2.5.29.73) KEY gets `;alt=<alt key>/<alt signature>`, and MAKER's parameter check covers the alternative algorithms too. Without it, KEY showed only the classical half. The item is added only when those extensions exist, so no other value changed for it.
- **Merkle Tree Certificates are prepared for.** draft-ietf-plants-merkle-tree-certs-07 (Oct 2026) uses id-alg-mtcProof (1.3.6.1.5.5.7.6.67) as the signature algorithm and (log number << 48) | index as the serial. The serial class is `mtc` for them, because the serial's size depends on the log number and the index, and MAKER ends with `mtc=` (`log` for these certificates, empty for all others). The log number and index go to the unhashed info (`mtc=3/12345`): the index is different on every certificate, and the log number identifies the issuing log, much like a CA name. Certificates from different logs and indexes get the same value.

Appending `;mtc=` to MAKER changed every MAKER value once. The published examples were updated (keytool's MAKER `03e8b5b3` is now `96d5c677`, msfvenom's `8d872b64` is now `65fa07e6`, OpenSSL `req -x509` is `28505f23`); no two values merged or split.

Draft-era OIDs (pre-standard Dilithium, Open Quantum Safe provider builds, composite drafts) need no code: KEY's pre-hash string already holds the raw OIDs, and a separate lookup table for analysts maps them to names (open item 5). The generator never consults it.

## Decision: limits for scanner input (Oct 16 2026, specification 1-draft.2)
An audit with crafted certificates found three inputs whose cost grew with their size, faster than linearly in two cases. None occurs in a real certificate, and no conformance vector or real certificate changed value (checked on 300,000 unique certificates from one day of Driftnet scanning):

- **Merkle Tree serial.** The log number was printed in decimal at any size: a 16 MB serial cost 50 s and 409 MB in Go, and the reference failed past about 1,790 bytes (Python's 4,300-digit limit), so the two disagreed. A log number over 64 bits now renders as `x`, like every other rendered integer.
- **OID arc count.** Arcs were capped at 64 bytes each but their number was not: an 8-million-arc signature OID cost 2.5 s and 5.7 GB of allocation in Go, and the rendered OID went into KEY at full length. An OID with more than 128 arcs now renders as `x` (real OIDs have under 20).
- **DSA g and y.** Only p and q were capped; a 1 MB g or y was reduced mod p in about 0.25 s. g or y longer than p now gives `u`, as an oversized p does.

After the change the same inputs take 0.01 to 0.02 s in Go and about 0.15 s in the reference, and both give the same result. The Go reader's nesting limit is now 64, the same as the reference (section 3.1 of the spec). It had been 500 as an interim, which left certificates nested 65 to 500 levels deep with a value in Go and a parse error in Python. For provenance a certificate must get one answer whichever implementation reads it, so both stop at 64; real certificates nest about a dozen levels.

## Decision: data after a name attribute's value (Oct 26 2026, specification 1-draft.3)
A Driftnet scan of a 2Wire home gateway (Arris/2Wire HomePortal, port 51001) failed with a parse error. The subject's commonName is `30 14 06 03 55 04 03 16 00` followed by the device's own IP address: the firmware appends the IP and fixes the SET and SEQUENCE lengths, but leaves the IA5String's length at 0. Strict DER readers reject it (OpenSSL, Python `cryptography`, both GFMX implementations); Go's `crypto/x509` ignores the extra bytes and shows an empty commonName. About 42,800 services carried this gateway's banner in ten days of Driftnet scanning.

The defect is a fixed trait of one firmware, which is what MAKER's encoding flags exist to record, so it is now read instead of rejected (spec 3.1.1): the attribute keeps its type and value, the tail is ignored, and MAKER gets `atvtrail`. The tolerance is deliberately narrow. The lenient reading runs only after the strict one fails, accepts a tail only inside an issuer or subject attribute, and falls back to the strict error for anything else. Names contribute only attribute types, so the IP address never reaches a pre-hash string, and every gateway of the family gets one value whatever its address.

No certificate that 1-draft.2 accepts changed value: the vectors, 2,151 locally generated test certificates, 2,151 Android signing certificates and 99,107 of 99,149 mutants gave byte-identical output (errors included) before and after; the other 42 mutants, the 2Wire certificate and one built example moved from a parse error to a value with `atvtrail`. The one-day Driftnet corpus (999,866 certificates, open item 2) had no parse errors, so none of it can change. Vectors `quirk/` hold the gateway's certificate (its address replaced by 198.51.100.17, and its serial number, public key and signature by neutral bytes of the same length, none of which changes the value) and five certificates with the same defect outside a name, which stay errors.

## Prototype v0 results (Oct 2026)
Prototype: `gfmx.py` (Python, own DER reader). Pre-hash strings are printed with `--raw`.

### Real tools
32 generated self-signed TLS-style certs with randomized names from 5 generators, 6 non-TLS certs, and 128 public root CAs:

| Tool | GFMX |
|---|---|
| OpenSSL `req -x509`, RSA | `ec009cbb:317621f9:d3da824d:9f86176d` |
| OpenSSL, ECDSA | `76f29026:317621f9:d3da824d:9f86176d` |
| Go `crypto/x509`, RSA | `ec009cbb:2a7d13da:a7a2f673:3209853a` |
| Go, ECDSA | `76f29026:2a7d13da:55788719:3209853a` |
| Python `cryptography` (3650 days) | `2f686cf1:4d05ac63:595c724b:9f86176d` |
| Java `keytool` (1-year TLS cert) | `dde6732d:0696577a::9f86176d` |
| Java `keytool` (10000-day APK signing cert) | `894d2797:0696577a::9f86176d` |
| Sigstore Fulcio (npm provenance, 10 min) | `e74cdd36:6cd06c1f:3d7148d3:eca5d7e7` |

(These are 4-segment values from before SPAN was split out of WHAT; the first segment then held KEY and SPAN together. MAKER, AUDIENCE, NAMES and every grouping are unchanged.)

- **Stable within each tool:** every generator gave one GFMX across all its certs despite random names.
- **MAKER separates tools:** OpenSSL, Go, Python `cryptography` and `keytool` each got a distinct MAKER.
- **Key type changes only WHAT (now KEY):** OpenSSL and Go with RSA vs ECDSA kept the same MAKER (Go's AUDIENCE also changed, correctly, because it adds keyEncipherment only for RSA).
- **Randomized name fields change only NAMES:** Go certs with random field presence (Sliver-style) kept WHAT (now KEY and SPAN), MAKER and AUDIENCE stable.
- **Same tool across uses:** keytool's TLS cert and APK-signing cert share a MAKER; only the validity (now SPAN) differs.
- **Same issuing template, different purposes:** code-signing, mTLS client and S/MIME certs from one test CA share a MAKER and differ in AUDIENCE.
- **CT:** a precertificate and its final certificate got identical GFMX values.
- **Real certs:** 128 public roots parsed with 0 errors; one root uses GeneralizedTime before 2050 (flagged). A hand-made non-DER BOOLEAN was flagged in MAKER.
- NAMES alone is weak: OpenSSL, Python and keytool samples shared the same NAMES value (C, O, CN). MAKER is what separates them.

### Test bench (blueprint + noise)
Scripts: `testbench/` (`gen_certs.py`, `noise.py`, `match.py`, `run_test.sh`).
- The generator picks a **blueprint** (stable configuration: key, signature hash, issuance, validity, notBefore alignment, end offset, serial style, string-type policy, subject template, extension list/order/criticality/contents) and `noise.py` fills instance data: new key, serial value, name values (10–60% with non-PrintableString characters), notBefore anywhere in 2000–2049 (periods cross Feb 29, DST changes and 2050), SAN on/off at a random position, URL hosts.
- Validity in a blueprint is a length plus how the tool counts it: fixed days (7 … 10000), calendar months (1, 3, 6, 12, 24, 27, 120; clamp or Go-style roll-over at month end), fixed seconds (10 min, 1 h, 12 h) or a fixed end date (9999, 2049). Day and month arithmetic may run in local time (Berlin, New York, Sydney) and be converted to UTC, like .NET `DateTime.Now.AddYears()`. A "validity counting" mutant keeps the length and changes only how it is counted (e.g. 365 days ↔ 12 months, clamp ↔ roll-over, UTC ↔ local time); the fingerprint must not move.
- Configurations switch between batches: **fresh** blueprints, **one-parameter mutants** of earlier blueprints, and **revisits**. Certificates are written under blind random names.
- `gfmx.py` fingerprints the folder without any knowledge of the generator; `match.py` joins the two tables. Pass = one fingerprint per blueprint, no unexpected merges, and every in-scope one-parameter change detected.

Results with the 5-segment layout (Oct 13; 28 runs, 90 blueprints each): **16,690 certificates, 2,520 blueprints, 0 splits, 0 unexpected merges, 1,076/1,076 one-parameter changes detected, 0/62 same-length validity changes moved the fingerprint.** Validity-length changes moved SPAN (and MAKER when the construction also changed) and never KEY; key, signature-hash and issuance changes never moved SPAN.

Earlier 4-segment results over 28 runs (20 with 3–7 certs per batch, 8 with 15–30 per batch): **12,522 certificates, 1,040 blueprints, 0 splits, 0 unexpected merges, 427/427 one-parameter changes detected, 0/21 same-length validity changes moved the fingerprint**. Validity mix: 418 day-count, 352 calendar-month, 171 sub-day and 99 fixed-end blueprints; 381 did their date math in local time. Calendar blueprints hit every possible day count (e.g. 6 months: 181–184, plus the DST hour).

| One-parameter change | Detected (4-segment run) | Segment that moves (5-segment names) |
|---|---|---|
| Key type/size | 32/32 | KEY (AUDIENCE when Key Usage follows key type) |
| Signature hash | 15/15 | KEY |
| Validity length | 38/38 | SPAN (MAKER when the construction also changes) |
| Issuance (self/CA) | 27/27 | KEY, MAKER, NAMES |
| notBefore alignment | 28/28 | MAKER |
| End offset (−1 s) | 28/28 | MAKER |
| Serial style | 42/42 | MAKER |
| Extension order | 33/33 | MAKER |
| Extension criticality | 35/35 | MAKER |
| Extension added / removed | 61/61 | MAKER, AUDIENCE |
| Extension contents | 46/46 | AUDIENCE (MAKER for key-ID methods) |
| Subject template | 42/42 | NAMES |
| Validity counting, same length (365 days ↔ 12 months, clamp ↔ roll-over, UTC ↔ local time) | 0/21 | must not move, by design |
| String-type policy | 0/35 | (out of scope, by design) |

The bench caught two fragile elements: the string-type choice on its first runs (see "Deliberately excluded"), and validity once calendar-month, DST and fixed-end generators were added. The previous validity rule (±1-day year rounding, whole-day construction without DST tolerance) kept one fingerprint for only 14 of 30 blueprints on one of the new runs, splitting in WHAT, now SPAN (e.g. 3 calendar months as `91d` and `92d`) and in MAKER (`day` vs `hr` across DST).

Earlier result with the previous validity rule and the day-count-only generator: 20 runs, 7,065 certificates, 800 blueprints, 0 splits, 519/519 changes detected. Limitation: all bench certificates come from one library (Python `cryptography`), so encoding-level differences between libraries are covered by the real-tool tests, not the bench.

Limitations:
- Issuance class is `s` / `n` (same name, not self-signed) / `u` (same name, algorithm cannot be checked) / `i` (issued). Splitting `i` into public vs private CA needs a public-CA key-ID list (e.g. from CCADB).
- The reference CLI reads PEM, DER and hex/base64 lines; containers (PKCS#7, PE, APK/JAR) and carving are in the Go CLI.
- Live `--host` mode must run from a normal network; a TLS-intercepting proxy will substitute its own certificates.
- Hostile input: scan data is attacker-controlled. The DER reader rejects nesting deeper than 64 levels in both implementations (a crafted cert otherwise exhausted the stack), and the self-signature check gives `u` for RSA moduli over 16,384 bits, RSA exponents over 64 bits, DSA p over 4,096 bits, DSA q over 512 bits, and DSA g or y longer than p (a crafted 32,768-bit key with a same-size exponent otherwise took 33 s for one cert). A batch run records any per-cert failure as a parse-error row and carries on. An impossible date (e.g. `000000000000Z`) no longer fails the certificate: it sets `tfmt` and gives SPAN `len=?;kind=?`.

## Open items
1. Freeze the canonical pre-hash strings: written down as [SPEC.md](SPEC.md) version 1-draft.3 with conformance vectors.
2. ~~Run the stability test on real families~~: done on one day of Driftnet scan data (999,866 distinct certificates from 1,647,882 hosts, Oct 2026) against products, builds, appliances, device classes, protocols, mail servers, operators and CAs, and on 2,068 Android malware signing certificates in 58 families. C2 frameworks still need a labelled sample.
3. ~~Measure distinct values per segment on the Driftnet corpus~~: done on the same 999,866 certificates (35,623 distinct values). Distinct values per segment: KEY 156, SPAN 6,323, MAKER 4,187, AUDIENCE 2,383, NAMES 2,215; no hash collision. At 6,323 values the chance of any 8-hex collision in a segment is under 0.5%, so 8 hex is enough at this scale; recheck SPAN on a full-scan count.
4. ~~Decide whether validity stays in WHAT~~: done, it is now the SPAN segment (see "Validity is its own segment").
   - Still unhandled in SPAN: tools that set notBefore to "now" and notAfter to the end of the last day (23:59:59), and fixed end dates other than the three known ones. Both make the span depend on the start time; look for them in Driftnet data.
   - Seen in CT data (Oct 2026): CAs that reissue to a fixed end date (Microsoft Azure, Sectigo) spread one profile over 10 to 18 SPAN values (e.g. 88, 87, 86, 85 days). No per-certificate rule can recover the length; hunts on these issuers should wildcard SPAN.
5. Build the KEY and SPAN lookup tables (including post-quantum, composite and MTC algorithm OIDs).
6. Backfill needs the raw certificate: a scan pipeline that keeps only parsed fields cannot compute MAKER for past data.
7. ~~Add certificate extraction for PKCS#7/CMS, PE (Authenticode) and APK signing blocks, and TLS 1.2 certificates from PCAPs~~: done in the Go CLI and `connectors/` (tshark, Suricata, Zeek). Still open: Linux kernel module and macOS code signatures, PKCS#12.
8. Extend the test bench with a second generator library (e.g. Go or OpenSSL) so encoding-level elements are exercised under noise too.
9. Candidate MAKER/NAMES elements found during review, each needing a test-bench noise run before it can be hashed: KU BIT STRING not trimmed to its last set bit (a DER violation that is constant per template); a coarse value shape per name field (length range and character class), which the APK study showed would separate keytool-default builders that share NAMES today. Rejected on review: unsorted SET OF in multi-valued RDNs, because whether a non-sorting library's output happens to be sorted depends on the values.
