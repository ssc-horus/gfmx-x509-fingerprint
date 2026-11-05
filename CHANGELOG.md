# Changelog

## Unreleased

No fingerprint value changes; specification unchanged.

- Licensed under the Sustainable Use License 1.0 (`LICENSE.md`, SPDX `SUL-1.0`); GFMX is patent pending.
- The public repository is read-only and takes no outside contributions (`CONTRIBUTING.md`).
- Conformance vector `quirk/name-tail-2wire-gateway.der`: the device's serial number, public key and signature are replaced by neutral bytes of the same length. Its value, pre-hash strings and info are unchanged.

## 0.9.10: specification 1-draft.3

Values change only for certificates that 0.9.9 rejected; every certificate 0.9.9 fingerprints keeps its value.

- Certificates whose issuer or subject attribute carries data after its value (2Wire home gateways append their IP address to a zero-length commonName) are fingerprinted instead of rejected, with the new MAKER flag `atvtrail` (spec 3.1.1). The same defect anywhere else in a certificate is still a parse error, with the same message as before.
- 8 new conformance vectors (`quirk/`): the gateway's certificate with its address replaced, two built examples, and five certificates with the defect outside a name, which stay errors.

## 0.9.9: specification 1-draft.2

No fingerprint value changes; specification and conformance vectors unchanged.

- Connectors report each certificate with `gfmx`, or `gfmx` null and the reason in `gfmx_error`, and none decides which side of a connection is the server or the client:
  - PCAP script: rows carry the packet's `src`, `src_port`, `dst`, `dst_port` instead of `server`, `port`, `client` (a mutual-TLS client certificate was reported as the server's); `error` is now `gfmx_error`; a truncated capture is read as far as tshark gets, with a warning, instead of failing with no output.
  - Suricata: `tls.gfmx_error` and `tls.gfmx_chain_errors` when a certificate cannot be fingerprinted.
  - Zeek: the script logs only Zeek's `fuid` and `uid` (the `resp_h` and `resp_p` columns are gone; join to Zeek's own logs for roles); the enricher adds `gfmx_error` and passes lines it cannot read through unchanged.
- Connector tests in CI on captures and logs in `connectors/testdata/` (PCAP, Suricata, Zeek enricher, MISP object schema, Ghidra carving), the Zeek script in Zeek 7.0, and a manual headless Ghidra workflow.
- `--host` offers every TLS version and cipher suite the build still has, so servers that speak only TLS 1.0 or RSA key exchange answer (Go stopped offering RSA key exchange by default in 1.22 and 3DES in 1.23; Python used OpenSSL's default security level). New `--sni NAME` for IP targets, in Go and Python.
- README: what a shared segment tells you, how to choose wildcards, and that a match names a template, not an owner.
- CI: actions pinned by commit; Python 3.11.17 and 3.15.0; Go 1.24.13 (go.mod's minimum) and 1.27.2. Release workflow: tags `vX.Y.Z` build the command-line tool for Linux, macOS and Windows and the C library for Linux, with checksums.

## 0.9.8 (not tagged): specification 1-draft.2

- Specification written down in `docs/SPEC.md`, with 440 conformance vectors in `testdata/vectors.jsonl`.
- Go implementation (`go/gfmx`), command-line tool (`go/cmd/gfmx`) and C library (`go/capi`), byte-identical to the reference; about 9,000 certificates per second per core.
- Certificate extraction in the Go CLI: PKCS#7/CMS (DER, BER and PEM), Authenticode PE, APK/JAR (v1, v2, v3, v3.1, lineage, source stamp, split bundles, broken central directories), carving from arbitrary binaries.
- Connectors: PCAP script (tshark), Suricata eve enricher, Zeek script, Ghidra script, MISP object template.
- Reference implementation has no dependencies: ECDSA (nine named curves), Ed25519 and Ed448 self-signatures are verified with integer math.
- Output changes against the prototype (all other values unchanged):
  - KEY records DSA p size and RSA-PSS modulus size.
  - OID arcs over 64 bytes render as `x`; version and pathLen over 8 bytes render as `x`.
  - DSA p over 4,096 bits, unsupported or explicit EC curves give `iss=u`.
  - New MAKER flag `dupext` for repeated extensions (first occurrence used).
- Post-quantum: ML-DSA-44/65/87 self-signatures verified with integer math (FIPS 204, RFC 9881); ML-KEM keys in the parameter table; hybrid certificates add `alt=<alt key>/<alt signature>` to KEY; Merkle Tree Certificates (id-alg-mtcProof) get serial class `mtc`, MAKER item `mtc=` and the log number and index in info. Every MAKER value changed once (new trailing `mtc=` item).
- CLI: stdin input, hex/base64 line input, `--json`, IPv6 `--host`, `sha256` and `error` columns, exit status 1 when a certificate cannot be parsed and 2 for unreadable input.
- Python 3.11 or later (3.9 and 3.10 no longer get security fixes); build requirement setuptools 84.0.0 (75.8.0 had CVE-2025-47273 and CVE-2026-59890).
- DER nesting is limited to 64 levels in both implementations (Go had accepted 500 as an interim, so certificates nested 65 to 500 levels deep got a value in Go and a parse error in the reference; they are now a parse error in both). The Go container reader no longer drops every certificate in a PKCS#7, APK v1 signature or Authenticode signature when one of them is nested deeper than 48 levels or malformed inside: that certificate is passed on whole and gets its own result.
- Specification 1-draft.2 (hostile input only; no vector or real certificate changed): an OID with more than 128 arcs renders as `x`; a Merkle Tree log number over 64 bits renders as `x` in info (Python and Go used to disagree there); DSA g or y longer than p gives `iss=u`. Eight new conformance vectors (`hostile/`) cover each limit and the value just inside it.
- Name: GFMX, the X.509 member of the GFM fingerprint suite. Command `gfmx`, Python module `gfmx` (package `gfmx-x509`), Go module `github.com/ssc-horus/gfmx-x509-fingerprint/go` (package `gfmx`, command `go/cmd/gfmx`), C library `libgfmx` (`gfmx_json`, `gfmx_free`, `gfmx_version`), JSON field `"gfmx"` in the CLI output, the conformance vectors and every connector. No value changes.
- Version 0.9.8, for development use; `gfmx --version` reports the specification version in Python too, as in Go and the C library.
- Go: about 2.2x faster on issued certificates with about 85% fewer allocations (OID fast path, slab-allocated DER nodes); `Error.Kind` (malformed, depth, internal) for callers that count failures.
- Loader and CLI: OpenSSL `TRUSTED CERTIFICATE` blocks fingerprint like the plain certificate (trust settings no longer raise `trail`); an unreadable folder is reported and the run continues with exit status 2; a failed `--csv` write exits 2 with a message instead of a traceback (Python) or a false success (Go).

## Prototype (Oct 2026)

- 5-segment layout KEY:SPAN:MAKER:AUDIENCE:NAMES; validity as length + kind; self-signatures checked for every algorithm; MAKER stabilised against hostile certificates.
