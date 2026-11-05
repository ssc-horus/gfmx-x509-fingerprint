# Connectors

Ways to get GFMX into the tools people already use. Every connector produces the same fingerprint, because they all call one of the two implementations that share the conformance vectors in `testdata/`: the reference `gfmx.py` (standard library only) or the Go package (`go/gfmx`, also exposed as a C library).

## Status

| Tool | What it does | Where | Status |
|---|---|---|---|
| **Command line (Go)** | Certificates from PEM, DER, PKCS#7/CMS (.p7b, .p7s, Windows .cat), signed APK/JAR (v1, v2, v3, v3.1, key-rotation lineage, source stamp, split bundles, broken central directories), Authenticode PE (.exe, .dll, .sys), live TLS servers, and `--carve` for certificates embedded anywhere in a binary | `go/cmd/gfmx` | Built, tested |
| **C library** (`libgfmx.so` / `.a`) | `gfmx_fingerprint()`, `gfmx_json()` for C, C++, Rust or any FFI: the base for native Zeek, YARA or sandbox plugins (see Licensing) | `go/capi` | Built, tested with a C program |
| **PCAP files** | Runs tshark and writes one row per certificate (JSON lines or CSV) with the packet's frame, time, TCP stream, source and destination address and port, chain position and the stream's SNI; reads truncated captures as far as they go | `tshark/gfmx_pcap.py` | Tested in CI |
| **Suricata** | eve.json filter adding `tls.gfmx`, `tls.gfmx_chain` and, when one fails, `tls.gfmx_error` / `tls.gfmx_chain_errors`; config fragment that makes Suricata log the certificate and chain | `suricata/` | Filter tested in CI; tested on Suricata 7.0 |
| **Zeek** | Script logs each certificate's DER with Zeek's file and connection IDs (`gfmx_der.log`); `zeek_gfmx.py` adds `gfmx` and `gfmx_error` columns (TSV or JSON logs) | `zeek/` | Script tested in CI (Zeek 7.0); enricher tested in CI |
| **Ghidra** | PyGhidra script: finds certificates embedded in the loaded program, bookmarks them and comments each with its fingerprint | `ghidra/GFMXCertificates.py` | Carving tested in CI; headless Ghidra run: manual workflow `ghidra` |
| **MISP** | Object template `gfmx` (fingerprint, wildcard pattern, segments, raw strings, certificate hashes, attributed tool) | `misp/gfmx/definition.json` | Validated against MISP's object schema and loaded with PyMISP in CI; not yet imported into a MISP server |

## What every connector reports

- One record per certificate it sees, in the order it sees them, with that tool's own context (packet, flow, file or connection IDs, time).
- `gfmx` when the certificate can be fingerprinted; otherwise `gfmx` is null (`-` in Zeek TSV) and `gfmx_error` says why: not base64, not a certificate, or the parser's reason. Nothing is dropped and nothing is guessed. A missing `gfmx` tool is reported as such, not as a bad certificate.
- No connector decides which side of a connection is the server or the client. The PCAP rows carry the packet's source and destination; Zeek rows carry Zeek's `fuid` and `uid`, which join to `x509.log`, `files.log`, `ssl.log` and `conn.log`, where Zeek records the roles. The platform reading the output applies its own logic.
- Test captures and logs are in `testdata/` (`make_fixtures.sh` rebuilds the captures); `tests/test_connectors.py` checks all of the above.

TLS 1.3 and QUIC encrypt the server certificate, so passive tools (tshark, Zeek, Suricata) only see certificates from TLS 1.2 and earlier unless the traffic is decrypted (e.g. `tshark -o tls.keylog_file:keys.log`). Active scanning (Driftnet) and file-based sources are not affected.

## Quick use

```bash
# files, folders, containers
gfmx --json app.apk signed.exe bundle.p7b certs/
gfmx --carve implant.bin firmware.img

# packet captures
python3 connectors/tshark/gfmx_pcap.py --gfmx-bin ./gfmx cap.pcapng > certs.jsonl

# Suricata (merge connectors/suricata/suricata-gfmx.yaml into your eve-log config)
python3 connectors/suricata/eve_gfmx.py eve.json | jq 'select(.tls.gfmx != null)'

# Zeek
zeek -r cap.pcap connectors/zeek/gfmx.zeek && python3 connectors/zeek/zeek_gfmx.py gfmx_der.log

# certificate streams (one base64 or hex certificate per line on stdin)
some-ct-feed | jq -r '.data.leaf_cert.as_der' | gfmx --json -
```

Set `GFMX_BIN` if the `gfmx` binary is not on `PATH`.

## Licensing

GFMX is under the [Sustainable Use License 1.0](../LICENSE.md). The connectors for GPL tools (tshark, Suricata) keep GFMX in its own process: they run tshark or read Suricata's `eve.json` and pass certificates to `gfmx` as data, so no GPL code is combined with GFMX. A connector that runs inside a GPL program (a Lua script on its API, a plugin linking `libgfmx`) would have to be GPL itself, and GFMX's license does not allow that; such connectors are not part of this repository. Native plugins for tools under permissive licenses (Zeek, YARA) can link `libgfmx`.

## Planned or proposed

Ordered by how directly they serve the two lead use cases (internet scanning and malware certificates).

| Tool | Approach |
|---|---|
| **ZGrab2 / zcrypto, ZMap ecosystem** | Go module, one call per certificate; adds a `gfmx` field next to the existing parsed certificate |
| **Certificate Transparency** (certstream, crt.sh, Google CT logs) | Stream leaf DER into `gfmx -`; precertificates and final certificates already get the same value |
| **Censys / Shodan exports** | Both expose raw certificate DER in bulk exports; batch through the CLI |
| **Arkime** | Arkime keeps certificate fields per session; a plugin via `libgfmx` or a post-processing job on PCAP |
| **Zeek native** | Zeek plugin linking `libgfmx`, adding `gfmx` straight to `x509.log` (removes the DER log) |
| **CAPE / Cuckoo sandboxes** | Processing module: fingerprint Authenticode signers of samples and dropped files, and certificates in sandbox traffic |
| **VirusTotal / YARA** | YARA module on `libgfmx` exposing `gfmx.fingerprint` for PE signers; VT Intelligence enrichment via the CLI on downloaded samples |
| **IDA Pro, Binary Ninja** | Same carving as the Ghidra script, on IDAPython / Binary Ninja Python |
| **binwalk / unblob** | Firmware extraction plugin: carve certificates from unpacked images (device identity and update-signing certs) |
| **Velociraptor, osquery** | Endpoint hunting: Authenticode signers and certificates in files on disk, collected fleet-wide |
| **Elastic, Splunk, OpenSearch** | Ingest processor / app that adds `gfmx` and segment fields to existing TLS and file-signature data |
| **OpenCTI / STIX 2.1** | Custom property on `x509-certificate` observables (`x_gfmx`) and an indicator pattern convention for wildcarded values |
| **Maltego** | Transforms: certificate → GFMX → other hosts and samples with the same template |
| **Android tooling** (apksigner, Androguard, MobSF) | Signing-certificate fingerprint next to the certificate hash in reports |
