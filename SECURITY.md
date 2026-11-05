# Security

GFMX parses certificates taken from the internet, from malware and from packet captures, so the parsers are attack surface. Reports of crashes, hangs, excessive CPU or memory on crafted input, or inputs where the Python and Go implementations disagree are welcome.

Please report privately through GitHub's **Report a vulnerability** button on the repository's Security tab. Include the input (base64 is fine) and the command you ran.

What is already bounded, and must stay bounded:
- DER nesting depth (64 levels in both implementations; the Go container reader expands 48 levels and keeps anything deeper whole), OID arc length (64 bytes) and arc count (128), rendered integer size (8 bytes, including the Merkle Tree log number).
- Self-signature checks: RSA moduli up to 16,384 bits with exponents up to 64 bits, DSA p up to 4,096 bits, q up to 512 bits, and g and y no longer than p; anything larger is not verified (`iss=u`).
- The Go library recovers from any internal panic and reports it as a parse error.
