#!/usr/bin/env bash
# Rebuild the connector test captures. Needs openssl and python3.
# Not run in CI: the captures are committed. Certificates are throwaway test certificates.
#
#   mtls.pcap     one TLS 1.2 handshake with mutual authentication and SNI: the server
#                 sends a leaf and its CA, the client sends its own certificate
#   badcert.pcap  a Certificate message whose only entry is not a certificate
set -euo pipefail
cd "$(dirname "$0")"
T=$(mktemp -d); trap 'rm -rf "$T"; kill $(jobs -p) 2>/dev/null || true' EXIT
o() { openssl "$@" 2>/dev/null; }
o req -x509 -newkey rsa:2048 -nodes -keyout "$T/ca.key" -out "$T/ca.crt" -subj /CN=Test-CA -days 3650
o req -newkey rsa:2048 -nodes -keyout "$T/s.key" -out "$T/s.csr" -subj /CN=server.test
o x509 -req -in "$T/s.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -set_serial 2 -days 365 -out "$T/s.crt"
o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/c.key" -out "$T/c.crt" -subj /CN=client -days 365
cat "$T/s.crt" "$T/ca.crt" > "$T/chain.crt"

# A relay between client and server records both directions in order.
cat > "$T/relay.py" <<'PY'
import socket, sys, threading
lport, rport, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
log, lock = [], threading.Lock()
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", lport)); ls.listen(1)
c, _ = ls.accept(); s = socket.create_connection(("127.0.0.1", rport))
def pump(a, b, d):
    while True:
        try: x = a.recv(65536)
        except OSError: break
        if not x: break
        with lock: log.append((d, x))
        try: b.sendall(x)
        except OSError: break
    for z in (a, b):
        try: z.shutdown(socket.SHUT_RDWR)
        except OSError: pass
ts = [threading.Thread(target=pump, args=(c, s, "O")), threading.Thread(target=pump, args=(s, c, "I"))]
[t.start() for t in ts]; [t.join() for t in ts]
with open(out, "w") as f:
    for d, x in log:
        for i in range(0, len(x), 1400):
            ch = x[i:i + 1400]
            f.write(d + "\n" + "".join("%06x %s\n" % (j, " ".join("%02x" % b for b in ch[j:j + 16]))
                                       for j in range(0, len(ch), 16)))
PY
openssl s_server -accept 24433 -cert "$T/s.crt" -key "$T/s.key" -cert_chain "$T/ca.crt" \
    -tls1_2 -Verify 1 -CAfile "$T/c.crt" -quiet >/dev/null 2>&1 &
python3 "$T/relay.py" 24434 24433 "$T/mtls.txt" & RELAY=$!
sleep 1
(sleep 1; echo Q) | timeout 5 openssl s_client -connect 127.0.0.1:24434 -tls1_2 -servername server.test \
    -cert "$T/c.crt" -key "$T/c.key" >/dev/null 2>&1 || true
wait $RELAY
# Client 192.0.2.10:50000, server 192.0.2.20:443 (documentation addresses), as one
# complete TCP session (Zeek analyses only sessions it saw open).
python3 tcp_session.py "$T/mtls.txt" mtls.pcap 192.0.2.10 50000 192.0.2.20 443

# Handshake record with one Certificate message holding 5 bytes that are not a certificate.
python3 - "$T/bad.txt" <<'PY'
import sys
entry = bytes.fromhex("3003020101")
certs = len(entry).to_bytes(3, "big") + entry
body = len(certs).to_bytes(3, "big") + certs
hs = b"\x0b" + len(body).to_bytes(3, "big") + body
rec = b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs
with open(sys.argv[1], "w") as f:
    f.write("I\n" + "".join("%06x %s\n" % (j, " ".join("%02x" % b for b in rec[j:j + 16]))
                           for j in range(0, len(rec), 16)))
PY
python3 tcp_session.py "$T/bad.txt" badcert.pcap 192.0.2.10 50001 192.0.2.20 443
ls -l mtls.pcap badcert.pcap
