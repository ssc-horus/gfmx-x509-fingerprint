#!/usr/bin/env python3
"""Write a relay dump as a pcap holding one complete TCP session.

Input: lines "I" or "O" starting a segment, then hex dump lines ("000000 16 03 ...").
"O" is client to server, "I" server to client. Output: Ethernet/IPv4/TCP with the
three-way handshake, the data with correct sequence numbers, and FIN/ACK, so tools
that only analyse sessions they saw open (Zeek) read it like a real capture.

    tcp_session.py dump.txt out.pcap [client_ip client_port server_ip server_port]
"""
from __future__ import annotations

import socket
import struct
import sys


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def segments(path: str):
    cur, out = None, []
    for line in open(path):
        line = line.strip()
        if line in ("I", "O"):
            if cur:
                out.append(cur)
            cur = (line, bytearray())
        elif line and cur:
            cur[1].extend(bytes.fromhex("".join(line.split()[1:])))
    if cur:
        out.append(cur)
    return [(d, bytes(b)) for d, b in out]


def main() -> None:
    src, dst = sys.argv[1], sys.argv[2]
    cip, cport, sip, sport = (sys.argv[3:7] + ["192.0.2.10", "50000", "192.0.2.20", "443"][len(sys.argv[3:7]):])
    cport, sport = int(cport), int(sport)
    ends = {"c": (socket.inet_aton(cip), cport), "s": (socket.inet_aton(sip), sport)}
    frames, t = [], 1792400000.0
    SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
    seq = {"c": 1000, "s": 5000}

    def send(frm: str, flags: int, payload: bytes = b"", ack: bool = True):
        nonlocal t
        to = "s" if frm == "c" else "c"
        a, b = ends[frm], ends[to]
        acknum = seq[to] if ack else 0
        tcp = struct.pack("!HHIIBBHHH", a[1], b[1], seq[frm], acknum, 5 << 4, flags, 65535, 0, 0) + payload
        pseudo = a[0] + b[0] + struct.pack("!BBH", 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), len(frames) + 1, 0x4000, 64, 6, 0, a[0], b[0])
        ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
        eth = b"\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00" if to == "s" else b"\x02\0\0\0\0\x01\x02\0\0\0\0\x02\x08\x00"
        frames.append((t, eth + ip + tcp))
        t += 0.000001
        seq[frm] = (seq[frm] + len(payload) + (1 if flags & (SYN | FIN) else 0)) & 0xFFFFFFFF

    send("c", SYN, ack=False)
    send("s", SYN | ACK)
    send("c", ACK)
    for d, data in segments(src):
        frm = "c" if d == "O" else "s"
        for i in range(0, len(data), 1400):
            send(frm, PSH | ACK, data[i:i + 1400])
    send("c", FIN | ACK)
    send("s", FIN | ACK)
    send("c", ACK)
    with open(dst, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in frames:
            f.write(struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)), len(fr), len(fr)) + fr)


if __name__ == "__main__":
    main()
