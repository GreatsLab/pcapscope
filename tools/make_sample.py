"""Build samples/office.pcap (and a pcapng copy) by hand, byte by byte.

No scapy, no live capture: every packet here is synthetic, so the sample is
safe to publish and the tests know exactly what's in it.

  - normal browsing: DNS lookups, TLS ClientHello/ServerHello with SNI
  - a plain-HTTP request with Basic auth          -> finding
  - an FTP login in clear text                     -> finding
  - a port scan from 10.10.5.66                    -> finding
  - ARP reply for the gateway from a second MAC    -> finding (spoofing)
  - a burst of random-looking NXDOMAIN lookups     -> finding (DGA-ish)
  - a few TCP retransmissions, ICMP pings, DHCP, IPv6 DNS, a VLAN-tagged frame

Usage: python tools/make_sample.py
"""
import random
import struct

random.seed(7)
T0 = 1763452800.0  # 2025-11-18 08:00 UTC
pkts = []


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def ip(s):
    return bytes(int(x) for x in s.split("."))


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b)//2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


MACS = {"10.10.5.1": "00:1a:2b:00:00:01", "10.10.5.23": "3c:22:fb:10:20:23", "10.10.5.40": "3c:22:fb:10:20:40",
        "10.10.5.66": "f4:8e:38:aa:bb:66", "10.10.5.80": "3c:22:fb:10:20:80"}
GW = "00:1a:2b:00:00:01"


def eth(src_ip, dst_ip, payload, etype=0x0800, vlan=None):
    s = mac(MACS.get(src_ip, GW)) if src_ip in MACS else mac(GW)
    d = mac(MACS.get(dst_ip, GW)) if dst_ip in MACS else mac(GW)
    if vlan is not None:
        return d + s + struct.pack("!HHH", 0x8100, vlan, etype) + payload
    return d + s + struct.pack("!H", etype) + payload


def ipv4(src, dst, proto, payload, ttl=64):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), random.randint(0, 65535), 0x4000, ttl, proto, 0, ip(src), ip(dst))
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(sport, dport, seq, ack, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def add(t, frame):
    pkts.append((T0 + t, frame))


def tcp_pkt(t, src, sp, dst, dp, seq, ack, flags, payload=b"", vlan=None):
    add(t, eth(src, dst, ipv4(src, dst, 6, tcp(sp, dp, seq, ack, flags, payload)), vlan=vlan))


def udp_pkt(t, src, sp, dst, dp, payload):
    add(t, eth(src, dst, ipv4(src, dst, 17, udp(sp, dp, payload))))


SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04


def qname(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0"


def dns_query(qid, name, qtype=1):
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", qtype, 1)


def dns_resp(qid, name, answers, qtype=1, rcode=0):
    body = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, len(answers), 0, 0) + qname(name) + struct.pack("!HH", qtype, 1)
    for a in answers:
        if qtype == 1:
            body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip(a)
        else:
            body += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 300, 16) + a
    return body


def client_hello(sni, alpn=("h2", "http/1.1")):
    ext = b""
    name = sni.encode()
    sn = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    ext += struct.pack("!HH", 0, len(sn)) + sn
    al = b"".join(bytes([len(x)]) + x.encode() for x in alpn)
    al = struct.pack("!H", len(al)) + al
    ext += struct.pack("!HH", 16, len(al)) + al
    sv = bytes([4]) + struct.pack("!HH", 0x0304, 0x0303)
    ext += struct.pack("!HH", 43, len(sv)) + sv
    body = struct.pack("!H", 0x0303) + bytes(random.getrandbits(8) for _ in range(32)) + b"\x20" + bytes(32)
    body += struct.pack("!H", 4) + struct.pack("!HH", 0x1301, 0xC02F) + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def server_hello(ver=0x0303):
    body = struct.pack("!H", ver) + bytes(32) + b"\x00" + struct.pack("!H", 0x1301) + b"\x00" + struct.pack("!H", 0)
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def browse(t, client, sni, server_ip, sport):
    qid = random.randint(1, 65535)
    udp_pkt(t, client, sport + 1000, "10.10.0.53", 53, dns_query(qid, sni))
    udp_pkt(t + 0.012, "10.10.0.53", 53, client, sport + 1000, dns_resp(qid, sni, [server_ip]))
    s = random.randint(1, 2**31)
    r = random.randint(1, 2**31)
    tcp_pkt(t + 0.02, client, sport, server_ip, 443, s, 0, SYN)
    tcp_pkt(t + 0.05, server_ip, 443, client, sport, r, s + 1, SYN | ACK)
    tcp_pkt(t + 0.051, client, sport, server_ip, 443, s + 1, r + 1, ACK)
    ch = client_hello(sni)
    tcp_pkt(t + 0.052, client, sport, server_ip, 443, s + 1, r + 1, PSH | ACK, ch)
    sh = server_hello()
    tcp_pkt(t + 0.09, server_ip, 443, client, sport, r + 1, s + 1 + len(ch), PSH | ACK, sh + bytes(900))
    tcp_pkt(t + 0.091, client, sport, server_ip, 443, s + 1 + len(ch), r + 1 + len(sh) + 900, ACK)
    return s + 1 + len(ch), r + 1 + len(sh) + 900


sites = [("github.com", "140.82.121.4"), ("www.google.com", "142.250.184.132"), ("paystack.com", "104.18.7.141"),
         ("auroxhost.com", "102.89.4.20"), ("api.whatsapp.com", "157.240.214.60"), ("outlook.office365.com", "52.97.146.162"),
         ("cdn.jsdelivr.net", "151.101.1.229")]

t = 0.0
port = 50000
for i in range(28):
    client = random.choice(["10.10.5.23", "10.10.5.40", "10.10.5.80"])
    sni, sip = random.choice(sites)
    seq, rseq = browse(t, client, sni, sip, port)
    port += 1
    # a couple of connections lose a segment and retransmit it
    if i in (5, 17):
        data = bytes(1200)
        tcp_pkt(t + 0.2, client, port - 1, sip, 443, seq, rseq, PSH | ACK, data)
        tcp_pkt(t + 0.5, client, port - 1, sip, 443, seq, rseq, PSH | ACK, data)
    t += random.uniform(1, 9)

# plain HTTP with basic auth (a router admin page)
s = 900001
tcp_pkt(40.0, "10.10.5.40", 51111, "10.10.5.1", 80, s, 0, SYN)
tcp_pkt(40.001, "10.10.5.1", 80, "10.10.5.40", 51111, 7000, s + 1, SYN | ACK)
tcp_pkt(40.002, "10.10.5.40", 51111, "10.10.5.1", 80, s + 1, 7001, ACK)
req = b"GET /admin/status HTTP/1.1\r\nHost: 10.10.5.1\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
tcp_pkt(40.003, "10.10.5.40", 51111, "10.10.5.1", 80, s + 1, 7001, PSH | ACK, req)
tcp_pkt(40.01, "10.10.5.1", 80, "10.10.5.40", 51111, 7001, s + 1 + len(req), PSH | ACK, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

# FTP login in clear text to a NAS
s = 1200
tcp_pkt(55.0, "10.10.5.23", 52020, "10.10.5.200", 21, s, 0, SYN)
tcp_pkt(55.001, "10.10.5.200", 21, "10.10.5.23", 52020, 50, s + 1, SYN | ACK)
tcp_pkt(55.002, "10.10.5.23", 52020, "10.10.5.200", 21, s + 1, 51, ACK)
tcp_pkt(55.01, "10.10.5.200", 21, "10.10.5.23", 52020, 51, s + 1, PSH | ACK, b"220 NAS FTP server ready\r\n")
tcp_pkt(55.5, "10.10.5.23", 52020, "10.10.5.200", 21, s + 1, 77, PSH | ACK, b"USER backup\r\n")
tcp_pkt(55.6, "10.10.5.23", 52020, "10.10.5.200", 21, s + 14, 77, PSH | ACK, b"PASS Summer2026!\r\n")

# port scan: 10.10.5.66 hits 60 ports on the file server, most closed
for i, p in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017] + list(range(1000, 1036))):
    tt = 70 + i * 0.01
    tcp_pkt(tt, "10.10.5.66", 40000 + i, "10.10.5.200", p, 1000 + i, 0, SYN)
    if p in (22, 80, 139, 445):
        tcp_pkt(tt + 0.001, "10.10.5.200", p, "10.10.5.66", 40000 + i, 5000, 1001 + i, SYN | ACK)
    elif i % 3 == 0:
        tcp_pkt(tt + 0.001, "10.10.5.200", p, "10.10.5.66", 40000 + i, 0, 1001 + i, RST | ACK)

# ARP: gateway answers normally, then someone else claims the gateway's IP
def arp_reply(t, sha, spa, tha, tpa):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mac(sha) + ip(spa) + mac(tha) + ip(tpa)
    add(t, mac(tha) + mac(sha) + struct.pack("!H", 0x0806) + body)


def arp_req(t, sha, spa, tpa):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac(sha) + ip(spa) + bytes(6) + ip(tpa)
    add(t, b"\xff" * 6 + mac(sha) + struct.pack("!H", 0x0806) + body)


arp_req(1.0, MACS["10.10.5.23"], "10.10.5.23", "10.10.5.1")
arp_reply(1.001, GW, "10.10.5.1", MACS["10.10.5.23"], "10.10.5.23")
arp_reply(90.0, MACS["10.10.5.66"], "10.10.5.1", MACS["10.10.5.23"], "10.10.5.23")

# DGA-ish: a burst of random .com lookups that don't exist
for i in range(24):
    name = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(random.randint(12, 18))) + ".com"
    qid = 30000 + i
    udp_pkt(100 + i * 0.4, "10.10.5.80", 53000 + i, "10.10.0.53", 53, dns_query(qid, name))
    udp_pkt(100 + i * 0.4 + 0.03, "10.10.0.53", 53, "10.10.5.80", 53000 + i, dns_resp(qid, name, [], rcode=3))

# pings to the gateway and to 1.1.1.1
for i in range(4):
    for dst in ("10.10.5.1", "1.1.1.1"):
        icmp = struct.pack("!BBHHH", 8, 0, 0, 0x4242, i) + bytes(32)
        icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
        add(20 + i, eth("10.10.5.23", dst, ipv4("10.10.5.23", dst, 1, icmp)))
        rep = struct.pack("!BBHHH", 0, 0, 0, 0x4242, i) + bytes(32)
        rep = rep[:2] + struct.pack("!H", csum(rep)) + rep[4:]
        add(20 + i + (0.002 if dst.startswith("10.") else 0.031), eth(dst, "10.10.5.23", ipv4(dst, "10.10.5.23", 1, rep)))

# DHCP: a new laptop joins
def dhcp_pkt(t, mtype, src, dst, yiaddr="0.0.0.0", hostname=None):
    b = struct.pack("!BBBBIHH4s4s4s4s", 1 if mtype in (1, 3) else 2, 1, 6, 0, 0xABCD1234, 0, 0x8000,
                    bytes(4), ip(yiaddr), bytes(4), bytes(4)) + mac("a4:5e:60:12:34:56") + bytes(10) + bytes(192)
    b += b"\x63\x82\x53\x63" + bytes([53, 1, mtype])
    if hostname:
        b += bytes([12, len(hostname)]) + hostname.encode()
    b += b"\xff"
    sp, dp = (68, 67) if mtype in (1, 3) else (67, 68)
    add(t, b"\xff" * 6 + mac("a4:5e:60:12:34:56") + struct.pack("!H", 0x0800) + ipv4(src, dst, 17, udp(sp, dp, b)))


dhcp_pkt(5.0, 1, "0.0.0.0", "255.255.255.255", hostname="GREAT-LAPTOP")
dhcp_pkt(5.01, 2, "10.10.5.1", "255.255.255.255", yiaddr="10.10.5.90")
dhcp_pkt(5.02, 3, "0.0.0.0", "255.255.255.255", hostname="GREAT-LAPTOP")
dhcp_pkt(5.03, 5, "10.10.5.1", "255.255.255.255", yiaddr="10.10.5.90")

# one VLAN-tagged voice frame
tcp_pkt(33.0, "10.10.5.80", 5060, "10.10.0.10", 5060, 1, 1, PSH | ACK, b"OPTIONS sip:pbx SIP/2.0\r\n", vlan=20)

# IPv6 DNS over UDP
def ip6(s):
    import ipaddress
    return ipaddress.IPv6Address(s).packed


def ipv6(src, dst, nh, payload):
    return struct.pack("!IHBB", 0x60000000, len(payload), nh, 64) + ip6(src) + ip6(dst) + payload


q = dns_query(4242, "github.com", 28)
add(12.0, mac(GW) + mac(MACS["10.10.5.23"]) + struct.pack("!H", 0x86DD) + ipv6("2c0f:f4c0:1::23", "2001:4860:4860::8888", 17, udp(53535, 53, q)))
r = dns_resp(4242, "github.com", [ip6("2606:50c0:8000::153")], qtype=28)
add(12.03, mac(MACS["10.10.5.23"]) + mac(GW) + struct.pack("!H", 0x86DD) + ipv6("2001:4860:4860::8888", "2c0f:f4c0:1::23", 17, udp(53, 53535, r)))

pkts.sort(key=lambda x: x[0])


def write_pcap(path):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in pkts:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(fr), len(fr)) + fr)


def write_pcapng(path):
    def block(t, body):
        pad = (4 - len(body) % 4) % 4
        body += b"\0" * pad
        n = 12 + len(body)
        return struct.pack("<II", t, n) + body + struct.pack("<I", n)
    with open(path, "wb") as f:
        f.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        # interface with nanosecond resolution option, to exercise if_tsresol
        opts = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)
        f.write(block(1, struct.pack("<HHI", 1, 0, 65535) + opts))
        for ts, fr in pkts:
            ns = int(round(ts * 1e9))
            f.write(block(6, struct.pack("<IIIII", 0, ns >> 32, ns & 0xFFFFFFFF, len(fr), len(fr)) + fr))


write_pcap("samples/office.pcap")
write_pcapng("samples/office.pcapng")
print(f"{len(pkts)} packets")
