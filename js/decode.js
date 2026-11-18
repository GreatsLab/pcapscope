// Turn raw frames into something a person can read.
// Ethernet / 802.1Q / Linux SLL / raw IP -> IPv4 / IPv6 / ARP -> TCP / UDP / ICMP -> DNS, TLS, HTTP, DHCP...
import { LINKTYPE } from "./pcap.js";

const ETH = { IPV4: 0x0800, ARP: 0x0806, VLAN: 0x8100, QINQ: 0x88a8, IPV6: 0x86dd };
const IPPROTO = { 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF", 112: "VRRP", 132: "SCTP" };

// well known ports -> application label. Checked dst first, then src.
const PORTS = {
  20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
  69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
  143: "IMAP", 161: "SNMP", 162: "SNMP", 179: "BGP", 389: "LDAP", 443: "TLS", 445: "SMB", 465: "SMTPS",
  514: "Syslog", 587: "SMTP", 636: "LDAPS", 853: "DoT", 993: "IMAPS", 995: "POP3S", 1194: "OpenVPN",
  1812: "RADIUS", 1813: "RADIUS", 1900: "SSDP", 3306: "MySQL", 3389: "RDP", 4500: "IPsec", 500: "IPsec",
  5060: "SIP", 5353: "mDNS", 5355: "LLMNR", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP", 8443: "TLS",
  51820: "WireGuard", 2049: "NFS", 5900: "VNC", 27017: "MongoDB",
};

const hex2 = (b) => b.toString(16).padStart(2, "0");
export const mac = (d, o) => [0, 1, 2, 3, 4, 5].map(i => hex2(d[o + i])).join(":");
export const ip4 = (d, o) => `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`;

export function ip6(d, o) {
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push(((d[o + i] << 8) | d[o + i + 1]).toString(16));
  // collapse the longest run of zero groups (RFC 5952)
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== "0") { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === "0") j++;
    if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best < 0) return g.join(":");
  return `${g.slice(0, best).join(":")}::${g.slice(best + bestLen).join(":")}`;
}

const u16 = (d, o) => (d[o] << 8) | d[o + 1];
const u32 = (d, o) => ((d[o] << 24) >>> 0) + (d[o + 1] << 16) + (d[o + 2] << 8) + d[o + 3];

export function decode(frame) {
  const d = frame.data;
  const p = { n: frame.n, ts: frame.ts, len: frame.len, caplen: d.length, stack: [], info: "" };
  let off = 0, etype = null;

  switch (frame.linktype) {
    case LINKTYPE.ETHERNET:
      if (d.length < 14) return bad(p, "short ethernet frame");
      p.srcMac = mac(d, 6); p.dstMac = mac(d, 0);
      etype = u16(d, 12); off = 14;
      p.stack.push("Ethernet");
      while ((etype === ETH.VLAN || etype === ETH.QINQ) && off + 4 <= d.length) {
        (p.vlan ||= []).push(u16(d, off) & 0x0fff);
        etype = u16(d, off + 2); off += 4;
        p.stack.push("802.1Q");
      }
      break;
    case LINKTYPE.LINUX_SLL:
      if (d.length < 16) return bad(p, "short SLL header");
      etype = u16(d, 14); off = 16; p.stack.push("Linux cooked");
      break;
    case LINKTYPE.LINUX_SLL2:
      if (d.length < 20) return bad(p, "short SLL2 header");
      etype = u16(d, 0); off = 20; p.stack.push("Linux cooked v2");
      break;
    case LINKTYPE.NULL: {
      // BSD loopback: 4-byte family in host byte order
      const fam = d[0] || d[3];
      etype = fam === 2 ? ETH.IPV4 : ETH.IPV6; off = 4; p.stack.push("Loopback");
      break;
    }
    case LINKTYPE.RAW: case LINKTYPE.IPV4: case LINKTYPE.IPV6:
      etype = (d[0] >> 4) === 6 ? ETH.IPV6 : ETH.IPV4; off = 0;
      break;
    default:
      return bad(p, `link type ${frame.linktype} not supported`);
  }

  if (etype === ETH.ARP) return arp(p, d, off);
  if (etype === ETH.IPV4) return ipv4(p, d, off);
  if (etype === ETH.IPV6) return ipv6(p, d, off);
  p.proto = `0x${etype.toString(16).padStart(4, "0")}`;
  p.info = `EtherType ${p.proto}`;
  return p;
}

function bad(p, why) { p.proto = "?"; p.info = why; p.malformed = true; return p; }

function arp(p, d, o) {
  p.stack.push("ARP"); p.proto = "ARP";
  if (d.length < o + 28) return bad(p, "short ARP");
  const op = u16(d, o + 6);
  const sha = mac(d, o + 8), spa = ip4(d, o + 14), tpa = ip4(d, o + 24);
  p.src = spa; p.dst = tpa;
  p.arp = { op, sha, spa, tpa };
  p.info = op === 1 ? (spa === tpa ? `Gratuitous ARP for ${spa}` : `Who has ${tpa}? Tell ${spa}`)
    : op === 2 ? `${spa} is at ${sha}` : `ARP op ${op}`;
  return p;
}

function ipv4(p, d, o) {
  if (d.length < o + 20) return bad(p, "short IPv4 header");
  const ihl = (d[o] & 0x0f) * 4;
  const total = u16(d, o + 2);
  const flagsFrag = u16(d, o + 6);
  p.stack.push("IPv4");
  p.ipv = 4; p.ttl = d[o + 8];
  p.src = ip4(d, o + 12); p.dst = ip4(d, o + 16);
  const proto = d[o + 9];
  p.fragment = (flagsFrag & 0x1fff) !== 0 || (flagsFrag & 0x2000) !== 0;
  const end = Math.min(d.length, o + (total || d.length - o));
  if ((flagsFrag & 0x1fff) !== 0) { p.proto = IPPROTO[proto] || `IP-${proto}`; p.info = "fragment"; return p; }
  return transport(p, d, o + ihl, end, proto);
}

function ipv6(p, d, o) {
  if (d.length < o + 40) return bad(p, "short IPv6 header");
  p.stack.push("IPv6");
  p.ipv = 6; p.ttl = d[o + 7];
  p.src = ip6(d, o + 8); p.dst = ip6(d, o + 24);
  let next = d[o + 6], off = o + 40;
  const end = Math.min(d.length, o + 40 + u16(d, o + 4));
  // walk extension headers: hop-by-hop, routing, destination options, fragment
  for (let guard = 0; guard < 8 && [0, 43, 60, 44].includes(next) && off + 8 <= end; guard++) {
    const hlen = next === 44 ? 8 : (d[off + 1] + 1) * 8;
    next = d[off]; off += hlen;
  }
  return transport(p, d, off, end, next);
}

function transport(p, d, o, end, proto) {
  const name = IPPROTO[proto] || `IP-${proto}`;
  p.proto = name;
  if (proto === 6) return tcp(p, d, o, end);
  if (proto === 17) return udp(p, d, o, end);
  if (proto === 1 || proto === 58) return icmp(p, d, o, end, proto === 58);
  p.stack.push(name);
  p.info = name;
  return p;
}

const TCPF = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"];

function tcp(p, d, o, end) {
  if (end < o + 20) return bad(p, "short TCP header");
  p.stack.push("TCP");
  p.sport = u16(d, o); p.dport = u16(d, o + 2);
  const seq = u32(d, o + 4), ack = u32(d, o + 8);
  const hl = (d[o + 12] >> 4) * 4;
  const fl = d[o + 13];
  const flags = TCPF.filter((_, i) => fl & (1 << i));
  const payload = d.subarray(Math.min(o + hl, end), end);
  p.tcp = { seq, ack, flags: fl, flagNames: flags, win: u16(d, o + 14), len: payload.length };
  p.info = `${p.sport} → ${p.dport} [${flags.join(", ")}] Seq=${seq}${fl & 0x10 ? ` Ack=${ack}` : ""} Len=${payload.length}`;
  app(p, payload, "tcp");
  return p;
}

function udp(p, d, o, end) {
  if (end < o + 8) return bad(p, "short UDP header");
  p.stack.push("UDP");
  p.sport = u16(d, o); p.dport = u16(d, o + 2);
  const payload = d.subarray(o + 8, Math.min(end, o + Math.max(8, u16(d, o + 4))));
  p.udp = { len: payload.length };
  p.info = `${p.sport} → ${p.dport} Len=${payload.length}`;
  app(p, payload, "udp");
  return p;
}

const ICMP4 = { 0: "Echo reply", 3: "Destination unreachable", 5: "Redirect", 8: "Echo request", 11: "Time exceeded" };
const ICMP6 = { 1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded", 128: "Echo request", 129: "Echo reply",
  133: "Router solicitation", 134: "Router advertisement", 135: "Neighbor solicitation", 136: "Neighbor advertisement" };

function icmp(p, d, o, end, v6) {
  p.stack.push(v6 ? "ICMPv6" : "ICMP");
  if (end < o + 4) return bad(p, "short ICMP");
  const type = d[o], code = d[o + 1];
  p.icmp = { type, code };
  p.info = (v6 ? ICMP6 : ICMP4)[type] || `type ${type} code ${code}`;
  if ((type === 8 || type === 0 || type === 128 || type === 129) && end >= o + 8) {
    p.icmp.id = u16(d, o + 4); p.icmp.seq = u16(d, o + 6);
    p.info += ` id=${p.icmp.id} seq=${p.icmp.seq}`;
  }
  return p;
}

// ---- application layer -----------------------------------------------

function app(p, payload, l4) {
  const label = PORTS[p.dport] || PORTS[p.sport];
  if (label) p.app = label;

  // content beats port numbers where we can tell
  if (l4 === "tcp" && payload.length > 5 && payload[0] === 0x16 && payload[1] === 0x03) {
    const t = tls(payload);
    if (t) { p.app = "TLS"; p.tls = t; p.stack.push("TLS"); p.info = t.info; return; }
  }
  if (l4 === "tcp" && payload.length >= 4 && /^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT) /.test(ascii(payload, 0, 10))) {
    p.app = "HTTP"; p.http = httpReq(payload); p.stack.push("HTTP");
    p.info = `${p.http.method} ${p.http.path}${p.http.host ? `  Host: ${p.http.host}` : ""}`;
    return;
  }
  if (l4 === "tcp" && payload.length >= 12 && ascii(payload, 0, 5) === "HTTP/") {
    p.app = "HTTP"; const line = firstLine(payload);
    p.http = { status: Number(line.split(" ")[1]) || 0, response: true };
    p.stack.push("HTTP"); p.info = line; return;
  }
  if (l4 === "tcp" && payload.length >= 4 && ascii(payload, 0, 4) === "SSH-") {
    p.app = "SSH"; p.stack.push("SSH"); p.info = firstLine(payload); p.ssh = { banner: firstLine(payload) }; return;
  }
  if ((p.dport === 53 || p.sport === 53 || p.dport === 5353 || p.sport === 5353 || p.dport === 5355 || p.sport === 5355) && payload.length >= 12) {
    const dns = parseDns(payload, l4 === "tcp");
    if (dns) { p.app = p.dport === 5353 || p.sport === 5353 ? "mDNS" : p.dport === 5355 || p.sport === 5355 ? "LLMNR" : "DNS"; p.dns = dns; p.stack.push(p.app); p.info = dnsInfo(dns); return; }
  }
  if ((p.dport === 67 || p.dport === 68) && payload.length >= 240) {
    const dh = dhcp(payload);
    if (dh) { p.app = "DHCP"; p.dhcp = dh; p.stack.push("DHCP"); p.info = dh.info; return; }
  }
  if (l4 === "udp" && payload.length >= 1200 && (payload[0] & 0xc0) === 0xc0 && (p.dport === 443 || p.sport === 443)) {
    p.app = "QUIC"; p.stack.push("QUIC"); p.info = "QUIC Initial"; return;
  }
  // cleartext protocols where credentials fly past: worth flagging
  if (l4 === "tcp" && payload.length && ["FTP", "Telnet", "POP3", "IMAP", "SMTP"].includes(p.app)) {
    const line = firstLine(payload);
    p.text = line; p.stack.push(p.app); p.info = line.slice(0, 120);
    return;
  }
  if (p.app && payload.length) p.stack.push(p.app);
}

export function ascii(b, o, n) {
  let s = "";
  for (let i = o; i < Math.min(b.length, o + n); i++) s += String.fromCharCode(b[i]);
  return s;
}

function firstLine(b) {
  let s = "";
  for (let i = 0; i < Math.min(b.length, 512); i++) {
    if (b[i] === 13 || b[i] === 10) break;
    s += String.fromCharCode(b[i]);
  }
  return s;
}

function httpReq(b) {
  const text = ascii(b, 0, Math.min(b.length, 4096));
  const [head] = text.split("\r\n\r\n");
  const lines = head.split("\r\n");
  const [method, path] = lines[0].split(" ");
  const h = {};
  for (const l of lines.slice(1)) {
    const i = l.indexOf(":");
    if (i > 0) h[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim();
  }
  const out = { method, path, host: h.host || "", ua: h["user-agent"] || "" };
  if (h.authorization && /^basic /i.test(h.authorization)) out.basicAuth = true;
  return out;
}

// TLS: find the ClientHello's SNI and ALPN, or the ServerHello's version
export function tls(b) {
  if (b.length < 9) return null;
  const recVer = u16(b, 1);
  const hsType = b[5];
  const names = { 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3" };
  if (hsType === 1) {                          // ClientHello
    let o = 9 + 2 + 32;                        // handshake header(4) + version(2) + random(32)
    if (o >= b.length) return { hello: "client", info: "Client Hello (truncated)" };
    o += 1 + b[o];                             // session id
    if (o + 2 > b.length) return { hello: "client", info: "Client Hello" };
    o += 2 + u16(b, o);                        // cipher suites
    if (o + 1 > b.length) return { hello: "client", info: "Client Hello" };
    o += 1 + b[o];                             // compression
    if (o + 2 > b.length) return { hello: "client", info: "Client Hello" };
    const extEnd = Math.min(b.length, o + 2 + u16(b, o));
    o += 2;
    let sni = "", alpn = [], tls13 = false;
    while (o + 4 <= extEnd) {
      const type = u16(b, o), len = u16(b, o + 2), e = o + 4;
      if (type === 0 && e + 5 <= extEnd) {     // server_name
        const nlen = u16(b, e + 3);
        sni = ascii(b, e + 5, nlen);
      } else if (type === 16 && e + 2 <= extEnd) {   // ALPN
        let q = e + 2;
        while (q < e + len && q < extEnd) { const l = b[q]; alpn.push(ascii(b, q + 1, l)); q += 1 + l; }
      } else if (type === 43) {
        for (let q = e + 1; q + 1 < e + len; q += 2) if (u16(b, q) === 0x0304) tls13 = true;
      }
      o = e + len;
    }
    return { hello: "client", sni, alpn, offers13: tls13, info: `Client Hello${sni ? `  SNI=${sni}` : ""}${alpn.length ? `  ALPN=${alpn.join(",")}` : ""}` };
  }
  if (hsType === 2) {
    const ver = u16(b, 9);
    return { hello: "server", version: names[ver] || ver.toString(16), info: `Server Hello (${names[ver] || "?"})` };
  }
  return { info: `TLS handshake (${names[recVer] || "?"})` };
}

// ---- DNS --------------------------------------------------------------

const QTYPE = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY" };
const RCODE = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"];

function readName(b, o, depth = 0) {
  const labels = [];
  let jumped = false, next = o;
  for (let guard = 0; guard < 128; guard++) {
    if (o >= b.length) return null;
    const len = b[o];
    if (len === 0) { if (!jumped) next = o + 1; break; }
    if ((len & 0xc0) === 0xc0) {               // compression pointer
      if (o + 1 >= b.length || depth > 10) return null;
      if (!jumped) next = o + 2;
      o = ((len & 0x3f) << 8) | b[o + 1];
      jumped = true; depth++;
      continue;
    }
    labels.push(ascii(b, o + 1, len));
    o += 1 + len;
  }
  return { name: labels.join(".") || ".", next };
}

export function parseDns(b, overTcp = false) {
  if (overTcp) b = b.subarray(2);
  if (b.length < 12) return null;
  const id = u16(b, 0), flags = u16(b, 2);
  const qd = u16(b, 4), an = u16(b, 6);
  if (qd > 10 || an > 200) return null;       // not DNS, just traffic on port 53
  const out = { id, response: !!(flags & 0x8000), rcode: RCODE[flags & 0x0f] || String(flags & 0x0f), questions: [], answers: [] };
  let o = 12;
  for (let i = 0; i < qd; i++) {
    const r = readName(b, o);
    if (!r || r.next + 4 > b.length) return out.questions.length ? out : null;
    out.questions.push({ name: r.name, type: QTYPE[u16(b, r.next)] || String(u16(b, r.next)) });
    o = r.next + 4;
  }
  for (let i = 0; i < an; i++) {
    const r = readName(b, o);
    if (!r || r.next + 10 > b.length) break;
    const type = u16(b, r.next), ttl = u32(b, r.next + 4), rdlen = u16(b, r.next + 8);
    const rd = r.next + 10;
    if (rd + rdlen > b.length) break;
    let data = "";
    if (type === 1 && rdlen === 4) data = ip4(b, rd);
    else if (type === 28 && rdlen === 16) data = ip6(b, rd);
    else if (type === 5 || type === 2 || type === 12) data = (readName(b, rd) || {}).name || "";
    else if (type === 15) data = (readName(b, rd + 2) || {}).name || "";
    else if (type === 16) data = ascii(b, rd + 1, b[rd]);
    out.answers.push({ name: r.name, type: QTYPE[type] || String(type), ttl, data });
    o = rd + rdlen;
  }
  return out;
}

function dnsInfo(d) {
  const q = d.questions[0];
  const qs = q ? `${q.type} ${q.name}` : "";
  if (!d.response) return `Query ${qs}`;
  if (d.rcode !== "NOERROR") return `Response ${qs}  ${d.rcode}`;
  return `Response ${qs}  ${d.answers.map(a => a.data).filter(Boolean).slice(0, 3).join(", ")}`;
}

// ---- DHCP -------------------------------------------------------------

const DHCPMSG = ["", "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK", "RELEASE", "INFORM"];

function dhcp(b) {
  if (u32(b, 236) !== 0x63825363) return null;   // magic cookie
  const out = { yiaddr: ip4(b, 16), chaddr: mac(b, 28) };
  let o = 240;
  while (o < b.length && b[o] !== 255) {
    const code = b[o];
    if (code === 0) { o++; continue; }
    const len = b[o + 1], v = o + 2;
    if (code === 53) out.type = DHCPMSG[b[v]] || String(b[v]);
    else if (code === 12) out.hostname = ascii(b, v, len);
    else if (code === 50) out.requested = ip4(b, v);
    else if (code === 54) out.server = ip4(b, v);
    else if (code === 60) out.vendor = ascii(b, v, len);
    o = v + len;
  }
  out.info = `DHCP ${out.type || "?"}${out.hostname ? `  host=${out.hostname}` : ""}${out.yiaddr !== "0.0.0.0" ? `  ${out.yiaddr}` : ""}`;
  return out;
}
