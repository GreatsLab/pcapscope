// Aggregate decoded packets into the views the UI shows, and look for things
// an analyst would want pointed out.

export function analyze(packets, { timelineBuckets = 120 } = {}) {
  const a = {
    count: packets.length, bytes: 0, first: Infinity, last: -Infinity,
    protocols: new Map(),       // label -> {packets, bytes}
    conversations: new Map(),   // key -> conv
    endpoints: new Map(),       // ip -> {packets, bytes, macs:Set}
    dns: [], tls: new Map(), http: [], dhcp: [], arp: new Map(),
    findings: [],
  };

  const dnsPending = new Map();
  const synSeen = new Map();      // "src>dst:port" -> ts of SYN
  const synAcked = new Set();
  const tcpSeen = new Map();      // retransmission tracking: conv+dir -> Set(seq:len)
  const scan = new Map();         // src -> Map(dst -> Set(ports))
  let retrans = 0, resets = 0, malformed = 0;

  for (const p of packets) {
    a.bytes += p.len;
    if (p.ts) { a.first = Math.min(a.first, p.ts); a.last = Math.max(a.last, p.ts); }
    if (p.malformed) malformed++;

    const label = p.app || p.proto || "?";
    bump(a.protocols, label, p.len);

    if (p.src && p.dst) {
      ep(a, p.src, p.len, p.srcMac);
      ep(a, p.dst, p.len, p.dstMac);
      const key = convKey(p);
      let c = a.conversations.get(key);
      if (!c) {
        const [x, y] = order(p);
        c = { key, a: x.ip, ap: x.port, b: y.ip, bp: y.port, proto: p.proto, app: p.app || p.service || "",
              packets: 0, bytes: 0, ab: 0, ba: 0, first: p.ts, last: p.ts, flags: new Set() };
        a.conversations.set(key, c);
      }
      c.packets++; c.bytes += p.len; c.last = p.ts;
      if (p.src === c.a && (p.sport ?? null) === c.ap) c.ab += p.len; else c.ba += p.len;
      if (p.app && !c.app) c.app = p.app;
    }

    if (p.tcp) {
      const f = p.tcp.flags;
      const syn = f & 0x02, ack = f & 0x10, rst = f & 0x04;
      const k = `${p.src}>${p.dst}:${p.dport}`;
      if (syn && !ack) {
        synSeen.set(k, p.ts);
        let m = scan.get(p.src);
        if (!m) scan.set(p.src, (m = new Map()));
        let s = m.get(p.dst);
        if (!s) { m.set(p.dst, (s = new Set())); s.firstN = p.n; }
        s.add(p.dport);
      }
      if (syn && ack) synAcked.add(`${p.dst}>${p.src}:${p.sport}`);
      if (rst) resets++;
      if (p.tcp.len > 0) {
        const dk = `${p.src}:${p.sport}>${p.dst}:${p.dport}`;
        let set = tcpSeen.get(dk);
        if (!set) tcpSeen.set(dk, (set = new Set()));
        const sk = `${p.tcp.seq}:${p.tcp.len}`;
        if (set.has(sk)) { retrans++; p.retransmission = true; a.conversations.get(convKey(p))?.flags.add("retransmissions"); }
        else set.add(sk);
      }
    }

    if (p.dns) {
      const q = p.dns.questions[0];
      if (!p.dns.response && q) {
        dnsPending.set(`${p.dns.id}|${q.name}|${p.src}`, { ts: p.ts, client: p.src, server: p.dst, name: q.name, type: q.type, n: p.n });
      } else if (p.dns.response && q) {
        const k = `${p.dns.id}|${q.name}|${p.dst}`;
        const req = dnsPending.get(k);
        a.dns.push({ ts: req ? req.ts : p.ts, client: p.dst, server: p.src, name: q.name, type: q.type,
                     rcode: p.dns.rcode, answers: p.dns.answers.map(x => x.data).filter(Boolean),
                     ms: req && p.ts && req.ts ? (p.ts - req.ts) * 1000 : null, n: p.n });
        dnsPending.delete(k);
      }
    }

    if (p.tls && p.tls.hello === "client") {
      const sni = p.tls.sni || "(no SNI)";
      const t = a.tls.get(sni) || { sni, clients: new Set(), servers: new Set(), hellos: 0, alpn: new Set(), first: p.ts };
      t.hellos++; t.clients.add(p.src); t.servers.add(p.dst);
      p.tls.alpn.forEach(x => t.alpn.add(x));
      a.tls.set(sni, t);
    }
    if (p.http && !p.http.response) a.http.push({ ts: p.ts, client: p.src, server: p.dst, port: p.dport, ...p.http, n: p.n });
    if (p.dhcp) a.dhcp.push({ ts: p.ts, ...p.dhcp, n: p.n });
    if (p.arp && p.arp.op === 2) {
      const prev = a.arp.get(p.arp.spa);
      if (prev && prev.mac !== p.arp.sha) {
        a.findings.push({ severity: "high", kind: "arp-conflict", n: p.n,
          title: `${p.arp.spa} answered from two different MACs`,
          detail: `${prev.mac} (packet ${prev.n}) and ${p.arp.sha} (packet ${p.n}). Either an IP conflict or ARP spoofing / a man-in-the-middle.` });
      }
      a.arp.set(p.arp.spa, { mac: p.arp.sha, n: p.n });
    }

    // credentials in the clear
    if (p.text && /^(USER|PASS) /i.test(p.text) && p.app === "FTP") {
      a.findings.push({ severity: "high", kind: "cleartext-creds", n: p.n,
        title: `FTP ${p.text.split(" ")[0].toUpperCase()} sent in clear text`,
        detail: `${p.src} → ${p.dst}. Anyone on the path can read the login. Use SFTP/FTPS.` });
    }
    if (p.app === "Telnet" && p.tcp && p.tcp.len) a.telnet = (a.telnet || 0) + 1;
    if (p.http && p.http.basicAuth) {
      a.findings.push({ severity: "high", kind: "cleartext-creds", n: p.n,
        title: `HTTP Basic auth over plain HTTP to ${p.http.host || p.dst}`,
        detail: `${p.src} sent a username and password base64-encoded (not encrypted).` });
    }
    if (p.app === "TLS" && p.tls && p.tls.hello === "server" && /SSL|1\.0|1\.1/.test(p.tls.version)) {
      a.findings.push({ severity: "medium", kind: "old-tls", n: p.n,
        title: `${p.src} negotiated ${p.tls.version}`, detail: "Deprecated protocol version." });
    }
  }

  // ---- after the pass ----------------------------------------------------
  for (const [src, m] of scan) {
    let ports = 0;
    const targets = [];
    let firstN;
    for (const [dst, s] of m) {
      ports += s.size;
      if (s.size >= 15) { targets.push(`${dst} (${s.size} ports)`); firstN ??= s.firstN; }
    }
    if (targets.length) {
      a.findings.push({ severity: "high", kind: "port-scan", n: firstN, title: `${src} looks like it's port scanning`,
        detail: `SYNs to many ports on ${targets.join(", ")}.` });
    } else if (m.size >= 30) {
      a.findings.push({ severity: "medium", kind: "host-sweep", title: `${src} tried to connect to ${m.size} different hosts`,
        detail: "Could be a network sweep, or just a busy client." });
    }
  }
  const failed = [...synSeen.keys()].filter(k => !synAcked.has(k));
  if (failed.length >= 5) {
    a.findings.push({ severity: "low", kind: "failed-connects", title: `${failed.length} TCP connections never got a SYN-ACK`,
      detail: `e.g. ${failed.slice(0, 4).join(", ")}. Filtered ports, a dead service, or scanning.` });
  }
  if (retrans) {
    a.findings.push({ severity: retrans > a.count * 0.02 ? "medium" : "low", kind: "retransmissions",
      title: `${retrans} TCP retransmission${retrans > 1 ? "s" : ""}`,
      detail: `${((retrans / Math.max(1, a.count)) * 100).toFixed(1)}% of packets. Above ~1% usually means loss on the path.` });
  }
  const nx = a.dns.filter(d => d.rcode === "NXDOMAIN");
  if (nx.length >= 10) {
    const byClient = count(nx.map(d => d.client));
    const [top, n] = [...byClient].sort((x, y) => y[1] - x[1])[0];
    a.findings.push({ severity: n >= 20 ? "medium" : "low", kind: "nxdomain",
      title: `${nx.length} lookups for names that don't exist`,
      detail: `${top} made ${n} of them. Lots of random-looking NXDOMAINs can mean malware using a domain generation algorithm.` });
  }
  const longNames = a.dns.filter(d => d.name.split(".")[0].length >= 40);
  if (longNames.length >= 3) {
    a.findings.push({ severity: "medium", kind: "dns-tunnel", title: `${longNames.length} DNS queries with very long labels`,
      detail: `e.g. ${longNames[0].name.slice(0, 70)}… Long encoded-looking labels are a classic DNS tunnelling sign.` });
  }
  if (a.telnet) a.findings.push({ severity: "high", kind: "telnet", title: "Telnet session in the capture", detail: "Everything typed, including passwords, is visible." });
  if (resets > a.count * 0.05 && resets > 20) {
    a.findings.push({ severity: "low", kind: "resets", title: `${resets} TCP resets`, detail: "A lot of refused or aborted connections." });
  }
  if (malformed) a.findings.push({ severity: "low", kind: "malformed", title: `${malformed} packets couldn't be decoded`, detail: "Truncated, or a link type this tool doesn't know." });

  const order_ = { high: 0, medium: 1, low: 2 };
  a.findings.sort((x, y) => order_[x.severity] - order_[y.severity]);

  a.timeline = timeline(packets, a.first, a.last, timelineBuckets);
  a.duration = a.last > a.first ? a.last - a.first : 0;
  return a;
}

function bump(m, k, bytes) {
  const v = m.get(k) || { packets: 0, bytes: 0 };
  v.packets++; v.bytes += bytes;
  m.set(k, v);
}

function ep(a, ip, bytes, macAddr) {
  const e = a.endpoints.get(ip) || { ip, packets: 0, bytes: 0, macs: new Set() };
  e.packets++; e.bytes += bytes;
  if (macAddr) e.macs.add(macAddr);
  a.endpoints.set(ip, e);
}

function order(p) {
  const x = { ip: p.src, port: p.sport ?? null }, y = { ip: p.dst, port: p.dport ?? null };
  // the side with the lower port is usually the server; put the client first
  if (x.port != null && y.port != null && x.port < y.port) return [y, x];
  if (x.port == null && x.ip > y.ip) return [y, x];
  return [x, y];
}

export function convKey(p) {
  const [x, y] = order(p);
  return `${p.proto}|${x.ip}|${x.port}|${y.ip}|${y.port}`;
}

function count(xs) {
  const m = new Map();
  for (const x of xs) m.set(x, (m.get(x) || 0) + 1);
  return m;
}

function timeline(packets, first, last, n) {
  if (!isFinite(first) || last <= first) return { start: first, step: 0, buckets: [] };
  const step = (last - first) / n;
  const buckets = Array.from({ length: n }, () => ({ packets: 0, bytes: 0, byProto: {} }));
  for (const p of packets) {
    if (!p.ts) continue;
    const i = Math.min(n - 1, Math.floor((p.ts - first) / step));
    const b = buckets[i];
    b.packets++; b.bytes += p.len;
    const k = p.app || p.proto || "?";
    b.byProto[k] = (b.byProto[k] || 0) + p.len;
  }
  return { start: first, step, buckets };
}
