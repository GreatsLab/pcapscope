import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { readFrames, PcapError } from "../js/pcap.js";
import { decode, ip6, parseDns } from "../js/decode.js";
import { analyze } from "../js/analyze.js";

const load = (f) => { const b = readFileSync(new URL(`../samples/${f}`, import.meta.url)); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); };
const pcap = [...readFrames(load("office.pcap"))].map(decode);
const ng = [...readFrames(load("office.pcapng"))].map(decode);

test("pcap and pcapng give the same packets", () => {
  assert.equal(pcap.length, 397);
  assert.equal(ng.length, 397);
  for (let i = 0; i < pcap.length; i += 37) {
    assert.equal(ng[i].info, pcap[i].info);
    assert.ok(Math.abs(ng[i].ts - pcap[i].ts) < 1e-5, "timestamps (ns resolution in pcapng)");
  }
});

test("big-endian nanosecond pcap", () => {
  const frame = new Uint8Array(pcap[0].caplen);
  const src = [...readFrames(load("office.pcap"))][0].data;
  frame.set(src);
  const buf = new ArrayBuffer(24 + 16 + frame.length);
  const dv = new DataView(buf);
  dv.setUint32(0, 0xa1b23c4d, false); dv.setUint16(4, 2); dv.setUint16(6, 4);
  dv.setUint32(16, 65535); dv.setUint32(20, 1);
  dv.setUint32(24, 1700000000); dv.setUint32(28, 500000000);
  dv.setUint32(32, frame.length); dv.setUint32(36, frame.length);
  new Uint8Array(buf, 40).set(frame);
  const [f] = [...readFrames(buf)];
  assert.equal(f.ts, 1700000000.5);
  assert.equal(decode(f).info, pcap[0].info);
});

test("not a capture", () => {
  assert.throws(() => [...readFrames(new ArrayBuffer(100))], PcapError);
});

test("ipv6 formatting", () => {
  const b = new Uint8Array(16); b[0] = 0x20; b[1] = 0x01; b[2] = 0x0d; b[3] = 0xb8; b[15] = 1;
  assert.equal(ip6(b, 0), "2001:db8::1");
});

test("decoders", () => {
  const sip = pcap.find(p => p.vlan);
  assert.deepEqual(sip.vlan, [20]);
  assert.equal(sip.app, "SIP");
  const v6 = pcap.find(p => p.ipv === 6 && p.dns && p.dns.response);
  assert.equal(v6.dns.answers[0].data, "2606:50c0:8000::153");
  const hello = pcap.find(p => p.tls && p.tls.hello === "client");
  assert.ok(hello.tls.sni && hello.tls.alpn.includes("h2") && hello.tls.offers13);
  const dh = pcap.find(p => p.dhcp && p.dhcp.hostname);
  assert.equal(dh.dhcp.hostname, "GREAT-LAPTOP");
  const arp = pcap.find(p => p.arp);
  assert.match(arp.info, /Who has 10\.10\.5\.1\?/);
});

test("dns compression loop doesn't hang", () => {
  // header + a name that points at itself
  const b = new Uint8Array([0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1]);
  assert.doesNotThrow(() => parseDns(b));
});

test("findings", () => {
  const a = analyze(pcap);
  const kinds = new Set(a.findings.map(f => f.kind));
  for (const k of ["cleartext-creds", "arp-conflict", "port-scan", "nxdomain", "retransmissions"]) assert.ok(kinds.has(k), k);
  assert.ok(!kinds.has("telnet"), "scan SYNs to port 23 are not a telnet session");
  assert.equal(a.findings[0].severity, "high");
});

test("protocol counts don't include scan SYNs as services", () => {
  const a = analyze(pcap);
  assert.ok(!a.protocols.has("Telnet"));
  assert.ok(a.protocols.get("DNS").packets >= 100);
});

test("dns pairs query and response with latency", () => {
  const a = analyze(pcap);
  const d = a.dns.find(x => x.name === "github.com" && x.type === "A");
  assert.ok(d.ms > 0 && d.ms < 100);
  assert.equal(a.dns.filter(x => x.rcode === "NXDOMAIN").length, 24);
});
