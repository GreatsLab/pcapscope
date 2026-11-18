// Read classic libpcap and pcapng files into a flat list of frames.
// Pure functions over an ArrayBuffer - runs in a worker, in node, anywhere.

export const LINKTYPE = { ETHERNET: 1, RAW: 101, LINUX_SLL: 113, IPV4: 228, IPV6: 229, LINUX_SLL2: 276, NULL: 0 };

export class PcapError extends Error {}

export function* readFrames(buf) {
  const dv = new DataView(buf);
  if (buf.byteLength < 24) throw new PcapError("file is too small to be a capture");
  const magic = dv.getUint32(0, false);
  if (magic === 0x0a0d0d0a) { yield* readPcapng(dv); return; }
  yield* readPcap(dv, magic);
}

function* readPcap(dv, magic) {
  // a1b2c3d4 = microseconds, a1b23c4d = nanoseconds; byte order from how it reads
  let le, nano;
  switch (magic) {
    case 0xa1b2c3d4: le = false; nano = false; break;
    case 0xd4c3b2a1: le = true; nano = false; break;
    case 0xa1b23c4d: le = false; nano = true; break;
    case 0x4d3cb2a1: le = true; nano = true; break;
    default: throw new PcapError("not a pcap or pcapng file (unknown magic number)");
  }
  const linktype = dv.getUint32(20, le) & 0x0fffffff;
  let off = 24, n = 0;
  while (off + 16 <= dv.byteLength) {
    const sec = dv.getUint32(off, le);
    const frac = dv.getUint32(off + 4, le);
    const incl = dv.getUint32(off + 8, le);
    const orig = dv.getUint32(off + 12, le);
    off += 16;
    if (incl > 262144 || off + incl > dv.byteLength) break;   // truncated last packet: stop, don't throw
    yield { n: ++n, ts: sec + frac / (nano ? 1e9 : 1e6), linktype, len: orig,
            data: new Uint8Array(dv.buffer, dv.byteOffset + off, incl) };
    off += incl;
  }
}

function* readPcapng(dv) {
  let off = 0, n = 0, le = true;
  const ifaces = [];   // {linktype, tsres} per interface in the current section
  while (off + 12 <= dv.byteLength) {
    let type = dv.getUint32(off, le);
    if (type === 0x0a0d0d0a) {
      // section header: byte-order magic decides endianness for the section
      const bom = dv.getUint32(off + 8, true);
      le = bom === 0x1a2b3c4d;
      if (!le && dv.getUint32(off + 8, false) !== 0x1a2b3c4d) throw new PcapError("bad pcapng byte-order magic");
      ifaces.length = 0;
      type = 0x0a0d0d0a;
    }
    const blen = dv.getUint32(off + 4, le);
    if (blen < 12 || off + blen > dv.byteLength) break;
    const body = off + 8;
    if (type === 1) {                         // interface description
      const linktype = dv.getUint16(body, le);
      let tsres = 1e-6;
      // options: look for if_tsresol (code 9)
      let o = body + 8;
      while (o + 4 <= off + blen - 4) {
        const code = dv.getUint16(o, le), olen = dv.getUint16(o + 2, le);
        if (code === 0) break;
        if (code === 9 && olen >= 1) {
          const v = dv.getUint8(o + 4);
          tsres = v & 0x80 ? 2 ** -(v & 0x7f) : 10 ** -(v & 0x7f);
        }
        o += 4 + ((olen + 3) & ~3);
      }
      ifaces.push({ linktype, tsres });
    } else if (type === 6) {                  // enhanced packet
      const ifid = dv.getUint32(body, le);
      const hi = dv.getUint32(body + 4, le), lo = dv.getUint32(body + 8, le);
      const incl = dv.getUint32(body + 12, le), orig = dv.getUint32(body + 16, le);
      const iface = ifaces[ifid] || { linktype: 1, tsres: 1e-6 };
      if (body + 20 + incl <= off + blen) {
        yield { n: ++n, ts: (hi * 4294967296 + lo) * iface.tsres, linktype: iface.linktype, len: orig,
                data: new Uint8Array(dv.buffer, dv.byteOffset + body + 20, incl) };
      }
    } else if (type === 3) {                  // simple packet (no timestamp)
      const orig = dv.getUint32(body, le);
      const incl = Math.min(orig, blen - 16);
      const iface = ifaces[0] || { linktype: 1 };
      yield { n: ++n, ts: 0, linktype: iface.linktype, len: orig,
              data: new Uint8Array(dv.buffer, dv.byteOffset + body + 4, incl) };
    }
    off += blen;
  }
}
