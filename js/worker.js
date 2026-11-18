// Parse + analyse off the main thread so a 50 MB capture doesn't freeze the page.
import { readFrames } from "./pcap.js";
import { decode } from "./decode.js";
import { analyze } from "./analyze.js";

self.onmessage = (e) => {
  const buf = e.data;
  try {
    const packets = [];
    let i = 0;
    for (const f of readFrames(buf)) {
      const p = decode(f);
      // keep where the bytes are instead of the bytes, the page slices the
      // original buffer itself for the hex view
      p.off = f.data.byteOffset; p.caplen = f.data.length;
      packets.push(p);
      if (++i % 20000 === 0) self.postMessage({ progress: i });
    }
    const a = analyze(packets);
    self.postMessage({ done: true, packets, analysis: a, buffer: buf }, [buf]);
  } catch (err) {
    self.postMessage({ error: err.message || String(err) });
  }
};
