const $ = (s) => document.querySelector(s);
const NS = "http://www.w3.org/2000/svg";
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const fmt = (n) => Math.round(n).toLocaleString("en-US");

// one colour per protocol, used everywhere: timeline, legend, packet list
const COLORS = { DNS: "--p-dns", mDNS: "--p-dns", LLMNR: "--p-dns", TLS: "--p-tls", QUIC: "--p-tls", HTTP: "--p-http",
  TCP: "--p-tcp", UDP: "--p-udp", ICMP: "--p-icmp", ICMPv6: "--p-icmp", ARP: "--p-arp", DHCP: "--p-dhcp" };
const css = getComputedStyle(document.documentElement);
const color = (k) => css.getPropertyValue(COLORS[k] || "--p-other").trim() || "#9AA1AC";

let state = null;   // { packets, analysis, bytes: Uint8Array, view: [], range: null, selected: null }

function bytesH(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}
function dur(s) {
  if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
  if (s < 120) return `${s.toFixed(1)} s`;
  if (s < 7200) return `${(s / 60).toFixed(1)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}
const clock = (t) => new Date(t * 1000).toISOString().slice(11, 23);

function status(msg, err = false) {
  const s = $("#status");
  s.textContent = msg;
  s.classList.toggle("err", err);
}

// ---------------------------------------------------------------- loading
function load(buf, name) {
  status(`Reading ${name}…`);
  $("#filename").textContent = name;
  const w = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
  w.onmessage = (e) => {
    const m = e.data;
    if (m.progress) { status(`Reading ${name}… ${fmt(m.progress)} packets`); return; }
    w.terminate();
    if (m.error) { status(`${name}: ${m.error}`, true); return; }
    state = { packets: m.packets, analysis: m.analysis, bytes: new Uint8Array(m.buffer), view: m.packets, range: null, selected: null };
    status("");
    render();
  };
  w.onerror = (e) => status(`Couldn't analyse ${name}: ${e.message}`, true);
  w.postMessage(buf, [buf]);
}

async function loadFile(file) {
  if (!file) return;
  if (file.size > 400 * 1048576) { status("That's over 400 MB. Split it first (editcap -c 500000) so your browser doesn't run out of memory.", true); return; }
  load(await file.arrayBuffer(), file.name);
}

async function loadSample() {
  status("Fetching the sample…");
  try {
    const r = await fetch("samples/office.pcapng");
    if (!r.ok) throw new Error(r.status);
    load(await r.arrayBuffer(), "office.pcapng (sample)");
  } catch (e) {
    status(`Couldn't fetch the sample (${e.message}).`, true);
  }
}

$("#file").addEventListener("change", (e) => loadFile(e.target.files[0]));
$("#sample").addEventListener("click", loadSample);
$("#sample2").addEventListener("click", loadSample);
$("#drop").addEventListener("click", () => $("#file").click());
$("#drop").addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#file").click(); } });

let dragDepth = 0;
window.addEventListener("dragenter", (e) => { if (e.dataTransfer.types.includes("Files")) { dragDepth++; $("#dropveil").hidden = false; } });
window.addEventListener("dragleave", () => { if (--dragDepth <= 0) { dragDepth = 0; $("#dropveil").hidden = true; } });
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => {
  e.preventDefault(); dragDepth = 0; $("#dropveil").hidden = true;
  loadFile(e.dataTransfer.files[0]);
});

// ---------------------------------------------------------------- report
function render() {
  const a = state.analysis;
  $("#landing").hidden = true;
  $("#report").hidden = false;

  const hosts = [...a.endpoints.keys()].filter(ip => !/^(255\.|0\.0\.0\.0|224\.|ff0)/.test(ip)).length;
  const top = [...a.protocols].sort((x, y) => y[1].bytes - x[1].bytes).slice(0, 3).map(([k]) => k);
  const high = a.findings.filter(f => f.severity === "high").length;
  $("#summary").innerHTML =
    `<b>${fmt(a.count)}</b> packets, <b>${bytesH(a.bytes)}</b> over <b>${dur(a.duration)}</b>, between ${fmt(hosts)} addresses. ` +
    `Mostly ${top.map(esc).join(", ")}. ` +
    (a.findings.length ? `<b>${a.findings.length} finding${a.findings.length > 1 ? "s" : ""}</b>${high ? `, ${high} serious` : ""}.` : "Nothing suspicious stood out.");

  $("#n-findings").textContent = a.findings.length || "";
  $("#n-convs").textContent = fmt(a.conversations.size);
  $("#n-dns").textContent = fmt(a.dns.length);
  $("#n-web").textContent = fmt(a.tls.size + a.http.length);
  drawTimeline();
  renderLegend();
  renderFindings();
  renderConvs();
  renderDns();
  renderWeb();
  applyFilter();
  showTab(a.findings.length ? "findings" : "convs");
}

function protoOrder() {
  return [...state.analysis.protocols].sort((x, y) => y[1].bytes - x[1].bytes).map(([k]) => k);
}

function renderLegend() {
  const a = state.analysis;
  $("#legend").innerHTML = protoOrder().slice(0, 10).map(k => {
    const v = a.protocols.get(k);
    return `<span><i style="background:${color(k)}"></i><b>${esc(k)}</b>${bytesH(v.bytes)}, ${fmt(v.packets)} pkts</span>`;
  }).join("");
}

function drawTimeline() {
  const svg = $("#timeline");
  const { buckets, start, step } = state.analysis.timeline;
  const W = Math.max(300, svg.clientWidth || 1000), H = 130;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.innerHTML = "";
  if (!buckets.length) return;
  const max = Math.max(...buckets.map(b => b.bytes)) || 1;
  const bw = W / buckets.length;
  const order = protoOrder();
  buckets.forEach((b, i) => {
    let y = H - 14;
    // sqrt scale on the bar height: one big download shouldn't flatten
    // everything else to nothing. Segments split the bar by share of bytes.
    const total = Math.sqrt(b.bytes / max) * (H - 26);
    for (const k of order) {
      const v = b.byProto[k];
      if (!v) continue;
      const h = total * (v / b.bytes);
      const r = document.createElementNS(NS, "rect");
      r.setAttribute("x", (i * bw + 0.5).toFixed(1)); r.setAttribute("width", Math.max(1, bw - 1).toFixed(1));
      r.setAttribute("y", (y - h).toFixed(1)); r.setAttribute("height", Math.max(0.5, h).toFixed(1));
      r.setAttribute("fill", color(k));
      svg.appendChild(r);
      y -= h;
    }
  });
  // where the findings happened
  for (const f of state.analysis.findings) {
    if (!f.n) continue;
    const p = state.packets[f.n - 1];
    if (!p || !p.ts) continue;
    const x = ((p.ts - start) / (step * buckets.length)) * W;
    const t = document.createElementNS(NS, "path");
    t.setAttribute("d", `M${x - 5},2 L${x + 5},2 L${x},10 Z`);
    t.setAttribute("class", "mark");
    const title = document.createElementNS(NS, "title"); title.textContent = f.title; t.appendChild(title);
    svg.appendChild(t);
  }
  if (state.range) {
    const [t0, t1] = state.range, span = step * buckets.length;
    const r = document.createElementNS(NS, "rect");
    r.setAttribute("class", "sel");
    r.setAttribute("x", ((t0 - start) / span) * W); r.setAttribute("width", Math.max(2, ((t1 - t0) / span) * W));
    r.setAttribute("y", 0); r.setAttribute("height", H - 12);
    svg.appendChild(r);
  }
  $("#tl-start").textContent = clock(start);
  $("#tl-end").textContent = clock(start + step * buckets.length);
  $("#tl-sel").textContent = state.range ? `showing ${clock(state.range[0])} – ${clock(state.range[1])} · click to clear` : "drag across the chart to zoom the packet list";
}

// drag on the timeline to pick a time window for the packet list
(() => {
  const svg = $("#timeline");
  let down = null;
  const tAt = (e) => {
    const r = svg.getBoundingClientRect();
    const { start, step, buckets } = state.analysis.timeline;
    return start + Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)) * step * buckets.length;
  };
  svg.addEventListener("pointerdown", (e) => { if (state) { down = tAt(e); svg.setPointerCapture(e.pointerId); } });
  svg.addEventListener("pointerup", (e) => {
    if (down == null) return;
    const t = tAt(e);
    const [a, b] = [Math.min(down, t), Math.max(down, t)];
    down = null;
    const { step } = state.analysis.timeline;
    state.range = b - a < step / 2 ? null : [a, b];
    drawTimeline();
    applyFilter();
    if (state.range) showTab("packets");
  });
})();
window.addEventListener("resize", () => state && drawTimeline());

// ---------------------------------------------------------------- tabs
function showTab(name) {
  document.querySelectorAll("#tabs button").forEach(b => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  document.querySelectorAll(".panel").forEach(p => { p.hidden = p.dataset.panel !== name; });
  if (name === "packets") drawRows();
}
$("#tabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-tab]"); if (b) showTab(b.dataset.tab); });

// ---------------------------------------------------------------- findings
function renderFindings() {
  const f = state.analysis.findings;
  $("#findings").innerHTML = f.length ? f.map((x, i) => `<li>
      <span class="sev ${x.severity}">${x.severity}</span>
      <div><b>${esc(x.title)}</b><p>${esc(x.detail)}</p></div>
      ${x.n ? `<button class="go" data-n="${x.n}">packet ${x.n}</button>` : `<span></span>`}
    </li>`).join("") : `<li><span class="none">Nothing on the list. That doesn't prove the capture is clean, only that none of the checks fired.</span></li>`;
}
$("#findings").addEventListener("click", (e) => {
  const b = e.target.closest(".go");
  if (!b) return;
  $("#filter").value = "";
  state.range = null; drawTimeline(); applyFilter();
  showTab("packets");
  selectPacket(Number(b.dataset.n), true);
});

// ---------------------------------------------------------------- tables
function table(el, cols, rows, initialSort) {
  let sort = initialSort;
  const draw = () => {
    const r = [...rows];
    if (sort) {
      const c = cols.find(c => c.key === sort.key);
      r.sort((x, y) => { const a = c.sortVal ? c.sortVal(x) : x[c.key], b = c.sortVal ? c.sortVal(y) : y[c.key]; return (a > b ? 1 : a < b ? -1 : 0) * sort.dir; });
    }
    const shown = r.slice(0, 2000);
    el.innerHTML = `<thead><tr>${cols.map(c => `<th data-k="${c.key}">${c.label}${sort && sort.key === c.key ? (sort.dir > 0 ? " ▲" : " ▼") : ""}</th>`).join("")}</tr></thead>
      <tbody>${shown.map(x => `<tr>${cols.map(c => `<td class="${c.cls || ""}">${c.render ? c.render(x) : esc(x[c.key])}</td>`).join("")}</tr>`).join("")}
      ${r.length > shown.length ? `<tr><td colspan="${cols.length}" class="muted">…and ${fmt(r.length - shown.length)} more</td></tr>` : ""}
      ${!r.length ? `<tr><td colspan="${cols.length}" class="muted">None in this capture.</td></tr>` : ""}</tbody>`;
  };
  el.onclick = (e) => {
    const th = e.target.closest("th");
    if (!th) return;
    const k = th.dataset.k;
    sort = sort && sort.key === k ? { key: k, dir: -sort.dir } : { key: k, dir: -1 };
    draw();
  };
  draw();
}

const pill = (k) => k ? `<span class="pill" style="background:${color(k)}">${esc(k)}</span>` : "";
const hostPort = (ip, port) => `${esc(ip)}${port != null ? `<span class="muted">:${port}</span>` : ""}`;

function renderConvs() {
  const rows = [...state.analysis.conversations.values()];
  table($("#convs"), [
    { key: "a", label: "Client", cls: "mono", render: c => hostPort(c.a, c.ap) },
    { key: "b", label: "Server", cls: "mono", render: c => hostPort(c.b, c.bp) },
    { key: "app", label: "Service", render: c => pill(c.app || c.proto) },
    { key: "packets", label: "Packets", cls: "num", render: c => fmt(c.packets) },
    { key: "bytes", label: "Bytes", cls: "num", render: c => bytesH(c.bytes) },
    { key: "ab", label: "Sent / received", render: c => `<span class="ratio" title="${bytesH(c.ab)} sent, ${bytesH(c.ba)} received"><span style="width:${(c.ab / Math.max(1, c.bytes)) * 100}%"></span></span>` },
    { key: "first", label: "Duration", cls: "num", sortVal: c => c.last - c.first, render: c => dur(Math.max(0, c.last - c.first)) },
    { key: "flags", label: "", render: c => c.flags.size ? `<span class="bad">${[...c.flags].join(", ")}</span>` : "" },
  ], rows, { key: "bytes", dir: -1 });
}

function renderDns() {
  table($("#dns"), [
    { key: "ts", label: "Time", cls: "mono", render: d => clock(d.ts) },
    { key: "client", label: "Client", cls: "mono" },
    { key: "name", label: "Name", cls: "mono wrap" },
    { key: "type", label: "Type" },
    { key: "rcode", label: "Result", render: d => d.rcode === "NOERROR" ? esc(d.answers.slice(0, 3).join(", ")) || "(no answers)" : `<span class="bad">${esc(d.rcode)}</span>` },
    { key: "ms", label: "Took", cls: "num", render: d => d.ms == null ? "" : `${d.ms.toFixed(1)} ms` },
  ], state.analysis.dns, { key: "ts", dir: 1 });
}

function renderWeb() {
  table($("#tls"), [
    { key: "sni", label: "Server name (SNI)", cls: "mono wrap" },
    { key: "hellos", label: "Connections", cls: "num" },
    { key: "clients", label: "Clients", sortVal: t => t.clients.size, render: t => fmt(t.clients.size) },
    { key: "servers", label: "Server IPs", cls: "mono", sortVal: t => t.servers.size, render: t => esc([...t.servers].slice(0, 3).join(", ")) },
    { key: "alpn", label: "ALPN", render: t => esc([...t.alpn].join(", ")) },
  ], [...state.analysis.tls.values()], { key: "hellos", dir: -1 });
  table($("#http"), [
    { key: "ts", label: "Time", cls: "mono", render: h => clock(h.ts) },
    { key: "client", label: "Client", cls: "mono" },
    { key: "method", label: "Method" },
    { key: "host", label: "Host", cls: "mono" },
    { key: "path", label: "Path", cls: "mono wrap" },
    { key: "basicAuth", label: "", render: h => h.basicAuth ? `<span class="bad">password in clear text</span>` : "" },
  ], state.analysis.http, { key: "ts", dir: 1 });
}

// ---------------------------------------------------------------- packets
// filter words are ANDed:  dns  tls  10.10.5.23  10.10.  port 443  syn  rst  retrans  vlan 20  "free text"
function matcher(q) {
  const toks = q.toLowerCase().match(/"[^"]+"|\S+/g) || [];
  const tests = [];
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i].replace(/^"|"$/g, "");
    if ((t === "port" || t === "vlan") && toks[i + 1]) {
      const n = Number(toks[++i]);
      tests.push(t === "port" ? (p => p.sport === n || p.dport === n) : (p => (p.vlan || []).includes(n)));
    } else if (/^\d{1,3}(\.\d{1,3}){0,3}\.?$/.test(t) || t.includes(":") && /^[0-9a-f:]+$/.test(t)) {
      tests.push(p => (p.src || "").startsWith(t) || (p.dst || "").startsWith(t));
    } else if (["syn", "ack", "rst", "fin", "psh"].includes(t)) {
      tests.push(p => p.tcp && p.tcp.flagNames.map(x => x.toLowerCase()).includes(t));
    } else if (t === "retrans") {
      tests.push(p => p.retransmission);
    } else {
      tests.push(p => (p.stack || []).some(s => s.toLowerCase() === t) || (p.app || "").toLowerCase() === t || (p.info || "").toLowerCase().includes(t));
    }
  }
  return (p) => tests.every(f => f(p));
}

function applyFilter() {
  if (!state) return;
  const m = matcher($("#filter").value);
  const r = state.range;
  state.view = state.packets.filter(p => (!r || (p.ts >= r[0] && p.ts <= r[1])) && m(p));
  $("#n-packets").textContent = fmt(state.packets.length);
  $("#filter-count").textContent = state.view.length === state.packets.length ? `${fmt(state.view.length)} packets` : `${fmt(state.view.length)} of ${fmt(state.packets.length)}`;
  $("#pk-list").scrollTop = 0;
  drawRows();
}
let ft;
$("#filter").addEventListener("input", () => { clearTimeout(ft); ft = setTimeout(applyFilter, 120); });

const ROW = 26;
function drawRows() {
  const list = $("#pk-list");
  if (!state || list.offsetParent === null) return;
  const v = state.view;
  const first = Math.max(0, Math.floor(list.scrollTop / ROW) - 10);
  const last = Math.min(v.length, first + Math.ceil(list.clientHeight / ROW) + 20);
  const t0 = state.analysis.first;
  let html = `<div style="height:${v.length * ROW}px"></div>`;
  for (let i = first; i < last; i++) {
    const p = v[i];
    const k = p.app || p.proto;
    const cls = `pk-row${p.n === state.selected ? " on" : ""}${p.retransmission || (p.tcp && p.tcp.flags & 4) ? " flag" : ""}`;
    html += `<div class="${cls}" style="top:${i * ROW}px;border-left-color:${color(k)}" data-n="${p.n}">
      <span>${p.n}</span><span class="c-time">${p.ts ? (p.ts - t0).toFixed(3) : ""}</span><span class="c-src">${esc(p.src || p.srcMac || "")}</span>
      <span class="c-dst">${esc(p.dst || p.dstMac || "")}</span><span>${esc(k)}</span><span class="c-info">${esc(p.info)}</span></div>`;
  }
  list.innerHTML = html;
}
$("#pk-list").addEventListener("scroll", () => requestAnimationFrame(drawRows));
$("#pk-list").addEventListener("click", (e) => { const r = e.target.closest(".pk-row"); if (r) selectPacket(Number(r.dataset.n)); });
$("#pk-list").addEventListener("keydown", (e) => {
  if (!state || !["ArrowDown", "ArrowUp"].includes(e.key)) return;
  e.preventDefault();
  const i = state.view.findIndex(p => p.n === state.selected);
  const next = state.view[Math.max(0, Math.min(state.view.length - 1, (i < 0 ? -1 : i) + (e.key === "ArrowDown" ? 1 : -1)))];
  if (next) selectPacket(next.n, true);
});

function selectPacket(n, scroll = false) {
  state.selected = n;
  const p = state.packets[n - 1];
  if (scroll) {
    const i = state.view.findIndex(x => x.n === n);
    if (i >= 0) $("#pk-list").scrollTop = Math.max(0, i * ROW - 200);
  }
  drawRows();
  const rows = [
    ["Packet", `${p.n}  (${p.len} bytes${p.caplen < p.len ? `, ${p.caplen} captured` : ""})`],
    ["Time", p.ts ? new Date(p.ts * 1000).toISOString().replace("T", " ").replace("Z", " UTC") : "-"],
    ["Layers", p.stack.join(" › ")],
  ];
  if (p.srcMac) rows.push(["MAC", `${p.srcMac} → ${p.dstMac}`]);
  if (p.vlan) rows.push(["VLAN", p.vlan.join(", ")]);
  if (p.src) rows.push(["IP", `${p.src} → ${p.dst}${p.ttl != null ? `  ttl ${p.ttl}` : ""}`]);
  if (p.sport != null) rows.push(["Ports", `${p.sport} → ${p.dport}`]);
  if (p.tcp) rows.push(["TCP", `${p.tcp.flagNames.join(" ") || "-"}  seq ${p.tcp.seq}  ack ${p.tcp.ack}  win ${p.tcp.win}  len ${p.tcp.len}${p.retransmission ? "  RETRANSMISSION" : ""}`]);
  if (p.dns) rows.push(["DNS", `${p.dns.response ? "response" : "query"} id ${p.dns.id}  ${p.dns.questions.map(q => `${q.type} ${q.name}`).join(", ")}${p.dns.response ? `  ${p.dns.rcode}` : ""}`]);
  if (p.dns && p.dns.answers.length) rows.push(["Answers", p.dns.answers.map(a => `${a.type} ${a.data} (ttl ${a.ttl})`).join("\n")]);
  if (p.tls && p.tls.sni) rows.push(["SNI", p.tls.sni]);
  if (p.http && p.http.host) rows.push(["HTTP", `${p.http.method} http://${p.http.host}${p.http.path}`]);
  if (p.dhcp) rows.push(["DHCP", `${p.dhcp.type} client ${p.dhcp.chaddr}${p.dhcp.hostname ? ` (${p.dhcp.hostname})` : ""}`]);
  $("#pk-detail").innerHTML = `<h4>${esc(p.info)}</h4><dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v).replace(/\n/g, "<br>")}</dd>`).join("")}</dl>
    <div class="hex">${esc(hexdump(state.bytes.subarray(p.off, p.off + p.caplen)))}</div>`;
}

function hexdump(b) {
  const lines = [];
  for (let o = 0; o < Math.min(b.length, 4096); o += 16) {
    const chunk = b.subarray(o, o + 16);
    const hex = [...chunk].map(x => x.toString(16).padStart(2, "0")).join(" ");
    const asc = [...chunk].map(x => (x >= 32 && x < 127 ? String.fromCharCode(x) : ".")).join("");
    lines.push(`${o.toString(16).padStart(4, "0")}  ${hex.padEnd(47)}  ${asc}`);
  }
  if (b.length > 4096) lines.push(`… ${b.length - 4096} more bytes`);
  return lines.join("\n");
}

if (new URLSearchParams(location.search).has("sample")) loadSample();
