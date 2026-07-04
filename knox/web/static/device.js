"use strict";

const MAC = document.querySelector(".device-main").dataset.mac;
let hours = 24;

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

async function loadDevice() {
  const d = await (await fetch(`/api/device/${encodeURIComponent(MAC)}`)).json();
  if (d.error) { document.getElementById("dev-title").textContent = "Device not found"; return; }

  const name = d.label || d.hostname || (d.vendor && d.vendor !== "Unknown" ? d.vendor : d.mac);
  document.getElementById("dev-title").innerHTML =
    esc(name) + (d.blocked ? ' <span class="tag blocked">blocked</span>' : "");
  document.getElementById("dev-sub").innerHTML = `<span class="mono">${esc(d.ip || "—")}</span> · <span class="mono">${esc(d.mac)}</span>`;
  deviceBlocked = d.blocked;
  const bb = document.getElementById("block-btn");
  if (bb) bb.textContent = d.blocked ? "Unblock" : "Block";

  document.getElementById("d-status").innerHTML = d.online
    ? '<span class="online">Online</span>' : '<span class="muted">Offline</span>';
  document.getElementById("d-ports").textContent = (d.port_list || []).length;
  document.getElementById("d-first").textContent = fmtTime(d.first_seen);

  // details: meta + ports + hints
  const ports = d.port_list || [];
  const hints = d.hints || [];
  const meta = `<div class="detail-meta">
    <span><b>Vendor</b> ${esc(d.vendor || "—")}</span>
    <span><b>Hostname</b> ${esc(d.hostname || "—")}</span>
    <span><b>OS</b> ${esc(d.os || "—")}</span>
    <span><b>Trusted</b> ${d.trusted ? "yes" : "no"}</span>
    <span><b>Owner</b> ${esc(d.owner || "—")} <a class="editlink" onclick="setOwner('${esc(d.owner || "")}')">edit</a></span>
    <span><b>Last seen</b> ${esc(fmtTime(d.last_seen))}</span>
  </div>
  <div class="detail-notes"><b>Notes</b>
    <div class="notes-text">${esc(d.notes || "—")} <a class="editlink" onclick="setNotes()">edit</a></div>
  </div>`;
  const portsTable = ports.length
    ? `<table class="ports-table"><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th></tr></thead>
       <tbody>${ports.map((p) => `<tr><td class="mono">${p.port}</td><td>${esc(p.proto)}</td><td>${esc(p.service || "—")}</td><td class="muted">${esc(p.version || "—")}</td></tr>`).join("")}</tbody></table>`
    : '<div class="muted">No open ports found.</div>';
  const hintsTable = hints.length
    ? `<div class="detail-hints"><b>Identified via (passive)</b><table class="ports-table">
       <thead><tr><th>Source</th><th>Field</th><th>Value</th></tr></thead>
       <tbody>${hints.map((h) => `<tr><td><span class="src-badge src-${esc(h.source)}">${esc(h.source)}</span></td><td class="muted">${esc(h.key)}</td><td class="mono">${esc(h.value)}</td></tr>`).join("")}</tbody></table></div>`
    : "";
  document.getElementById("dev-detail").innerHTML =
    `${meta}<div class="detail-ports"><b>Open ports / services</b>${portsTable}</div>${hintsTable}`;
}

async function loadTimeline() {
  const t = await (await fetch(`/api/device/${encodeURIComponent(MAC)}/timeline?hours=${hours}`)).json();
  if (t.error) return;
  document.getElementById("d-uptime").textContent = t.uptime_pct + "%";
  document.getElementById("tl-hours").textContent = hours;
  document.getElementById("tl-start").textContent = fmtTime(t.start);
  document.getElementById("timeline").innerHTML = t.buckets
    .map((on) => `<span class="tl-cell ${on ? "on" : "off"}"></span>`).join("");
}

function fmtBytes(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + " " + u[i];
}

let bwHours = 24;

// Down (green area) + up (blue line) bandwidth chart from bw samples.
function bwChart(series) {
  if (!series.length) return '<div class="muted">No bandwidth samples yet — the router poller records these as devices transfer.</div>';
  const w = 700, h = 90, pad = 3;
  const max = Math.max(...series.map((s) => Math.max(s.down || 0, s.up || 0)), 1);
  const n = series.length;
  const x = (i) => (n === 1 ? w / 2 : (i / (n - 1)) * (w - pad * 2) + pad);
  const y = (v) => h - pad - (v / max) * (h - pad * 2);
  const dLine = series.map((s, i) => `${x(i).toFixed(1)},${y(s.down || 0).toFixed(1)}`).join(" ");
  const uLine = series.map((s, i) => `${x(i).toFixed(1)},${y(s.up || 0).toFixed(1)}`).join(" ");
  const dArea = `${pad},${h - pad} ${dLine} ${w - pad},${h - pad}`;
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="ov-chart">
      <polygon points="${dArea}" fill="var(--online)" fill-opacity="0.14"/>
      <polyline points="${dLine}" fill="none" stroke="var(--online)" stroke-width="1.5"/>
      <polyline points="${uLine}" fill="none" stroke="var(--accent)" stroke-width="1.5"/>
    </svg>
    <div class="chart-axis"><span class="bw-dn">↓ download</span><span class="bw-up">↑ upload</span></div>`;
}

function usageBox(label, u) {
  return `<div class="usage-box"><span class="usage-label">${label}</span>
    <span class="usage-val"><span class="bw-dn">↓${fmtBytes(u.down)}</span> <span class="bw-up">↑${fmtBytes(u.up)}</span></span></div>`;
}

async function loadTraffic() {
  const t = await (await fetch(`/api/device/${encodeURIComponent(MAC)}/traffic?hours=${bwHours}`)).json();
  if (t.error) return;
  const panel = document.getElementById("traffic-panel");
  const hasUsage = t.usage && t.usage.d7 && t.usage.d7.total > 0;
  if (!t.capture_on && !t.flows.length && !hasUsage) { panel.hidden = true; return; }
  panel.hidden = false;
  const u = t.usage || {};
  document.getElementById("bw-usage").innerHTML =
    usageBox("Last hour", u.h1 || { down: 0, up: 0 }) +
    usageBox("Last 24h", u.h24 || { down: 0, up: 0 }) +
    usageBox("Last 7 days", u.d7 || { down: 0, up: 0 });
  document.getElementById("bw-spark").innerHTML = bwChart(t.series);
  document.getElementById("flows").innerHTML = t.flows.length
    ? `<table class="ports-table"><thead><tr><th>Endpoint</th><th>Port</th><th>Proto</th><th>Data</th><th>Pkts</th></tr></thead>
       <tbody>${t.flows.map((f) => `<tr>
         <td class="mono">${esc(f.remote_host || f.remote_ip)}</td>
         <td class="mono">${f.dport || "—"}</td>
         <td>${esc(f.proto)}</td>
         <td>${fmtBytes(f.bytes)}</td>
         <td class="muted">${f.packets}</td></tr>`).join("")}</tbody></table>`
    : '<div class="muted">No flows captured yet. Enable capture with KNOX_CAPTURE=1 (elevated).</div>';
}

async function loadDomains() {
  const r = await (await fetch(`/api/device/${encodeURIComponent(MAC)}/domains`)).json();
  if (r.error) return;
  const panel = document.getElementById("domains-panel");
  if (!r.dns_on && !r.domains.length) { panel.hidden = true; return; }
  panel.hidden = false;
  document.getElementById("domains-total").textContent =
    r.domains.length ? `${r.domains.length} domains` : (r.dns_on ? "waiting for lookups…" : "");
  document.getElementById("domains").innerHTML = r.domains.length
    ? `<table class="ports-table"><thead><tr><th>Domain</th><th>Lookups</th><th>Last</th></tr></thead>
       <tbody>${r.domains.map((d) => `<tr>
         <td class="mono">${esc(d.domain)}</td>
         <td>${d.count}</td>
         <td class="muted">${esc(fmtTime(d.last_seen))}</td></tr>`).join("")}</tbody></table>`
    : '<div class="muted">No lookups yet. Point this device\'s DNS at Knox (KNOX_DNS_SERVER=1).</div>';
}

async function post(url, body) {
  await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}
async function setOwner(current) {
  const owner = prompt("Assign an owner (person) for this device:", current || "");
  if (owner === null) return;
  await post(`/api/device/${encodeURIComponent(MAC)}/owner`, { owner });
  loadDevice();
}
async function setNotes() {
  const notes = prompt("Notes for this device:", "");
  if (notes === null) return;
  await post(`/api/device/${encodeURIComponent(MAC)}/notes`, { notes });
  loadDevice();
}
let deviceBlocked = false;
async function wake() {
  const r = await (await fetch(`/api/device/${encodeURIComponent(MAC)}/wake`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).json();
  const btn = document.getElementById("wake-btn");
  btn.textContent = r.ok ? "Magic packet sent ✓" : "Wake failed";
  setTimeout(() => (btn.textContent = "Wake (WoL)"), 2500);
}
async function toggleBlock() {
  await post(`/api/device/${encodeURIComponent(MAC)}/block`, { blocked: !deviceBlocked });
  loadDevice();
}

function fmtDur(secs) {
  if (secs == null) return "—";
  const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60);
  if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m`;
  return `${secs}s`;
}

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function renderHeatmap(grid) {
  if (!grid || !grid.length) return '<div class="muted">No presence data yet.</div>';
  let html = '<div class="heatmap">';
  html += '<div class="hm-row hm-hours"><span class="hm-day"></span>' +
    Array.from({ length: 24 }, (_, h) => `<span class="hm-cell hm-hour">${h % 6 === 0 ? h : ""}</span>`).join("") + "</div>";
  grid.forEach((row, di) => {
    html += `<div class="hm-row"><span class="hm-day">${DAYS[di]}</span>` +
      row.map((v) => `<span class="hm-cell" style="background:${heatColor(v)}" title="${Math.round(v * 100)}%"></span>`).join("") +
      "</div>";
  });
  return html + "</div>";
}

function heatColor(v) {
  if (v <= 0) return "var(--bg-elev)";
  // accent-blue with alpha scaled by intensity
  const a = 0.15 + v * 0.85;
  return `rgba(88,166,255,${a.toFixed(2)})`;
}

async function loadSessions() {
  const s = await (await fetch(`/api/device/${encodeURIComponent(MAC)}/sessions`)).json();
  if (s.error) return;
  const st = s.stats;
  const cur = st.open_since ? `online since ${fmtTime(st.open_since)}` : "offline";
  document.getElementById("conn-stats").textContent =
    `${st.count} sessions · avg ${fmtDur(st.avg_secs)} · longest ${fmtDur(st.longest_secs)} · ${cur}`;
  document.getElementById("heatmap").innerHTML = renderHeatmap(s.heatmap);
  document.getElementById("session-log").innerHTML = s.sessions.length
    ? `<table class="ports-table"><thead><tr><th>Connected</th><th>Disconnected</th><th>Duration</th></tr></thead>
       <tbody>${s.sessions.map((x) => `<tr>
         <td>${esc(fmtTime(x.connected_at))}</td>
         <td>${x.online ? '<span class="online">online now</span>' : esc(fmtTime(x.disconnected_at))}</td>
         <td>${x.online ? "—" : fmtDur(x.duration_secs)}</td></tr>`).join("")}</tbody></table>`
    : '<div class="muted">No connection history yet — it builds as the monitor runs.</div>';
}

function refresh() {
  loadDevice().catch(() => {});
  loadTimeline().catch(() => {});
  loadTraffic().catch(() => {});
  loadDomains().catch(() => {});
  loadSessions().catch(() => {});
}

document.getElementById("tl-range").addEventListener("click", (e) => {
  const b = e.target.closest(".chip");
  if (!b) return;
  document.querySelectorAll("#tl-range .chip").forEach((c) => c.classList.remove("active"));
  b.classList.add("active");
  hours = parseInt(b.dataset.hours, 10);
  loadTimeline();
});

document.getElementById("bw-range").addEventListener("click", (e) => {
  const b = e.target.closest(".chip");
  if (!b) return;
  document.querySelectorAll("#bw-range .chip").forEach((c) => c.classList.remove("active"));
  b.classList.add("active");
  bwHours = parseInt(b.dataset.hours, 10);
  loadTraffic();
});

setInterval(refresh, 5000);
refresh();
