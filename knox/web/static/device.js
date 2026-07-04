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
  document.getElementById("dev-title").textContent = name;
  document.getElementById("dev-sub").innerHTML = `<span class="mono">${esc(d.ip || "—")}</span> · <span class="mono">${esc(d.mac)}</span>`;

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

function sparkline(series) {
  if (!series.length) return '<div class="muted">No bandwidth samples yet.</div>';
  const vals = series.map((s) => s.bytes);
  const max = Math.max(...vals, 1);
  const w = 600, h = 60, step = w / Math.max(series.length - 1, 1);
  const pts = vals.map((v, i) => `${(i * step).toFixed(1)},${(h - (v / max) * h).toFixed(1)}`).join(" ");
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="spark">
    <polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="1.5"/>
  </svg>`;
}

async function loadTraffic() {
  const t = await (await fetch(`/api/device/${encodeURIComponent(MAC)}/traffic`)).json();
  if (t.error) return;
  const panel = document.getElementById("traffic-panel");
  // Show the panel if capture is on OR we already have data.
  if (!t.capture_on && !t.flows.length) { panel.hidden = true; return; }
  panel.hidden = false;
  document.getElementById("traffic-total").textContent =
    t.total_bytes ? `${fmtBytes(t.total_bytes)} total` : (t.capture_on ? "capturing…" : "");
  document.getElementById("bw-spark").innerHTML = sparkline(t.series);
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

function refresh() {
  loadDevice().catch(() => {});
  loadTimeline().catch(() => {});
  loadTraffic().catch(() => {});
  loadDomains().catch(() => {});
}

document.getElementById("tl-range").addEventListener("click", (e) => {
  const b = e.target.closest(".chip");
  if (!b) return;
  document.querySelectorAll("#tl-range .chip").forEach((c) => c.classList.remove("active"));
  b.classList.add("active");
  hours = parseInt(b.dataset.hours, 10);
  loadTimeline();
});

setInterval(refresh, 5000);
refresh();
