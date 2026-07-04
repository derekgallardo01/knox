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
    <span><b>Trusted</b> ${d.trusted ? "yes" : "no"}</span>
    <span><b>Last seen</b> ${esc(fmtTime(d.last_seen))}</span>
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

function refresh() { loadDevice().catch(() => {}); loadTimeline().catch(() => {}); }

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
