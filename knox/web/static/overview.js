"use strict";

let hours = 24;

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtBytes(n) {
  if (n < 1024) return (n | 0) + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + " " + u[i];
}

// Area/line chart from [{at, value}]. fmtY formats the max label.
function lineChart(points, opts = {}) {
  if (!points.length) return '<div class="muted">No data yet.</div>';
  const w = 760, h = 120, pad = 4;
  const vals = points.map((p) => p.value);
  const max = Math.max(...vals, opts.min || 1);
  const n = points.length;
  const x = (i) => (n === 1 ? w / 2 : (i / (n - 1)) * (w - pad * 2) + pad);
  const y = (v) => h - pad - (v / max) * (h - pad * 2);
  const line = points.map((p, i) => `${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join(" ");
  const area = `${pad},${h - pad} ${line} ${w - pad},${h - pad}`;
  const color = opts.color || "var(--accent)";
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="ov-chart">
      <polygon points="${area}" fill="${color}" fill-opacity="0.12"/>
      <polyline points="${line}" fill="none" stroke="${color}" stroke-width="1.5"/>
    </svg>
    <div class="chart-axis"><span>${esc(opts.startLabel || "")}</span><span>peak ${esc(opts.fmtY ? opts.fmtY(max) : max)}</span><span>now</span></div>`;
}

function barList(rows, label, valFmt) {
  if (!rows.length) return `<div class="muted">${label}</div>`;
  const max = Math.max(...rows.map((r) => r.value), 1);
  return `<div class="bars">${rows.map((r) => `
    <div class="bar-row">
      <span class="bar-label mono" title="${esc(r.name)}">${esc(r.name)}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${(r.value / max * 100).toFixed(1)}%"></span></span>
      <span class="bar-val">${esc(valFmt(r.value))}</span>
    </div>`).join("")}</div>`;
}

async function load() {
  const d = await (await fetch(`/api/overview?hours=${hours}`)).json();

  const devPts = d.devices_series.map((s) => ({ at: s.at, value: s.online }));
  const last = d.devices_series[d.devices_series.length - 1];
  document.getElementById("dev-now").textContent = last ? `${last.online}/${last.total} online now` : "";
  document.getElementById("chart-devices").innerHTML = lineChart(devPts, {
    color: "var(--online)",
    startLabel: `${hours}h ago`,
    fmtY: (v) => v + " devices",
  });

  const bwPts = d.bandwidth_series.map((s) => ({ at: s.at, value: s.bytes }));
  document.getElementById("bw-note").textContent = d.capture_on ? "" : "capture off (KNOX_CAPTURE=1)";
  document.getElementById("chart-bw").innerHTML = lineChart(bwPts, {
    color: "var(--accent)",
    startLabel: `${hours}h ago`,
    fmtY: fmtBytes,
  });

  const du = d.top_data_users || [];
  document.getElementById("top-data-users").innerHTML = du.length
    ? `<table class="ports-table"><thead><tr><th>Device</th><th>Down</th><th>Up</th><th>Total</th></tr></thead>
       <tbody>${du.map((r) => `<tr>
         <td class="mono">${esc(r.name)}</td>
         <td class="bw-dn">${fmtBytes(r.down)}</td>
         <td class="bw-up">${fmtBytes(r.up)}</td>
         <td>${fmtBytes(r.bytes)}</td></tr>`).join("")}</tbody></table>`
    : '<div class="muted">No usage recorded yet — the router poller records data as devices transfer.</div>';

  document.getElementById("top-domains").innerHTML = d.dns_on || d.top_domains.length
    ? barList(d.top_domains.map((r) => ({ name: r.domain, value: r.count })), "No domains yet.", (v) => v + "×")
    : '<div class="muted">DNS resolver off (KNOX_DNS_SERVER=1).</div>';

  document.getElementById("top-talkers").innerHTML = d.capture_on || d.top_talkers.length
    ? barList(d.top_talkers.map((r) => ({ name: r.name, value: r.bytes })), "No traffic yet.", fmtBytes)
    : '<div class="muted">Capture off (KNOX_CAPTURE=1).</div>';
}

document.getElementById("ov-range").addEventListener("click", (e) => {
  const b = e.target.closest(".chip");
  if (!b) return;
  document.querySelectorAll("#ov-range .chip").forEach((c) => c.classList.remove("active"));
  b.classList.add("active");
  hours = parseInt(b.dataset.hours, 10);
  load();
});

setInterval(load, 10000);
load();
