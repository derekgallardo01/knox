"use strict";

const REFRESH_MS = 5000;

const state = {
  devices: [],
  gateway: null,
  filter: "all",
  search: "",
  lastDevicesJSON: "",
  lastAlertsJSON: "",
};

// --- icons -----------------------------------------------------------------
// Inline SVG (Lucide-style, MIT). Rendered via icon(); color = currentColor.

const ICONS = {
  router: '<rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6.01 18H6M10.01 18H10M15 10v4"/><path d="M17.84 7.17a4 4 0 0 0-5.66 0"/><path d="M20.66 4.34a8 8 0 0 0-11.31 0"/>',
  wifi: '<path d="M12 20h.01"/><path d="M2 8.82a15 15 0 0 1 20 0"/><path d="M5 12.86a10 10 0 0 1 14 0"/><path d="M8.5 16.43a5 5 0 0 1 7 0"/>',
  camera: '<path d="M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3l-2.5-3z"/><circle cx="12" cy="13" r="3"/>',
  tv: '<rect width="20" height="15" x="2" y="7" rx="2"/><polyline points="17 2 12 7 7 2"/>',
  gamepad: '<line x1="6" x2="10" y1="12" y2="12"/><line x1="8" x2="8" y1="10" y2="14"/><line x1="15" x2="15.01" y1="13" y2="13"/><line x1="18" x2="18.01" y1="11" y2="11"/><rect width="20" height="12" x="2" y="6" rx="6"/>',
  speaker: '<rect width="16" height="20" x="4" y="2" rx="2"/><circle cx="12" cy="14" r="4"/><line x1="12" x2="12.01" y1="6" y2="6"/>',
  smartphone: '<rect width="14" height="20" x="5" y="2" rx="2" ry="2"/><path d="M12 18h.01"/>',
  tablet: '<rect width="16" height="20" x="4" y="2" rx="2" ry="2"/><line x1="12" x2="12.01" y1="18" y2="18"/>',
  monitor: '<rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>',
  container: '<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/>',
  device: '<line x1="22" x2="2" y1="12" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" x2="6.01" y1="16" y2="16"/><line x1="10" x2="10.01" y1="16" y2="16"/>',
  join: '<circle cx="12" cy="12" r="10"/><path d="M8 12h8"/><path d="M12 8v8"/>',
  alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  check: '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
  pencil: '<path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/>',
  x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
};

function icon(name, extra) {
  const body = ICONS[name] || ICONS.device;
  return `<svg class="icon ${extra || ""}" viewBox="0 0 24 24" fill="none" stroke="currentColor" ` +
    `stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}

// --- helpers ---------------------------------------------------------------

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function ago(iso) {
  const secs = (Date.now() - new Date(iso).getTime()) / 1000;
  if (isNaN(secs)) return "";
  if (secs < 60) return Math.round(secs) + "s ago";
  if (secs < 3600) return Math.round(secs / 60) + "m ago";
  if (secs < 86400) return Math.round(secs / 3600) + "h ago";
  return Math.round(secs / 86400) + "d ago";
}

// Guess a device type + icon from vendor/hostname/role. Cosmetic only.
function classify(d) {
  if (d.ip && d.ip === state.gateway) return { icon: "router", role: "Router / gateway" };
  const hay = `${d.hostname || ""} ${d.vendor || ""} ${d.label || ""}`.toLowerCase();
  const has = (...xs) => xs.some((x) => hay.includes(x));
  if (has("docker")) return { icon: "container", role: "Container host" };
  if (has("reolink", "blink", "camera", "cam-", "wyze", "nest cam")) return { icon: "camera", role: "Camera" };
  if (has("roku", "tcl", "-tv", "tv.", "firetv", "chromecast", "vizio", "appletv")) return { icon: "tv", role: "TV / streamer" };
  if (has("xbox", "playstation", "-ps5", "nintendo")) return { icon: "gamepad", role: "Game console" };
  if (has("echo", "alexa", "sonos", "homepod")) return { icon: "speaker", role: "Smart speaker" };
  if (has("pixel", "galaxy", "iphone", "-s22", "-s23", "-a13", "-a53", "phone", "oneplus")) return { icon: "smartphone", role: "Phone" };
  if (has("ipad", "tab-s", "tablet")) return { icon: "tablet", role: "Tablet" };
  if (has("desktop", "-pc", "macbook", "laptop", "thinkpad")) return { icon: "monitor", role: "Computer" };
  if (has("ruijie", "tp-link", "tplink", "netgear", "ubiquiti", "asus", "eero", "router")) return { icon: "wifi", role: "Network gear" };
  if (has("amazon")) return { icon: "speaker", role: "Amazon device" };
  if (has("samsung")) return { icon: "smartphone", role: "Samsung device" };
  return { icon: "device", role: d.vendor && d.vendor !== "Unknown" ? d.vendor : "Unknown device" };
}

// --- data actions ----------------------------------------------------------

async function post(url, body) {
  await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : "{}",
  });
}

async function trust(mac, trusted) { await post(`/api/device/${encodeURIComponent(mac)}/trust`, { trusted }); refresh(true); }
async function trustAll() { await post("/api/devices/trust-all"); refresh(true); }
async function ackAlert(id) { await post(`/api/alerts/${id}/ack`); loadAlerts(true); }
async function ackAll() { await post("/api/alerts/ack-all"); loadAlerts(true); }

async function rename(mac, current) {
  const label = prompt("Name this device:", current || "");
  if (label === null) return;
  await post(`/api/device/${encodeURIComponent(mac)}/label`, { label });
  refresh(true);
}

// --- rendering -------------------------------------------------------------

function matchesFilter(d) {
  if (state.filter === "online" && !d.online) return false;
  if (state.filter === "offline" && d.online) return false;
  if (state.filter === "untrusted" && d.trusted) return false;
  if (state.search) {
    const hay = `${d.ip} ${d.mac} ${d.hostname || ""} ${d.vendor || ""} ${d.label || ""}`.toLowerCase();
    if (!hay.includes(state.search)) return false;
  }
  return true;
}

function renderDevices() {
  const tbody = document.querySelector("#devices tbody");
  const rows = state.devices.filter(matchesFilter);

  if (!state.devices.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty">No devices yet — a scan is running…</td></tr>';
    return;
  }
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty">No devices match this filter.</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map((d) => {
    const dot = d.online ? "online" : "offline";
    const cls = classify(d);
    const isGw = d.ip === state.gateway;
    const displayName = d.label || d.hostname || (d.vendor && d.vendor !== "Unknown" ? d.vendor : "Unknown");
    const statusTag = isGw
      ? '<span class="tag gateway">gateway</span>'
      : (d.trusted ? '<span class="tag trusted">trusted</span>' : '<span class="tag untrusted">unknown</span>');
    const portCls = d.ports > 0 ? "pill-ports has" : "pill-ports";
    const trustBtn = d.trusted
      ? `<button class="row-btn" onclick="trust('${d.mac}', false)">Untrust</button>`
      : `<button class="row-btn" onclick="trust('${d.mac}', true)">Trust</button>`;
    return `<tr>
      <td><span class="dot ${dot}" title="${dot}"></span></td>
      <td>
        <div class="device-cell">
          <span class="dev-icon ${isGw ? "gw" : ""}">${icon(cls.icon)}</span>
          <span class="dev-name">
            <span class="name">${esc(displayName)} ${statusTag}
              <span class="edit" title="Rename" onclick="rename('${d.mac}', '${esc(d.label || "")}')">${icon("pencil", "sm")}</span>
            </span>
            <span class="role">${esc(cls.role)}</span>
          </span>
        </div>
      </td>
      <td class="mono">${esc(d.ip || "—")}</td>
      <td class="mono">${esc(d.mac)}</td>
      <td>${esc(d.vendor || "—")}</td>
      <td class="num"><span class="${portCls}">${d.ports || 0}</span></td>
      <td class="muted" title="${esc(fmtTime(d.last_seen))}">${d.online ? ago(d.last_seen) : "offline"}</td>
      <td>${trustBtn}</td>
    </tr>`;
  }).join("");
}

async function loadDevices(force) {
  const res = await fetch("/api/devices");
  const data = await res.json();
  state.gateway = data.gateway;

  document.getElementById("s-total").textContent = data.total;
  document.getElementById("s-online").textContent = data.online;
  document.getElementById("s-untrusted").textContent = data.untrusted;
  document.getElementById("s-ports").textContent = data.open_ports;
  document.getElementById("s-alerts").textContent = data.unacked_alerts;

  const banner = document.getElementById("baseline");
  if (data.untrusted > 0) {
    banner.hidden = false;
    document.getElementById("baseline-count").textContent = data.untrusted;
  } else {
    banner.hidden = true;
  }

  // Only re-render the table when data actually changed (prevents flicker
  // while you scroll or hover), unless a user action forces it.
  const json = JSON.stringify(data.devices);
  if (force || json !== state.lastDevicesJSON) {
    state.devices = data.devices;
    state.lastDevicesJSON = json;
    renderDevices();
  }
}

async function loadAlerts(force) {
  const res = await fetch("/api/alerts");
  const data = await res.json();
  const ul = document.getElementById("alerts");

  const unacked = data.alerts.filter((a) => !a.acknowledged).length;
  const badge = document.getElementById("alert-badge");
  badge.hidden = unacked === 0;
  badge.textContent = unacked;
  document.getElementById("dismiss-all").hidden = unacked === 0;

  const json = JSON.stringify(data.alerts);
  if (!force && json === state.lastAlertsJSON) return;
  state.lastAlertsJSON = json;

  if (!data.alerts.length) {
    ul.innerHTML = `<li class="empty">${icon("check", "ok")} All quiet — no alerts.</li>`;
    return;
  }
  ul.innerHTML = data.alerts.map((a) => `
    <li class="alert ${a.acknowledged ? "ack" : ""}">
      <span class="a-icon ${a.type === "new_device" ? "join" : "warn"}">${icon(a.type === "new_device" ? "join" : "alert")}</span>
      <div class="a-body">
        <div class="a-msg">${esc(a.message)}</div>
        <div class="a-when">${esc(fmtTime(a.created_at))}</div>
      </div>
      ${a.acknowledged ? "" : `<button class="a-dismiss" title="Dismiss" onclick="ackAlert(${a.id})">${icon("x", "sm")}</button>`}
    </li>`).join("");
}

function refresh(force) {
  loadDevices(force).catch(() => {});
  loadAlerts(force).catch(() => {});
}

// --- wiring ----------------------------------------------------------------

document.getElementById("search").addEventListener("input", (e) => {
  state.search = e.target.value.trim().toLowerCase();
  renderDevices();
});

document.getElementById("filters").addEventListener("click", (e) => {
  const btn = e.target.closest(".chip");
  if (!btn) return;
  document.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
  btn.classList.add("active");
  state.filter = btn.dataset.filter;
  renderDevices();
});

setInterval(() => refresh(false), REFRESH_MS);
refresh(true);
