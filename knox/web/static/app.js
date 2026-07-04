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
  if (d.ip && d.ip === state.gateway) return { icon: "🌐", role: "Router / gateway" };
  const hay = `${d.hostname || ""} ${d.vendor || ""} ${d.label || ""}`.toLowerCase();
  const has = (...xs) => xs.some((x) => hay.includes(x));
  if (has("docker")) return { icon: "🐳", role: "Container host" };
  if (has("reolink", "blink", "camera", "cam-", "wyze", "nest cam")) return { icon: "📷", role: "Camera" };
  if (has("roku", "tcl", "-tv", "tv.", "firetv", "chromecast", "vizio", "appletv")) return { icon: "📺", role: "TV / streamer" };
  if (has("xbox", "playstation", "-ps5", "nintendo")) return { icon: "🎮", role: "Game console" };
  if (has("echo", "alexa", "sonos", "homepod")) return { icon: "🔊", role: "Smart speaker" };
  if (has("pixel", "galaxy", "iphone", "-s22", "-s23", "-a13", "-a53", "phone", "oneplus")) return { icon: "📱", role: "Phone" };
  if (has("ipad", "tab-s", "tablet")) return { icon: "📲", role: "Tablet" };
  if (has("desktop", "-pc", "macbook", "laptop", "thinkpad")) return { icon: "💻", role: "Computer" };
  if (has("ruijie", "tp-link", "tplink", "netgear", "ubiquiti", "asus", "eero", "router")) return { icon: "🛜", role: "Network gear" };
  if (has("amazon")) return { icon: "🔊", role: "Amazon device" };
  if (has("samsung")) return { icon: "📱", role: "Samsung device" };
  return { icon: "🖥️", role: d.vendor && d.vendor !== "Unknown" ? d.vendor : "Unknown device" };
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
    const { icon, role } = classify(d);
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
          <span class="dev-icon">${icon}</span>
          <span class="dev-name">
            <span class="name">${esc(displayName)} ${statusTag}
              <span class="edit" title="Rename" onclick="rename('${d.mac}', '${esc(d.label || "")}')">✎</span>
            </span>
            <span class="role">${esc(role)}</span>
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
    ul.innerHTML = '<li class="empty">No alerts — all quiet. 🟢</li>';
    return;
  }
  ul.innerHTML = data.alerts.map((a) => `
    <li class="alert ${a.acknowledged ? "ack" : ""}">
      <span class="a-icon">${a.type === "new_device" ? "🆕" : "⚠️"}</span>
      <div class="a-body">
        <div class="a-msg">${esc(a.message)}</div>
        <div class="a-when">${esc(fmtTime(a.created_at))}</div>
      </div>
      ${a.acknowledged ? "" : `<button class="a-dismiss" title="Dismiss" onclick="ackAlert(${a.id})">✕</button>`}
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
