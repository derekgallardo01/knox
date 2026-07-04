"use strict";

const REFRESH_MS = 5000;

const state = {
  devices: [],
  gateways: [],
  filter: "all",
  search: "",
  lastDevicesJSON: "",
  lastAlertsJSON: "",
  expanded: new Set(), // unit keys whose detail/member row is open
  details: {},         // mac -> full /api/device payload (ports etc.)
  groupDupes: true,    // collapse a device's randomized MACs into one row
  sort: { col: "last_seen", dir: "desc" },
  offlineCollapsed: true,
  selected: new Set(), // macs selected for bulk actions
  soundOn: localStorage.getItem("knox.sound") === "1",
  seenAlertIds: null,  // set of alert ids we've already notified on
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
  chevron: '<path d="m9 18 6-6-6-6"/>',
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
  if (d.ip && state.gateways.includes(d.ip)) return { icon: "router", role: "Router / gateway" };
  const hay = `${d.hostname || ""} ${d.vendor || ""} ${d.label || ""}`.toLowerCase();
  const has = (...xs) => xs.some((x) => hay.includes(x));
  if (has("docker")) return { icon: "container", role: "Container host" };
  if (has("reolink", "blink", "camera", "cam-", "wyze", "nest cam")) return { icon: "camera", role: "Camera" };
  if (has("roku", "tcl", "-tv", "tv.", "firetv", "chromecast", "vizio", "appletv")) return { icon: "tv", role: "TV / streamer" };
  if (has("xbox", "playstation", "-ps5", "nintendo")) return { icon: "gamepad", role: "Game console" };
  if (has("echo", "alexa", "sonos", "homepod")) return { icon: "speaker", role: "Smart speaker" };
  if (has("ipad", "tab-s", "tab-a", "tablet")) return { icon: "tablet", role: "Tablet" };
  if (has("pixel", "galaxy", "iphone", "-s22", "-s23", "-a13", "-a53", "phone", "oneplus")) return { icon: "smartphone", role: "Phone" };
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

// --- bulk selection --------------------------------------------------------

function updateBulkBar() {
  const bar = document.getElementById("bulk-bar");
  const n = state.selected.size;
  bar.hidden = n === 0;
  if (n) document.getElementById("bulk-count").textContent = `${n} selected`;
}

function clearSelection() {
  state.selected.clear();
  renderDevices();
  updateBulkBar();
}

async function bulkTrust(trusted) {
  const macs = [...state.selected];
  if (!macs.length) return;
  await post("/api/devices/trust", { macs, trusted });
  state.selected.clear();
  updateBulkBar();
  refresh(true);
}

// --- expand / detail -------------------------------------------------------

async function loadDetail(mac) {
  try {
    const res = await fetch(`/api/device/${encodeURIComponent(mac)}`);
    state.details[mac] = await res.json();
  } catch (e) {
    state.details[mac] = { port_list: [], error: true };
  }
  renderDevices();
}

function toggleExpand(key, mac) {
  if (state.expanded.has(key)) {
    state.expanded.delete(key);
  } else {
    state.expanded.add(key);
    if (mac && !state.details[mac]) loadDetail(mac); // lazy fetch (single device)
  }
  renderDevices();
}

function renderDetail(mac) {
  const det = state.details[mac];
  if (!det) return '<div class="detail-body muted">Loading…</div>';
  const ports = det.port_list || [];
  const meta = `
    <div class="detail-meta">
      <span><b>MAC</b> <span class="mono">${esc(det.mac)}</span></span>
      <span><b>Hostname</b> ${esc(det.hostname || "—")}</span>
      <span><b>Vendor</b> ${esc(det.vendor || "—")}</span>
      <span><b>First seen</b> ${esc(fmtTime(det.first_seen))}</span>
    </div>`;
  let portsHtml;
  if (!ports.length) {
    portsHtml = det.error
      ? '<div class="muted">Could not load ports.</div>'
      : '<div class="muted">No open ports found — device blocks scans, or a scan is still pending.</div>';
  } else {
    portsHtml = `<table class="ports-table">
      <thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th></tr></thead>
      <tbody>${ports.map((p) => `<tr>
        <td class="mono">${p.port}</td>
        <td>${esc(p.proto)}</td>
        <td>${esc(p.service || "—")}</td>
        <td class="muted">${esc(p.version || "—")}</td>
      </tr>`).join("")}</tbody>
    </table>`;
  }

  const hints = det.hints || [];
  let hintsHtml = "";
  if (hints.length) {
    hintsHtml = `<div class="detail-hints"><b>Identified via (passive)</b>
      <table class="ports-table">
        <thead><tr><th>Source</th><th>Field</th><th>Value</th></tr></thead>
        <tbody>${hints.map((h) => `<tr>
          <td><span class="src-badge src-${esc(h.source)}">${esc(h.source)}</span></td>
          <td class="muted">${esc(h.key)}</td>
          <td class="mono">${esc(h.value)}</td>
        </tr>`).join("")}</tbody>
      </table></div>`;
  }

  return `<div class="detail-body">${meta}<div class="detail-ports"><b>Open ports / services</b>${portsHtml}</div>${hintsHtml}</div>`;
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

function displayName(d) {
  return d.label || d.hostname || (d.vendor && d.vendor !== "Unknown" ? d.vendor : "Unknown");
}

// Collapse devices into "units": a group of one device's MACs, or a single one.
function buildUnits(devs) {
  if (!state.groupDupes) return devs.map((d) => ({ key: d.mac, members: [d], rep: d }));
  const map = new Map();
  for (const d of devs) {
    const k = d.group || d.mac;
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(d);
  }
  const units = [];
  for (const [key, members] of map) {
    const rep = members.find((m) => m.trusted) ||
      members.slice().sort((a, b) => (b.last_seen || "").localeCompare(a.last_seen || ""))[0];
    units.push({ key, members, rep });
  }
  return units;
}

const unitOnline = (u) => u.members.some((m) => m.online);
const unitPorts = (u) => u.members.reduce((s, m) => s + (m.ports || 0), 0);
const unitLastSeen = (u) => u.members.reduce((a, m) => (m.last_seen > a ? m.last_seen : a), "");

function sortUnits(units) {
  const { col, dir } = state.sort;
  const mul = dir === "asc" ? 1 : -1;
  const key = (u) => {
    switch (col) {
      case "name": return displayName(u.rep).toLowerCase();
      case "ip": return (u.rep.ip || "").split(".").map((o) => o.padStart(3, "0")).join(".");
      case "vendor": return (u.rep.vendor || "").toLowerCase();
      case "ports": return unitPorts(u);
      default: return unitLastSeen(u);
    }
  };
  return units.sort((a, b) => {
    const va = key(a), vb = key(b);
    return va < vb ? -mul : va > vb ? mul : 0;
  });
}

function memberList(u) {
  return `<div class="member-list">${u.members.map((m) => {
    const tb = m.trusted
      ? `<button class="row-btn" onclick="trust('${m.mac}', false)">Untrust</button>`
      : `<button class="row-btn" onclick="trust('${m.mac}', true)">Trust</button>`;
    return `<div class="member-row">
      <span class="dot ${m.online ? "online" : "offline"}"></span>
      <span class="mono">${esc(m.ip || "—")}</span>
      <span class="mono">${esc(m.mac)}</span>
      <span class="muted">${m.online ? ago(m.last_seen) : "offline"}</span>
      <span class="member-actions">${tb}<a class="row-btn" href="/device/${encodeURIComponent(m.mac)}">Details</a></span>
    </div>`;
  }).join("")}</div>`;
}

function unitRow(u) {
  const d = u.rep;
  const isGroup = u.members.length > 1;
  const online = unitOnline(u);
  const cls = classify(d);
  const isGw = state.gateways.includes(d.ip);
  const open = state.expanded.has(u.key);
  const statusTag = isGw
    ? '<span class="tag gateway">gateway</span>'
    : (d.trusted ? '<span class="tag trusted">trusted</span>' : '<span class="tag untrusted">unknown</span>');
  const countBadge = isGroup ? `<span class="tag count">×${u.members.length}</span>` : "";
  const ports = unitPorts(u);
  const portCls = ports > 0 ? "pill-ports has" : "pill-ports";
  const lastSeen = unitLastSeen(u);
  const trustBtn = d.trusted
    ? `<button class="row-btn" onclick="trust('${d.mac}', false)">Untrust</button>`
    : `<button class="row-btn" onclick="trust('${d.mac}', true)">Trust</button>`;
  const macCell = isGroup ? `<span class="muted">${u.members.length} MACs</span>` : esc(d.mac);
  const memberMacs = u.members.map((m) => m.mac);
  const checked = memberMacs.every((m) => state.selected.has(m)) ? "checked" : "";
  const mainRow = `<tr class="dev-row ${open ? "open" : ""}" data-key="${esc(u.key)}" data-mac="${isGroup ? "" : esc(d.mac)}">
      <td class="check-col"><input type="checkbox" class="row-check" data-macs="${esc(memberMacs.join(","))}" ${checked} /></td>
      <td><span class="dot ${online ? "online" : "offline"}"></span></td>
      <td>
        <div class="device-cell">
          <span class="chevron ${open ? "open" : ""}">${icon("chevron")}</span>
          <span class="dev-icon ${isGw ? "gw" : ""}">${icon(cls.icon)}</span>
          <span class="dev-name">
            <span class="name">${esc(displayName(d))} ${countBadge} ${statusTag}
              <span class="edit" title="Rename" onclick="rename('${d.mac}', '${esc(d.label || "")}')">${icon("pencil", "sm")}</span>
            </span>
            <span class="role">${esc(cls.role)}</span>
          </span>
        </div>
      </td>
      <td class="mono">${esc(d.ip || "—")}</td>
      <td class="mono">${macCell}</td>
      <td>${esc(d.vendor || "—")}</td>
      <td class="num"><span class="${portCls}">${ports}</span></td>
      <td class="muted" title="${esc(fmtTime(lastSeen))}">${online ? ago(lastSeen) : "offline"}</td>
      <td class="row-actions">${trustBtn}<a class="row-btn" href="/device/${encodeURIComponent(d.mac)}">Details</a></td>
    </tr>`;
  let detailRow = "";
  if (open) {
    const inner = isGroup ? memberList(u) : renderDetail(d.mac);
    detailRow = `<tr class="detail-row"><td colspan="9">${inner}</td></tr>`;
  }
  return mainRow + detailRow;
}

function renderDevices() {
  const tbody = document.querySelector("#devices tbody");
  updateSortCarets();
  const filtered = state.devices.filter(matchesFilter);
  if (!state.devices.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty">No devices yet — a scan is running…</td></tr>';
    return;
  }
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty">No devices match this filter.</td></tr>';
    return;
  }
  const units = sortUnits(buildUnits(filtered));
  const online = units.filter(unitOnline);
  const offline = units.filter((u) => !unitOnline(u));
  let html = online.map(unitRow).join("");
  if (offline.length) {
    html += `<tr class="offline-head ${state.offlineCollapsed ? "" : "open"}" data-offline>
      <td colspan="9"><span class="chevron ${state.offlineCollapsed ? "" : "open"}">${icon("chevron")}</span>
      Offline (${offline.length})</td></tr>`;
    if (!state.offlineCollapsed) html += offline.map(unitRow).join("");
  }
  tbody.innerHTML = html;
  updateBulkBar();
}

function updateSortCarets() {
  document.querySelectorAll("#devices thead th[data-sort]").forEach((th) => {
    th.classList.toggle("sorted", th.dataset.sort === state.sort.col);
    th.dataset.dir = th.dataset.sort === state.sort.col ? state.sort.dir : "";
  });
}

async function loadDevices(force) {
  const res = await fetch("/api/devices");
  const data = await res.json();
  state.gateways = data.gateways || [];

  document.getElementById("s-total").textContent = data.total;
  document.getElementById("s-online").textContent = data.online;
  document.getElementById("s-untrusted").textContent = data.untrusted;
  document.getElementById("s-ports").textContent = data.open_ports;
  document.getElementById("s-alerts").textContent = data.unacked_alerts;

  updateWan(data.wan);
  updatePresence(data.devices);

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

  notifyCritical(data.alerts);
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
  ul.innerHTML = data.alerts.map((a) => {
    const sev = a.severity || "warning";
    const isNew = a.type === "new_device";
    const iconName = isNew ? "join" : (sev === "critical" ? "alert" : "alert");
    const iconCls = isNew ? "join" : (sev === "critical" ? "crit" : "warn");
    const label = (a.type || "").replace(/_/g, " ");
    return `
    <li class="alert sev-${esc(sev)} ${a.acknowledged ? "ack" : ""}">
      <span class="a-icon ${iconCls}">${icon(iconName)}</span>
      <div class="a-body">
        <div class="a-msg">${esc(a.message)}</div>
        <div class="a-when"><span class="a-type">${esc(label)}</span> · ${esc(fmtTime(a.created_at))}</div>
      </div>
      ${a.acknowledged ? "" : `<button class="a-dismiss" title="Dismiss" onclick="ackAlert(${a.id})">${icon("x", "sm")}</button>`}
    </li>`;
  }).join("");
}

function updateWan(wan) {
  const pill = document.getElementById("wan-pill");
  if (!pill || !wan) return;
  if (wan.up === null || wan.up === undefined) {
    pill.className = "wan-pill";
    pill.textContent = "WAN —";
  } else if (wan.up) {
    pill.className = "wan-pill up";
    pill.textContent = `WAN up · ${wan.uptime_24h}%`;
  } else {
    pill.className = "wan-pill down";
    pill.textContent = "WAN DOWN";
  }
}

function updatePresence(devices) {
  // "Home" = owners (people) with any phone/tablet online, else the device name.
  const online = devices.filter((d) => {
    const r = classify(d).role;
    return (r === "Phone" || r === "Tablet") && d.online;
  });
  const names = new Set();
  for (const d of online) {
    names.add(d.owner && d.owner.trim() ? d.owner.trim() : (d.label || d.hostname || d.vendor || d.mac));
  }
  const wrap = document.getElementById("presence");
  const list = document.getElementById("presence-list");
  if (!wrap || !list) return;
  if (!names.size) { wrap.hidden = true; return; }
  wrap.hidden = false;
  list.innerHTML = [...names].map((n) =>
    `<span class="person"><span class="dot online"></span>${esc(n)}</span>`).join("");
}

// --- theme + sound/desktop alerts ------------------------------------------

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("knox.theme", theme);
  const btn = document.getElementById("theme-toggle");
  if (btn) btn.textContent = theme === "light" ? "☀" : "☾";
}

function initTheme() {
  applyTheme(localStorage.getItem("knox.theme") || "dark");
  const btn = document.getElementById("theme-toggle");
  if (btn) btn.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme");
    applyTheme(cur === "light" ? "dark" : "light");
  });
}

function initSound() {
  const btn = document.getElementById("sound-toggle");
  if (!btn) return;
  const render = () => { btn.textContent = state.soundOn ? "🔔" : "🔕"; };
  render();
  btn.addEventListener("click", () => {
    state.soundOn = !state.soundOn;
    localStorage.setItem("knox.sound", state.soundOn ? "1" : "0");
    if (state.soundOn && "Notification" in window && Notification.permission === "default") {
      Notification.requestPermission();
    }
    render();
  });
}

function beep() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain); gain.connect(ctx.destination);
    osc.type = "sine"; osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.15, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
    osc.start(); osc.stop(ctx.currentTime + 0.4);
  } catch (e) { /* ignore */ }
}

function notifyCritical(alerts) {
  // First load: seed the seen-set so we don't blast notifications on page open.
  if (state.seenAlertIds === null) {
    state.seenAlertIds = new Set(alerts.map((a) => a.id));
    return;
  }
  const fresh = alerts.filter(
    (a) => !a.acknowledged && a.severity === "critical" && !state.seenAlertIds.has(a.id));
  for (const a of fresh) state.seenAlertIds.add(a.id);
  if (!fresh.length || !state.soundOn) return;
  beep();
  if ("Notification" in window && Notification.permission === "granted") {
    for (const a of fresh.slice(0, 3)) {
      new Notification("Knox: critical alert", { body: a.message });
    }
  }
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

// Row click expands per-device detail; clicks on buttons/checkbox are ignored.
document.querySelector("#devices tbody").addEventListener("click", (e) => {
  if (e.target.closest("button, a, .edit, .check-col")) return;
  if (e.target.closest("tr.offline-head")) {
    state.offlineCollapsed = !state.offlineCollapsed;
    renderDevices();
    return;
  }
  const tr = e.target.closest("tr.dev-row");
  if (tr) toggleExpand(tr.dataset.key, tr.dataset.mac || null);
});

// Checkbox selection (delegated change events).
document.querySelector("#devices tbody").addEventListener("change", (e) => {
  const cb = e.target.closest(".row-check");
  if (!cb) return;
  const macs = (cb.dataset.macs || "").split(",").filter(Boolean);
  macs.forEach((m) => cb.checked ? state.selected.add(m) : state.selected.delete(m));
  updateBulkBar();
});

document.getElementById("select-all").addEventListener("change", (e) => {
  const on = e.target.checked;
  document.querySelectorAll("#devices .row-check").forEach((cb) => {
    (cb.dataset.macs || "").split(",").filter(Boolean).forEach((m) =>
      on ? state.selected.add(m) : state.selected.delete(m));
  });
  renderDevices();
  updateBulkBar();
});

document.querySelector("#devices thead").addEventListener("click", (e) => {
  const th = e.target.closest("th[data-sort]");
  if (!th) return;
  const col = th.dataset.sort;
  if (state.sort.col === col) {
    state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
  } else {
    state.sort = { col, dir: col === "last_seen" || col === "ports" ? "desc" : "asc" };
  }
  renderDevices();
});

const groupToggle = document.getElementById("group-toggle");
if (groupToggle) {
  groupToggle.addEventListener("change", (e) => {
    state.groupDupes = e.target.checked;
    renderDevices();
  });
}

initTheme();
initSound();
setInterval(() => refresh(false), REFRESH_MS);
refresh(true);
