"use strict";

const REFRESH_SECONDS = 5;

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString([], {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function ago(iso) {
  const secs = (Date.now() - new Date(iso).getTime()) / 1000;
  if (isNaN(secs)) return "";
  if (secs < 60) return Math.round(secs) + "s ago";
  if (secs < 3600) return Math.round(secs / 60) + "m ago";
  if (secs < 86400) return Math.round(secs / 3600) + "h ago";
  return Math.round(secs / 86400) + "d ago";
}

async function trust(mac, trusted) {
  await fetch(`/api/device/${encodeURIComponent(mac)}/trust`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ trusted }),
  });
  loadDevices();
}

async function ackAlert(id) {
  await fetch(`/api/alerts/${id}/ack`, { method: "POST" });
  loadAlerts();
}

async function loadDevices() {
  const res = await fetch("/api/devices");
  const data = await res.json();
  const tbody = document.querySelector("#devices tbody");

  document.getElementById("summary").textContent =
    `${data.online}/${data.total} online · ${data.untrusted} untrusted`;

  if (!data.devices.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty">No devices yet — run a scan.</td></tr>';
    return;
  }

  tbody.innerHTML = data.devices.map((d) => {
    const dot = d.online ? "online" : "offline";
    const name = d.label || d.hostname || "—";
    const trustTag = d.trusted
      ? '<span class="tag trusted">trusted</span>'
      : '<span class="tag untrusted">unknown</span>';
    const btn = d.trusted
      ? `<button onclick="trust('${d.mac}', false)">Untrust</button>`
      : `<button onclick="trust('${d.mac}', true)">Trust</button>`;
    return `<tr>
      <td><span class="dot ${dot}" title="${dot}"></span></td>
      <td class="mono">${d.ip || "—"}</td>
      <td class="mono">${d.mac}</td>
      <td>${name} ${trustTag}</td>
      <td>${d.vendor || "—"}</td>
      <td>${d.ports || 0}</td>
      <td class="muted">${fmtTime(d.first_seen)}</td>
      <td class="muted">${ago(d.last_seen)}</td>
      <td>${btn}</td>
    </tr>`;
  }).join("");
}

async function loadAlerts() {
  const res = await fetch("/api/alerts");
  const data = await res.json();
  const ul = document.getElementById("alerts");
  if (!data.alerts.length) {
    ul.innerHTML = '<li class="empty">No alerts.</li>';
    return;
  }
  ul.innerHTML = data.alerts.map((a) => `
    <li class="${a.acknowledged ? "ack" : ""}">
      ${a.acknowledged ? "" : `<button class="ackbtn" onclick="ackAlert(${a.id})">dismiss</button>`}
      ${a.message}
      <span class="when">${fmtTime(a.created_at)}</span>
    </li>`).join("");
}

function refresh() {
  loadDevices();
  loadAlerts();
}

let countdown = REFRESH_SECONDS;
setInterval(() => {
  countdown -= 1;
  if (countdown <= 0) {
    refresh();
    countdown = REFRESH_SECONDS;
  }
  const el = document.getElementById("countdown");
  if (el) el.textContent = countdown;
}, 1000);

refresh();
