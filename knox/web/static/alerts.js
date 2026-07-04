"use strict";

const ICONS = {
  join: '<circle cx="12" cy="12" r="10"/><path d="M8 12h8"/><path d="M12 8v8"/>',
  alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  check: '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
  x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
};
function icon(n, extra) {
  return `<svg class="icon ${extra || ""}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ICONS.alert}</svg>`;
}
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtTime(iso) {
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

const els = {
  search: document.getElementById("a-search"),
  severity: document.getElementById("a-severity"),
  type: document.getElementById("a-type"),
  unacked: document.getElementById("a-unacked"),
  list: document.getElementById("alerts-list"),
  count: document.getElementById("alerts-count"),
};

let typesLoaded = false;

async function post(url) {
  await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
}
async function ackAlert(id) { await post(`/api/alerts/${id}/ack`); load(); }
async function ackAll() { await post("/api/alerts/ack-all"); load(); }

async function load() {
  const p = new URLSearchParams({ limit: "500" });
  if (els.search.value.trim()) p.set("search", els.search.value.trim());
  if (els.severity.value) p.set("severity", els.severity.value);
  if (els.type.value) p.set("type", els.type.value);
  if (els.unacked.checked) p.set("unacked", "1");

  const data = await (await fetch(`/api/alerts?${p}`)).json();
  els.count.textContent = `${data.alerts.length} shown`;

  if (!typesLoaded && data.types) {
    typesLoaded = true;
    for (const t of data.types) {
      const o = document.createElement("option");
      o.value = t; o.textContent = t.replace(/_/g, " ");
      els.type.appendChild(o);
    }
  }

  if (!data.alerts.length) {
    els.list.innerHTML = `<li class="empty">${icon("check", "ok")} No alerts match.</li>`;
    return;
  }
  els.list.innerHTML = data.alerts.map((a) => {
    const sev = a.severity || "warning";
    const isNew = a.type === "new_device";
    const iconCls = isNew ? "join" : (sev === "critical" ? "crit" : "warn");
    return `<li class="alert sev-${esc(sev)} ${a.acknowledged ? "ack" : ""}">
      <span class="a-icon ${iconCls}">${icon(isNew ? "join" : "alert")}</span>
      <div class="a-body">
        <div class="a-msg">${esc(a.message)}</div>
        <div class="a-when"><span class="a-type">${esc((a.type || "").replace(/_/g, " "))}</span> · ${esc(fmtTime(a.created_at))}${a.mac ? " · " + esc(a.mac) : ""}</div>
      </div>
      ${a.acknowledged ? "" : `<button class="a-dismiss" title="Dismiss" onclick="ackAlert(${a.id})">${icon("x", "sm")}</button>`}
    </li>`;
  }).join("");
}

["input", "change"].forEach((ev) => {
  els.search.addEventListener(ev, load);
  els.severity.addEventListener(ev, load);
  els.type.addEventListener(ev, load);
  els.unacked.addEventListener(ev, load);
});
document.getElementById("ack-all").addEventListener("click", ackAll);

setInterval(load, 5000);
load();
