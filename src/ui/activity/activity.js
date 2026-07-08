"use strict";
const api = typeof browser !== "undefined" ? browser : chrome;

const TYPE_LABELS = {
  popups:    { title: "Popup blocks",       subtitle: "Sites where a popup or popunder was blocked." },
  overlays:  { title: "Overlay blocks",     subtitle: "Sites where a scam / paywall overlay was detected and neutralized." },
  redirects: { title: "Redirect blocks",    subtitle: "Sites reached through a suspicious redirect chain or ad-URL pattern." },
  phishing:  { title: "Phishing warnings",  subtitle: "Sites flagged as phishing by the heuristic scorer or a threat list." },
  clickfix:  { title: "Scam page blocks",   subtitle: 'Sites showing "press Win+R and paste this" style ClickFix instructions.' },
  downloads: { title: "Download warnings",  subtitle: "Sites that triggered a risky-download interstitial." }
};

function fmtRelative(ts) {
  const diff = Date.now() - ts;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return Math.floor(diff / 60_000) + " min ago";
  if (diff < 86_400_000) return Math.floor(diff / 3_600_000) + "h ago";
  return Math.floor(diff / 86_400_000) + "d ago";
}

function fmtAbsolute(ts) {
  return new Date(ts).toLocaleString();
}

async function loadEvents() {
  const { stats } = await api.storage.local.get({ stats: { events: [] } });
  return Array.isArray(stats?.events) ? stats.events : [];
}

async function saveEvents(events) {
  const { stats } = await api.storage.local.get({ stats: {} });
  stats.events = events;
  await api.storage.local.set({ stats });
}

function typeFromQuery() {
  const p = new URLSearchParams(location.search);
  const t = p.get("type");
  return TYPE_LABELS[t] ? t : null;
}

function render(type, events) {
  const label = TYPE_LABELS[type] || { title: "Activity", subtitle: "" };
  document.getElementById("title").textContent = label.title;
  document.getElementById("subtitle").textContent = label.subtitle;
  document.title = "Surf Shield · " + label.title;

  const filtered = events.filter((e) => e.type === type)
    .slice()
    .sort((a, b) => b.ts - a.ts); // newest first

  const content = document.getElementById("content");
  content.innerHTML = "";

  if (filtered.length === 0) {
    const div = document.createElement("div");
    div.className = "empty";
    div.textContent = "No events yet. Sites that trigger this counter will show up here.";
    content.appendChild(div);
    document.getElementById("totals").textContent = "";
    return;
  }

  const distinctHosts = new Set(filtered.map((e) => e.host));
  document.getElementById("totals").textContent =
    `${filtered.length} event${filtered.length === 1 ? "" : "s"} across ${distinctHosts.size} site${distinctHosts.size === 1 ? "" : "s"}`;

  const table = document.createElement("table");
  table.innerHTML = `
    <thead>
      <tr><th>Site</th><th>Timestamp</th><th>When</th></tr>
    </thead>
    <tbody></tbody>
  `;
  const tbody = table.querySelector("tbody");

  for (const e of filtered) {
    const tr = document.createElement("tr");
    const hostTd = document.createElement("td");
    hostTd.className = "host";
    hostTd.textContent = e.host;

    const tsTd = document.createElement("td");
    tsTd.className = "when";
    tsTd.textContent = fmtAbsolute(e.ts);

    const relTd = document.createElement("td");
    relTd.className = "when";
    relTd.textContent = fmtRelative(e.ts);

    tr.append(hostTd, tsTd, relTd);
    tbody.appendChild(tr);
  }

  content.appendChild(table);
}

async function main() {
  const type = typeFromQuery();
  if (!type) {
    document.getElementById("title").textContent = "Unknown category";
    document.getElementById("subtitle").textContent =
      "Open this page from the Surf Shield popup instead.";
    document.getElementById("clear").hidden = true;
    return;
  }
  const events = await loadEvents();
  render(type, events);

  document.getElementById("clear").addEventListener("click", async () => {
    if (!confirm("Clear all recorded activity? This wipes the ring buffer for every category.")) return;
    await saveEvents([]);
    render(type, []);
  });
}

main();
