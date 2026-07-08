"use strict";
const api = typeof browser !== "undefined" ? browser : chrome;

// Cloudflare Worker URL for one-click scam reports. Empty = feature hidden
// (safe default for forks that haven't deployed their own Worker). See
// worker/README.md for deploy steps.
const REPORT_ENDPOINT = "https://surf-shield-report.thureinoo.workers.dev";

let currentHost = null;
let currentHostListed = false;
let currentTabUrl = null;
let allowlist = [];
let blocklist = [];
let tempAllow = {};
let reportReason = null;
let reportSending = false;

function isTempTrusted(domain) {
  return (tempAllow[domain] || 0) > Date.now();
}

function send(msg) {
  return new Promise((resolve) => api.runtime.sendMessage(msg, resolve));
}

function renderStats(stats) {
  for (const key of ["popups", "overlays", "redirects", "phishing", "clickfix", "downloads"]) {
    document.getElementById(`stat-${key}`).textContent = stats[key] || 0;
  }
}

// Clicking a stat card opens the activity page filtered to that category,
// so the user can see WHICH sites triggered each counter and when.
for (const el of document.querySelectorAll(".stat[data-type]")) {
  el.addEventListener("click", () => {
    const type = el.getAttribute("data-type");
    api.tabs.create({
      url: api.runtime.getURL(`src/ui/activity/activity.html?type=${encodeURIComponent(type)}`)
    });
  });
}

function renderDomainList(elementId, entries, removeType) {
  const ul = document.getElementById(elementId);
  ul.innerHTML = "";
  if (entries.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "None";
    ul.appendChild(li);
    return;
  }
  for (const { domain, temp } of entries) {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.textContent = domain;
    if (temp) {
      const tag = document.createElement("span");
      tag.className = "temp-tag";
      tag.textContent = "1h";
      tag.title = "Trusted temporarily — expires automatically";
      span.appendChild(tag);
    }
    const btn = document.createElement("button");
    btn.textContent = "✕";
    btn.title = "Remove";
    btn.addEventListener("click", async () => {
      await send({ type: removeType, domain });
      await refresh();
    });
    li.append(span, btn);
    ul.appendChild(li);
  }
}

function renderSiteButtons() {
  const btn = document.getElementById("toggle-site");
  const blockBtn = document.getElementById("block-site");
  if (!currentHost) {
    btn.disabled = true;
    btn.textContent = "N/A";
    blockBtn.disabled = true;
    return;
  }
  const trusted = allowlist.includes(currentHost) || isTempTrusted(currentHost);
  if (currentHostListed && !trusted) {
    // On the shared/threat blocklists: only one-time bypass from the warning
    // page is possible — no trust from here.
    btn.disabled = true;
    btn.textContent = "Trust this site";
    btn.title = "This domain is on a threat blocklist — it can only be bypassed one visit at a time from the warning page.";
  } else {
    btn.disabled = false;
    btn.textContent = trusted ? "Re-enable protection" : "Trust this site";
    btn.classList.toggle("trusted", trusted);
  }

  blockBtn.disabled = false;
  const blocked = blocklist.includes(currentHost);
  blockBtn.textContent = blocked ? "Unblock" : "Block";
  blockBtn.classList.toggle("blocked", blocked);
}

async function refresh() {
  const state = await send({ type: "get-state" });
  allowlist = state.allowlist || [];
  blocklist = state.blocklist || [];
  tempAllow = state.tempAllow || {};
  renderStats(state.stats || {});
  if (state.statsSince) {
    document.getElementById("stats-since").textContent =
      "since " + new Date(state.statsSince).toLocaleDateString();
  }
  const trustedEntries = [
    ...allowlist.map((domain) => ({ domain, temp: false })),
    ...Object.keys(tempAllow).filter(isTempTrusted).map((domain) => ({ domain, temp: true }))
  ];
  renderDomainList("allowlist", trustedEntries, "allowlist-remove");
  renderDomainList("blocklist", blocklist.map((domain) => ({ domain })), "blocklist-remove");
  renderSiteButtons();
}

function setupReportButton() {
  const btn = document.getElementById("report-scam");
  const form = document.getElementById("report-form");
  const cancel = document.getElementById("report-cancel");
  const submit = document.getElementById("report-submit");
  const notes = document.getElementById("report-notes");
  const status = document.getElementById("report-status");

  // Only show when we have a URL to report AND a Worker endpoint configured.
  if (!REPORT_ENDPOINT || !currentTabUrl || !currentHost) {
    btn.hidden = true;
    return;
  }
  btn.hidden = false;
  btn.disabled = false;

  btn.addEventListener("click", () => {
    btn.hidden = true;
    form.hidden = false;
    status.hidden = true;
  });

  cancel.addEventListener("click", () => {
    form.hidden = true;
    btn.hidden = false;
    resetForm();
  });

  for (const chip of document.querySelectorAll(".chip")) {
    chip.addEventListener("click", () => {
      for (const c of document.querySelectorAll(".chip")) c.classList.remove("selected");
      chip.classList.add("selected");
      reportReason = chip.dataset.reason;
      submit.disabled = false;
    });
  }

  submit.addEventListener("click", async () => {
    if (reportSending || !reportReason) return;
    reportSending = true;
    submit.disabled = true;
    submit.textContent = "Sending…";

    try {
      const res = await fetch(REPORT_ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          url: currentTabUrl,
          reason: reportReason,
          notes: notes.value.trim(),
          version: api.runtime.getManifest().version
        })
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.ok) {
        showStatus(status, "ok",
          data.deduped
            ? `Thanks — added your report to existing issue #${data.issue}.`
            : `Thanks! Report filed as issue #${data.issue}.` +
              (data.url ? ` <a href="${data.url}" target="_blank">View</a>` : ""));
        setTimeout(() => { form.hidden = true; btn.hidden = false; resetForm(); }, 3500);
      } else {
        showStatus(status, "err", `Failed: ${data.error || res.status}`);
      }
    } catch (e) {
      showStatus(status, "err", `Network error — check your connection.`);
    } finally {
      reportSending = false;
      submit.disabled = false;
      submit.textContent = "Send report";
    }
  });

  function resetForm() {
    reportReason = null;
    notes.value = "";
    submit.disabled = true;
    status.hidden = true;
    for (const c of document.querySelectorAll(".chip")) c.classList.remove("selected");
  }
}

function showStatus(el, kind, html) {
  el.className = "report-status " + kind;
  el.innerHTML = html;
  el.hidden = false;
}

async function init() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  try {
    const url = new URL(tab.url);
    if (url.protocol === "http:" || url.protocol === "https:") {
      currentHost = url.hostname;
      currentTabUrl = tab.url;
      document.getElementById("site-host").textContent = currentHost;
      const status = await send({ type: "list-status", domain: currentHost });
      currentHostListed = !!(status && status.listed);
    }
  } catch {}

  setupReportButton();

  document.getElementById("open-options").addEventListener("click", () => {
    api.runtime.openOptionsPage();
  });

  try {
    const allowed = await api.extension.isAllowedIncognitoAccess();
    if (!allowed) document.getElementById("incognito-nudge").hidden = false;
  } catch {}

  const vtBtn = document.getElementById("vt-check");
  if (currentHost) {
    vtBtn.disabled = false;
    vtBtn.addEventListener("click", () => {
      api.tabs.create({
        url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(currentHost)}`
      });
    });
  }

  document.getElementById("toggle-site").addEventListener("click", async () => {
    if (!currentHost) return;
    const trusted = allowlist.includes(currentHost) || isTempTrusted(currentHost);
    await send({
      type: trusted ? "allowlist-remove" : "allowlist-add",
      domain: currentHost
    });
    await refresh();
  });

  document.getElementById("reset-stats").addEventListener("click", async () => {
    await send({ type: "stats-reset" });
    await refresh();
  });

  document.getElementById("block-site").addEventListener("click", async () => {
    if (!currentHost) return;
    const blocked = blocklist.includes(currentHost);
    await send({
      type: blocked ? "blocklist-remove" : "blocklist-add",
      domain: currentHost
    });
    await refresh();
  });

  await refresh();
}

init();
