"use strict";

import {
  BRANDS, OFFICIAL_DOMAINS, SUSPICIOUS_TLDS, INFRA_DOMAINS,
  AD_URL_PATTERNS,
  CHAIN_WINDOW_MS, CHAIN_MAX_HOPS, CHAIN_SCORE_THRESHOLD,
  SEEN_TTL_MS, STATS_EVENTS_MAX,
  safeHostOf, etldPlusOne, levenshtein, looksGenerated,
  phishingScore, chainScore
} from "./background/util.js";

const api = typeof browser !== "undefined" ? browser : chrome;

const DEFAULT_STATE = {
  allowlist: [],
  blocklist: [],
  tempAllow: {},
  statsSince: 0,
  stats: { popups: 0, overlays: 0, redirects: 0, phishing: 0, downloads: 0, clickfix: 0 },
  settings: {
    ads: true,
    cosmetics: true,
    popups: true,
    overlays: true,
    phishing: true,
    redirects: true,
    notifications: true,
    downloads: true
  }
};

async function getState() {
  const data = await api.storage.local.get(DEFAULT_STATE);
  data.settings = { ...DEFAULT_STATE.settings, ...data.settings };
  data.stats = { ...DEFAULT_STATE.stats, ...data.stats };
  return data;
}

// Badge shows what happened on *this* tab, not a lifetime total —
// that's what tells the user "the site you're on right now tried something".
const tabCounts = new Map();

function setTabBadge(tabId, text) {
  try {
    const p = api.action.setBadgeText({ tabId, text });
    if (p && p.catch) p.catch(() => {}); // tab may already be gone
  } catch {}
}

function bumpTabBadge(tabId) {
  if (tabId == null || tabId < 0) return;
  const n = (tabCounts.get(tabId) || 0) + 1;
  tabCounts.set(tabId, n);
  setTabBadge(tabId, String(n));
}

function resetTabBadge(tabId) {
  tabCounts.delete(tabId);
  setTabBadge(tabId, "");
}

api.action.setBadgeBackgroundColor({ color: "#c0392b" });

async function bumpStat(key, tabId, hostOrUrl) {
  const { stats } = await getState();
  stats[key] = (stats[key] || 0) + 1;

  // Prefer an explicit host/URL passed by the caller (that's the exact host
  // of the page at the moment of the block). Fall back to tabLastHost only
  // if nothing better is available. tabLastHost is only refreshed on
  // webNavigation.onCommitted, so for SPA nav events (YouTube, GMail, etc.)
  // it can lag behind the real URL by hundreds of ms.
  let host = null;
  if (hostOrUrl) {
    host = hostOrUrl.includes("://") ? safeHostOf(hostOrUrl) : hostOrUrl;
  }
  if (!host && tabId != null) host = tabLastHost.get(tabId) || null;

  if (host) {
    if (!Array.isArray(stats.events)) stats.events = [];
    stats.events.push({ type: key, host, ts: Date.now() });
    if (stats.events.length > STATS_EVENTS_MAX) {
      stats.events = stats.events.slice(-STATS_EVENTS_MAX);
    }
  }

  await api.storage.local.set({ stats });
  bumpTabBadge(tabId);
}

// ---- Auto-trust: sites you've settled on before ----
// If a top-frame navigation completed (page finished loading, no warning
// intervened), we implicitly trust the destination eTLD+1 for 30 days.
// Future visits skip our heuristic warnings (chain score, phishing score)
// so you never have to click "Proceed for 1 hour" on a legit site twice.
//
// Hard signals — threat-feed matches (URLhaus, PhishingArmy), user blocklist,
// AD_URL_PATTERNS — always fire regardless of "seen", because those catch
// actual compromise, not heuristic false positives.
let seenHosts = null; // { base: timestamp }, lazy-loaded
let seenDirty = false;

async function loadSeenHosts() {
  if (seenHosts !== null) return seenHosts;
  const { seenHosts: stored } = await api.storage.local.get({ seenHosts: {} });
  const now = Date.now();
  const pruned = {};
  for (const b in stored) {
    if (now - stored[b] < SEEN_TTL_MS) pruned[b] = stored[b];
  }
  seenHosts = pruned;
  return seenHosts;
}

async function isSeenBefore(base) {
  if (!base) return false;
  const seen = await loadSeenHosts();
  const ts = seen[base];
  return !!ts && Date.now() - ts < SEEN_TTL_MS;
}

function markSeen(base) {
  if (!base || !seenHosts) return;
  seenHosts[base] = Date.now();
  seenDirty = true;
}

// Persist debounced — onCompleted fires often.
setInterval(async () => {
  if (!seenDirty || !seenHosts) return;
  seenDirty = false;
  try { await api.storage.local.set({ seenHosts }); } catch {}
}, 30000);

// ---- Redirect chain breaker ----
// tabId -> { hops: [{host, time}], lastCommit }
const tabChains = new Map();

// Last committed host per tab — provenance signal for the phishing score:
// arriving on a suspicious URL *from* a flagged site is worse than typing it.
const tabLastHost = new Map();

function warningUrl(blockedUrl, reason, mode, extra) {
  let url = api.runtime.getURL(
    `src/ui/warning/warning.html?url=${encodeURIComponent(blockedUrl)}&reason=${encodeURIComponent(reason)}`
  );
  if (mode) url += `&mode=${mode}`;
  if (extra && typeof extra === "object") {
    for (const [k, v] of Object.entries(extra)) {
      if (v != null && v !== "") url += `&${k}=${encodeURIComponent(v)}`;
    }
  }
  return url;
}

function activeTempDomains(tempAllow) {
  const now = Date.now();
  return Object.keys(tempAllow).filter((d) => tempAllow[d] > now);
}

async function pruneTempAllow() {
  const { tempAllow } = await getState();
  const now = Date.now();
  const pruned = {};
  for (const [d, exp] of Object.entries(tempAllow)) if (exp > now) pruned[d] = exp;
  if (Object.keys(pruned).length !== Object.keys(tempAllow).length) {
    await api.storage.local.set({ tempAllow: pruned });
    await syncAllowlistRules();
  }
  return pruned;
}

// Public-suffix-style hosts where random users publish sites side-by-side.
// Trusting "github.io" must NEVER trust "attacker.github.io" — force exact
// match when the allowlisted entry is itself one of these bare TLDs.
const SHARED_HOSTING = new Set([
  "github.io", "gitlab.io", "bitbucket.io",
  "vercel.app", "netlify.app", "pages.dev", "web.app", "firebaseapp.com",
  "herokuapp.com", "glitch.me", "repl.co", "replit.dev", "replit.app",
  "surge.sh", "onrender.com", "workers.dev", "cloudfunctions.net",
  "azurewebsites.net", "appspot.com",
  "wixsite.com", "webflow.io", "carrd.co", "notion.site", "readthedocs.io",
  "js.org", "eu.org"
]);

function matchesTrusted(hostname, trusted) {
  if (hostname === trusted) return true;
  if (SHARED_HOSTING.has(trusted)) return false;
  return hostname.endsWith("." + trusted);
}

async function isAllowlisted(hostname) {
  const { allowlist, tempAllow } = await getState();
  const trusted = [...allowlist, ...activeTempDomains(tempAllow)];
  return trusted.some((d) => matchesTrusted(hostname, d));
}

// Domains on the shared/threat lists can only be trusted ONE visit at a
// time — never permanently. A user standing on a known-bad page is usually
// being tricked, not spotting a false positive.
const oneTimeAllow = new Set();

async function isListedDomain(hostname) {
  const { remoteDomains, remotePhishing, threatPhishing, threatMalware } =
    await api.storage.local.get({
      remoteDomains: [],
      remotePhishing: [],
      threatPhishing: [],
      threatMalware: []
    });
  const all = [...remoteDomains, ...remotePhishing, ...threatPhishing, ...threatMalware];
  return all.some((d) => hostname === d || hostname.endsWith("." + d));
}

api.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (details.url.startsWith(api.runtime.getURL(""))) return;
  resetTabBadge(details.tabId);
  let host;
  try {
    host = new URL(details.url).hostname;
  } catch {
    return;
  }
  if (!host) return;

  // Personal blocklist: show our own page instead of the browser's bare
  // "blocked by an extension" error, so the user knows *they* blocked it
  // and can unblock in one click.
  const { blocklist, settings } = await getState();
  if (blocklist.some((d) => host === d || host.endsWith("." + d))) {
    api.tabs.update(details.tabId, {
      url: warningUrl(details.url, "You added this site to your blocklist", "blocked")
    });
    return;
  }

  if (oneTimeAllow.delete(host)) return; // consumed: next visit warns again
  if (await isAllowlisted(host)) return;

  // Backstop for the DNR layer: popunder ad URLs have unmistakable
  // fingerprints. Catch them here too in case a ruleset failed to load.
  if (settings.redirects && AD_URL_PATTERNS.some((re) => re.test(details.url))) {
    noteAdActivity();
    await bumpStat("redirects", details.tabId, host);
    api.tabs.update(details.tabId, { url: warningUrl(details.url, "Popunder / ad redirect URL") });
    return;
  }

  if (!settings.phishing) return;

  const { remotePhishing, threatPhishing, threatMalware } = await api.storage.local.get({
    remotePhishing: [],
    threatPhishing: [],
    threatMalware: []
  });
  if (threatMalware.some((d) => host === d || host.endsWith("." + d))) {
    noteAdActivity();
    await bumpStat("phishing", details.tabId, host);
    api.tabs.update(details.tabId, {
      url: warningUrl(details.url, "Known malware domain (public threat-intelligence feeds)", "list")
    });
    return;
  }
  if (remotePhishing.some((d) => host === d || host.endsWith("." + d))) {
    noteAdActivity();
    await bumpStat("phishing", details.tabId, host);
    api.tabs.update(details.tabId, {
      url: warningUrl(details.url, "Domain is on the curated phishing blocklist", "list")
    });
    return;
  }
  if (threatPhishing.some((d) => host === d || host.endsWith("." + d))) {
    noteAdActivity();
    await bumpStat("phishing", details.tabId, host);
    api.tabs.update(details.tabId, {
      url: warningUrl(details.url, "Known phishing domain (public threat-intelligence feeds)", "list")
    });
    return;
  }

  const { score, reasons } = phishingScore(details.url);
  let total = score;
  const prevHost = tabLastHost.get(details.tabId);
  if (score > 0 && prevHost && etldPlusOne(prevHost) !== etldPlusOne(host)) {
    if (await isListedDomain(prevHost)) {
      total += 2;
      reasons.push("Reached from a domain on a threat blocklist");
    } else if (Date.now() - lastAdActivity < AD_PROVENANCE_WINDOW_MS) {
      total += 1;
      reasons.push("Reached right after a blocked ad/redirect");
    }
  }
  if (total >= 3 && !(await isSeenBefore(etldPlusOne(host)))) {
    await bumpStat("phishing", details.tabId, host);
    api.tabs.update(details.tabId, { url: warningUrl(details.url, reasons.join(" · ")) });
  }
});

api.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  let host;
  try {
    host = new URL(details.url).hostname;
  } catch {
    return;
  }
  if (!host || details.url.startsWith(api.runtime.getURL(""))) return;

  tabLastHost.set(details.tabId, host);

  const now = Date.now();
  const isRedirect =
    details.transitionQualifiers.includes("client_redirect") ||
    details.transitionQualifiers.includes("server_redirect");

  let chain = tabChains.get(details.tabId);
  const prevFromPopup = chain?.fromPopup ?? false;
  if (!chain || now - chain.lastCommit > CHAIN_WINDOW_MS || !isRedirect) {
    chain = { hops: [], lastCommit: now, fromPopup: prevFromPopup };
  }
  chain.lastCommit = now;

  const lastHop = chain.hops[chain.hops.length - 1];
  if (isRedirect && (!lastHop || etldPlusOne(lastHop.host) !== etldPlusOne(host))) {
    chain.hops.push({ host, url: details.url, time: now });
  }
  tabChains.set(details.tabId, chain);

  const { settings } = await getState();
  if (settings.redirects && chain.hops.length >= 2 && !(await isAllowlisted(host)) && !(await isSeenBefore(etldPlusOne(host)))) {
    const { score, reasons } = chainScore(chain, details.url);
    if (score >= CHAIN_SCORE_THRESHOLD) {
      tabChains.delete(details.tabId);
      noteAdActivity();
      await bumpStat("redirects", details.tabId, host);
      const reasonText = "Suspicious redirect chain — " + reasons.slice(0, 3).join("; ");
      // Pass the sequence of hop hostnames so the warning page can render
      // the actual redirect chain (bit.ly → landing.click → …), not just
      // describe it in words.
      const hops = (chain.hops || []).map((h) => h.host).join(",");
      api.tabs.update(details.tabId, { url: warningUrl(details.url, reasonText, null, { hops }) });
    }
  }
});

// Auto-trust: once a top-frame nav has *finished loading* without being
// redirected to our warning page, remember the destination so we don't
// warn on it again. If we warned during commit, the tab navigated to a
// warning URL (extension origin) — onCompleted then fires for that URL
// and the early-return skips the mark. Only genuinely-successful visits
// end up in the seen set. That's what makes the auto-trust race-free
// across the two onCommitted handlers.
api.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  let host;
  try {
    host = new URL(details.url).hostname;
  } catch {
    return;
  }
  if (!host || details.url.startsWith(api.runtime.getURL(""))) return;
  await loadSeenHosts();
  markSeen(etldPlusOne(host));
});

// New tabs (popunders!) inherit provenance from the tab that opened them.
api.webNavigation.onCreatedNavigationTarget.addListener((details) => {
  const openerHost = tabLastHost.get(details.sourceTabId);
  if (openerHost) tabLastHost.set(details.tabId, openerHost);
  // Mark the new tab's chain as popup-originated so chainScore adds the
  // forced-download / popunder penalty on any subsequent redirect.
  const chain = tabChains.get(details.tabId) || { hops: [], lastCommit: Date.now() };
  chain.fromPopup = true;
  tabChains.set(details.tabId, chain);
});

api.tabs.onRemoved.addListener((tabId) => {
  tabChains.delete(tabId);
  tabCounts.delete(tabId);
  tabLastHost.delete(tabId);
});

// ---- Download protection ----
const RISKY_EXT = /\.(exe|msi|msix|apk|scr|bat|cmd|ps1|vbs|vbe|js|jse|jar|hta|dmg|pkg|deb|rpm|iso|img|lnk|reg)$/i;

// invoice.pdf.exe, photo.jpg.scr — the real extension hides behind a fake one.
const DOUBLE_EXT = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp[34]|avi|mkv|zip|rar)\.(exe|msi|scr|bat|cmd|ps1|vbs|js|hta|lnk)$/i;

// Names pay-per-install bundleware ships under (the user's real-world hit
// was "operasetup.exe" served from a malvertising redirect).
const FAKE_INSTALLER = /(opera.?setup|chrome.?(setup|update|install)|firefox.?(setup|install)|edge.?setup|flash.?player|java.?update|driver.?(update|pack|booster)|codec.?pack|player.?setup|adobe.?(reader|flash).?(setup|update)|browser.?update)/i;

// Sliding window of "an ad/redirect/phishing block just happened" — a risky
// download started inside it almost certainly came from that same chain.
let lastAdActivity = 0;
const AD_PROVENANCE_WINDOW_MS = 30000;
function noteAdActivity() {
  lastAdActivity = Date.now();
}

function fileNameOf(item) {
  if (item.filename) return item.filename.split(/[\\/]/).pop();
  try {
    return decodeURIComponent(new URL(item.finalUrl || item.url).pathname.split("/").pop());
  } catch {
    return "";
  }
}

async function downloadRiskReasons(item, name, sourceHost) {
  const reasons = ["Executable file type"];
  if (DOUBLE_EXT.test(name)) {
    reasons.push("Disguised as a document/media file — hidden second extension");
  }
  if (FAKE_INSTALLER.test(name)) {
    reasons.push("Filename mimics a well-known installer (common bundleware/malware trick)");
  }
  const src = item.finalUrl || item.url || "";
  const ref = item.referrer || "";
  if (AD_URL_PATTERNS.some((re) => re.test(src) || re.test(ref))) {
    reasons.push("Download URL carries ad-network campaign parameters");
  }
  let refHost = "";
  try {
    refHost = new URL(ref).hostname;
  } catch {}
  const { remotePhishing, threatPhishing } = await api.storage.local.get({
    remotePhishing: [],
    threatPhishing: []
  });
  const badLists = [...remotePhishing, ...threatPhishing];
  if ([sourceHost, refHost].filter(Boolean).some((h) => badLists.some((d) => h === d || h.endsWith("." + d)))) {
    reasons.push("Source domain is on a threat-intelligence list");
  }
  if (Date.now() - lastAdActivity < AD_PROVENANCE_WINDOW_MS) {
    reasons.push("Started right after an ad/redirect block — typical forced-download chain");
  }
  return reasons;
}

async function inspectDownload(item) {
  const { settings } = await getState();
  if (!settings.downloads) return;
  const name = fileNameOf(item);
  if (!name || !RISKY_EXT.test(name)) return;
  let sourceHost = "";
  try {
    sourceHost = new URL(item.finalUrl || item.url).hostname;
  } catch {}
  if (sourceHost && (await isAllowlisted(sourceHost))) return;

  const reasons = await downloadRiskReasons(item, name, sourceHost);

  try {
    await api.downloads.pause(item.id);
  } catch {
    return; // already finished or gone — nothing to protect
  }
  await bumpStat("downloads", null, sourceHost);
  api.tabs.create({
    url: api.runtime.getURL(
      `src/ui/warning/warning.html?mode=download&dlid=${item.id}` +
        `&file=${encodeURIComponent(name)}&url=${encodeURIComponent(item.finalUrl || item.url)}` +
        `&why=${encodeURIComponent(reasons.join("|"))}`
    )
  });
}

const inspectedDownloads = new Set();

api.downloads.onCreated.addListener((item) => {
  if (fileNameOf(item)) {
    inspectedDownloads.add(item.id);
    inspectDownload(item);
  }
});

// Filename is often determined after onCreated (e.g. blob downloads).
api.downloads.onChanged.addListener(async (delta) => {
  if (!delta.filename || inspectedDownloads.has(delta.id)) return;
  inspectedDownloads.add(delta.id);
  const [item] = await api.downloads.search({ id: delta.id });
  if (item) inspectDownload(item);
});

// ---- Dynamic rule ID ranges ----
// 10000-14999 allowlist, 15000-19999 personal blocklist,
// 20000-29999 remote blocklist, 30000+ threat feeds.
const ALLOW_RULE_OFFSET = 10000;
const PERSONAL_RULE_OFFSET = 15000;
const REMOTE_RULE_OFFSET = 20000;
const THREAT_RULE_OFFSET = 30000;

// Shared validation for anything fetched over the network: even if the repo
// (or the network path) is compromised, refuse rules that would break major
// sites, and cap sizes so a bad update can't exhaust rule/storage quotas.
const PROTECTED_DOMAINS = ["google.com", "youtube.com", "facebook.com", "github.com", "microsoft.com", "apple.com", "amazon.com", "wikipedia.org", "cloudflare.com"];

function remoteDomainOk(d) {
  return (
    typeof d === "string" &&
    d.length <= 253 &&
    /^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/.test(d) &&
    !PROTECTED_DOMAINS.some((p) => d === p || d.endsWith("." + p))
  );
}

function sanitizeDomains(arr, cap) {
  return Array.isArray(arr) ? arr.filter(remoteDomainOk).slice(0, cap) : [];
}

function domainBlockRules(domains, startId, resourceTypes) {
  const rules = [];
  for (let i = 0; i < domains.length; i += 1000) {
    rules.push({
      id: startId + rules.length,
      priority: 1,
      action: { type: "block" },
      condition: { requestDomains: domains.slice(i, i + 1000), resourceTypes }
    });
  }
  return rules;
}

async function syncAllowlistRules() {
  const { allowlist, tempAllow } = await getState();
  let domains = [...new Set([...allowlist, ...activeTempDomains(tempAllow)])];
  // A domain trusted in the past may have landed on the shared/threat lists
  // since — those must not get DNR allow rules that override the block.
  const stillOk = await Promise.all(domains.map((d) => isListedDomain(d).then((l) => !l)));
  domains = domains.filter((_, i) => stillOk[i]);
  const existing = await api.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((r) => r.id >= ALLOW_RULE_OFFSET && r.id < PERSONAL_RULE_OFFSET)
    .map((r) => r.id);
  const addRules = domains.slice(0, 500).map((domain, i) => ({
    id: ALLOW_RULE_OFFSET + i,
    priority: 100,
    action: { type: "allowAllRequests" },
    condition: { requestDomains: [domain], resourceTypes: ["main_frame", "sub_frame"] }
  }));
  await api.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
}

// Personal blocklist: user-blocked sites, this browser only. Priority 200
// beats allowlist rules (100) in case a domain ever sits in both.
async function syncPersonalRules() {
  const { blocklist } = await getState();
  const existing = await api.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((r) => r.id >= PERSONAL_RULE_OFFSET && r.id < REMOTE_RULE_OFFSET)
    .map((r) => r.id);
  const addRules = blocklist.length
    ? [
        {
          id: PERSONAL_RULE_OFFSET,
          priority: 200,
          action: { type: "block" },
          condition: {
            requestDomains: blocklist.slice(0, 1000),
            // main_frame is handled in onBeforeNavigate so the user gets our
            // "you blocked this" page instead of a bare browser error.
            resourceTypes: ["sub_frame", "script", "xmlhttprequest", "ping", "image", "media"]
          }
        }
      ]
    : [];
  await api.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
}

// ---- Remote blocklist updates ----
// One file on GitHub, edited by hand or by the report-approval workflow;
// every install refreshes daily without a store release.
const REMOTE_LIST_URL =
  "https://raw.githubusercontent.com/ThureinOo/surf-shield/main/remote/blocklist.json";

async function updateRemoteRules() {
  let list;
  try {
    const res = await fetch(REMOTE_LIST_URL, { cache: "no-cache" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    list = await res.json();
  } catch (e) {
    console.warn("[surf-shield] remote list fetch failed:", e.message);
    return;
  }
  if (!list || !Array.isArray(list.domains)) return;

  // Fetch parsed successfully — record freshness even when the content
  // hasn't changed (unchanged content is still a successful check-in).
  await api.storage.local.set({ lastRemoteFeedTs: Date.now() });

  const { remoteVersion } = await api.storage.local.get({ remoteVersion: 0 });
  if (list.version === remoteVersion) return;

  const domains = sanitizeDomains(list.domains, 5000);
  const phishing = sanitizeDomains(list.phishingDomains, 5000);
  const dropped = list.domains.length - domains.length;
  if (dropped > 0) console.warn(`[surf-shield] remote list: dropped ${dropped} invalid/protected domains`);

  const addRules = domainBlockRules(domains, REMOTE_RULE_OFFSET, [
    "main_frame", "sub_frame", "script", "xmlhttprequest", "ping", "image"
  ]);
  // Chrome caps dynamic regex rules at 1000; stay well below.
  const patterns = (Array.isArray(list.patterns) ? list.patterns : [])
    .filter((p) => typeof p === "string" && p.length <= 200)
    .slice(0, 500);
  let id = REMOTE_RULE_OFFSET + addRules.length;
  for (const pattern of patterns) {
    addRules.push({
      id: id++,
      priority: 1,
      action: { type: "block" },
      condition: { regexFilter: pattern, resourceTypes: ["main_frame", "sub_frame", "script"] }
    });
  }

  const existing = await api.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((r) => r.id >= REMOTE_RULE_OFFSET && r.id < THREAT_RULE_OFFSET)
    .map((r) => r.id);
  try {
    await api.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  } catch (e) {
    console.error("[surf-shield] remote rules rejected:", e.message);
    return;
  }

  await api.storage.local.set({
    remoteVersion: list.version,
    remoteDomains: domains,
    remotePhishing: phishing
  });
  await syncAllowlistRules(); // drop allow rules for domains now on the list
  console.log(`[surf-shield] remote list v${list.version}: ${domains.length} domains, ${patterns.length} patterns`);
}

// ---- Threat-intel feeds (URLhaus, Hagezi TIF, Phishing Army) ----
// Aggregated daily by a GitHub Action into one file. Malware domains get a
// silent network block; phishing domains get the warning page on visit.
const THREAT_LIST_URL =
  "https://raw.githubusercontent.com/ThureinOo/surf-shield/main/remote/threat-domains.json";

async function updateThreatRules() {
  let list;
  try {
    const res = await fetch(THREAT_LIST_URL, { cache: "no-cache" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    list = await res.json();
  } catch (e) {
    console.warn("[surf-shield] threat feed fetch failed:", e.message);
    return;
  }
  if (!list || !Array.isArray(list.malware)) return;

  // Successful fetch — record freshness before the content-changed check.
  await api.storage.local.set({ lastThreatFeedTs: Date.now() });

  const { threatVersion } = await api.storage.local.get({ threatVersion: "" });
  if (list.updated === threatVersion) return;

  const malware = sanitizeDomains(list.malware, 15000);
  const phishing = sanitizeDomains(list.phishing, 8000);

  // No main_frame here: direct visits go through onBeforeNavigate instead,
  // so the user gets our warning page (with one-time proceed) rather than a
  // bare connection error. Embedded resources from these domains stay blocked.
  const addRules = domainBlockRules(malware, THREAT_RULE_OFFSET, [
    "sub_frame", "script", "xmlhttprequest", "ping", "image", "media"
  ]);

  const existing = await api.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.filter((r) => r.id >= THREAT_RULE_OFFSET).map((r) => r.id);
  try {
    await api.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  } catch (e) {
    console.error("[surf-shield] threat rules rejected:", e.message);
    return;
  }

  await api.storage.local.set({
    threatVersion: list.updated,
    threatMalware: malware,
    threatPhishing: phishing
  });
  await syncAllowlistRules(); // drop allow rules for domains now on the list
  console.log(`[surf-shield] threat feeds ${list.updated}: ${malware.length} malware, ${phishing.length} phishing`);
}

api.alarms.create("remote-update", { periodInMinutes: 1440, delayInMinutes: 1 });
api.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "remote-update") {
    updateRemoteRules();
    updateThreatRules();
  }
  if (alarm.name === "temp-allow-sweep") pruneTempAllow();
});

let cosmeticsCache = null;
async function getCosmetics() {
  if (cosmeticsCache) return cosmeticsCache;
  try {
    const res = await fetch(api.runtime.getURL("rules/cosmetic.json"));
    cosmeticsCache = await res.json();
  } catch {
    cosmeticsCache = [];
  }
  return cosmeticsCache;
}

// ---- Messages from content scripts and popup ----
api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg.type) {
      case "blocked-popup":
        await bumpStat("popups", sender.tab && sender.tab.id, sender.tab && sender.tab.url);
        sendResponse({ ok: true });
        break;
      case "blocked-overlay":
        await bumpStat("overlays", sender.tab && sender.tab.id, sender.tab && sender.tab.url);
        sendResponse({ ok: true });
        break;
      case "blocked-clickfix":
        await bumpStat("clickfix", sender.tab && sender.tab.id, sender.tab && sender.tab.url);
        sendResponse({ ok: true });
        break;
      case "get-state": {
        const state = await getState();
        state.tempAllow = await pruneTempAllow();
        sendResponse(state);
        break;
      }
      case "stats-reset": {
        for (const tabId of tabCounts.keys()) resetTabBadge(tabId);
        await api.storage.local.set({
          stats: { ...DEFAULT_STATE.stats },
          statsSince: Date.now()
        });
        sendResponse({ ok: true });
        break;
      }
      case "is-allowlisted": {
        const allowed = sender.url
          ? await isAllowlisted(new URL(sender.url).hostname)
          : false;
        sendResponse({ allowed });
        break;
      }
      case "get-cosmetics": {
        sendResponse({ selectors: await getCosmetics() });
        break;
      }
      case "get-config": {
        const { settings } = await getState();
        const allowed = sender.url
          ? await isAllowlisted(new URL(sender.url).hostname)
          : false;
        sendResponse({ settings, allowed });
        break;
      }
      case "set-settings": {
        const { settings } = await getState();
        const next = { ...settings, ...msg.settings };
        await api.storage.local.set({ settings: next });
        await api.declarativeNetRequest.updateEnabledRulesets(
          next.ads
            ? { enableRulesetIds: ["ads", "generated"] }
            : { disableRulesetIds: ["ads", "generated"] }
        );
        sendResponse({ ok: true });
        break;
      }
      case "allow-once": {
        // From the warning page only: bypass the next navigation to this
        // host, then warn again. Listed domains can never get more than this.
        oneTimeAllow.add(msg.domain);
        sendResponse({ ok: true });
        break;
      }
      case "list-status": {
        sendResponse({ listed: await isListedDomain(msg.domain) });
        break;
      }
      case "allowlist-add": {
        if (await isListedDomain(msg.domain)) {
          sendResponse({ ok: false, error: "listed" });
          break;
        }
        const { allowlist, blocklist, tempAllow } = await getState();
        if (!allowlist.includes(msg.domain)) allowlist.push(msg.domain);
        delete tempAllow[msg.domain];
        await api.storage.local.set({
          allowlist,
          tempAllow,
          blocklist: blocklist.filter((d) => d !== msg.domain)
        });
        await syncAllowlistRules();
        await syncPersonalRules();
        sendResponse({ ok: true });
        break;
      }
      case "allowlist-add-temp": {
        if (await isListedDomain(msg.domain)) {
          sendResponse({ ok: false, error: "listed" });
          break;
        }
        const minutes = 60;
        const { blocklist, tempAllow } = await getState();
        tempAllow[msg.domain] = Date.now() + minutes * 60000;
        await api.storage.local.set({
          tempAllow,
          blocklist: blocklist.filter((d) => d !== msg.domain)
        });
        await syncAllowlistRules();
        await syncPersonalRules();
        api.alarms.create("temp-allow-sweep", { delayInMinutes: minutes + 1 });
        sendResponse({ ok: true });
        break;
      }
      case "blocklist-add": {
        const { allowlist, blocklist } = await getState();
        if (!blocklist.includes(msg.domain)) blocklist.push(msg.domain);
        await api.storage.local.set({
          blocklist,
          allowlist: allowlist.filter((d) => d !== msg.domain)
        });
        await syncPersonalRules();
        await syncAllowlistRules();
        sendResponse({ ok: true });
        break;
      }
      case "blocklist-remove": {
        const { blocklist } = await getState();
        await api.storage.local.set({ blocklist: blocklist.filter((d) => d !== msg.domain) });
        await syncPersonalRules();
        sendResponse({ ok: true });
        break;
      }
      case "download-resume": {
        try {
          await api.downloads.resume(msg.dlid);
          sendResponse({ ok: true });
        } catch (e) {
          sendResponse({ ok: false, error: String(e) });
        }
        break;
      }
      case "download-cancel": {
        try {
          await api.downloads.cancel(msg.dlid);
        } catch {}
        sendResponse({ ok: true });
        break;
      }
      case "allowlist-remove": {
        const { allowlist, tempAllow } = await getState();
        delete tempAllow[msg.domain];
        await api.storage.local.set({
          allowlist: allowlist.filter((d) => d !== msg.domain),
          tempAllow
        });
        await syncAllowlistRules();
        sendResponse({ ok: true });
        break;
      }
      default:
        sendResponse({ ok: false });
    }
  })();
  return true;
});

api.runtime.onInstalled.addListener(async (details) => {
  const state = await getState();
  if (!state.statsSince) state.statsSince = Date.now();
  await api.storage.local.set(state);
  await syncAllowlistRules();
  await syncPersonalRules();
  // Feeds only refresh via a daily alarm — without a cold-start pull, a
  // fresh install has empty threat lists until tomorrow.
  updateRemoteRules();
  updateThreatRules();
  if (details.reason === "install") {
    api.tabs.create({ url: api.runtime.getURL("src/ui/onboarding/onboarding.html") });
  }
});

api.runtime.onStartup.addListener(() => {
  updateRemoteRules();
  updateThreatRules();
});

api.declarativeNetRequest
  .getEnabledRulesets()
  .then((ids) => console.log("[surf-shield] enabled rulesets:", ids))
  .catch((e) => console.error("[surf-shield] ruleset check failed:", e));

// Inject the YT ad-prevention bundle via chrome.scripting on webNavigation
// rather than via a manifest content_script. Fires marginally earlier —
// before YT's inline `<script>` that assigns `ytInitialPlayerResponse` —
// so the getters our bundle installs are already in place. Matches the
// architecture used by Adblock for YouTube and uBlock Origin's YT rules.
if (api.scripting && api.scripting.executeScript) {
  api.webNavigation.onCommitted.addListener(
    async ({ tabId, frameId }) => {
      if (frameId !== 0) return;
      try {
        await api.scripting.executeScript({
          target: { tabId, frameIds: [0] },
          world: "MAIN",
          injectImmediately: true,
          files: ["src/content/youtube-bundle.js"],
        });
      } catch {
        // Tab closed, chrome:// URL, or the tab is unloaded — all benign.
      }
    },
    {
      url: [
        { hostSuffix: "youtube.com" },
        { hostSuffix: "youtube-nocookie.com" },
      ],
    }
  );
}
