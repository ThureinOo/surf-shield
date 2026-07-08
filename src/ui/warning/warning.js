"use strict";
const api = typeof browser !== "undefined" ? browser : chrome;

// Never allow this page inside a frame: an embedding page could clickjack
// "Proceed anyway" into allowlisting an attacker-chosen domain.
if (window.top !== window) {
  document.documentElement.remove();
  throw new Error("framed");
}

// RFC 3492 punycode decoder (decode-only).
function punycodeDecode(input) {
  const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;
  const output = [];
  let n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
  const basic = input.lastIndexOf("-");
  for (let j = 0; j < Math.max(basic, 0); j++) output.push(input.charCodeAt(j));
  let index = basic > 0 ? basic + 1 : 0;

  const digit = (cp) => (cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 : cp - 97 < 26 ? cp - 97 : BASE);
  const adapt = (delta, numPoints, firstTime) => {
    delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((BASE - TMIN) * TMAX) >> 1) {
      delta = Math.floor(delta / (BASE - TMIN));
      k += BASE;
    }
    return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
  };

  while (index < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (index >= input.length) throw new Error("invalid");
      const d = digit(input.charCodeAt(index++));
      if (d >= BASE) throw new Error("invalid");
      i += d * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (d < t) break;
      w *= BASE - t;
    }
    bias = adapt(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

// Split a reason string into individual bullets. The scorers concatenate
// their per-signal reasons with " · " (phishing) or "; " (chain) or bury
// them after "— " (chain headline). Handle all three.
function splitReasons(reason) {
  if (!reason) return [];
  let s = reason;
  // Chain reasons look like: "Suspicious redirect chain — 3-hop; sub-second; 2 sus TLDs"
  // Strip the headline (everything before " — ") so we get just the signals.
  const dashIdx = s.indexOf(" — ");
  if (dashIdx !== -1) s = s.slice(dashIdx + 3);
  // Try semicolon then middle-dot; whichever produces more parts wins.
  const bySemi = s.split(/\s*;\s*/).filter(Boolean);
  const byDot  = s.split(/\s+·\s+/).filter(Boolean);
  return bySemi.length >= byDot.length ? bySemi : byDot;
}

const params = new URLSearchParams(location.search);
const blockedUrl = params.get("url") || "";
const mode = params.get("mode") || "nav";
const hopsParam = params.get("hops") || "";

const card = document.getElementById("card");
const iconEl = document.getElementById("icon");
const titleEl = document.getElementById("title");
const subtitleEl = document.getElementById("subtitle");
const backBtn = document.getElementById("back");
const proceedBtn = document.getElementById("proceed");
const reasonsEl = document.getElementById("reasons");
const reasonsSection = document.getElementById("reasons-section");
const chainSection = document.getElementById("chain-section");
const chainViz = document.getElementById("chain-viz");
const blockedUrlEl = document.getElementById("blocked-url");
const punycodeNote = document.getElementById("punycode-note");
const footerEl = document.getElementById("footer");

function renderReasonList(items) {
  reasonsEl.innerHTML = "";
  if (items.length === 0) {
    reasonsSection.hidden = true;
    return;
  }
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    reasonsEl.appendChild(li);
  }
}

// Visual redirect chain: bit.ly → oauth.example.com → landing.click
function renderChain(hostsStr) {
  const hosts = hostsStr.split(",").map((h) => h.trim()).filter(Boolean);
  if (hosts.length < 2) return;
  chainSection.hidden = false;
  chainViz.innerHTML = "";
  hosts.forEach((host, i) => {
    const span = document.createElement("span");
    span.className = "hop" + (i === hosts.length - 1 ? " last" : "");
    span.textContent = host;
    chainViz.appendChild(span);
    if (i < hosts.length - 1) {
      const arrow = document.createElement("span");
      arrow.className = "arrow";
      arrow.textContent = "→";
      chainViz.appendChild(arrow);
    }
  });
}

// Punycode note: show the *rendered* form of an IDN hostname so the user
// can see the actual glyphs (attackers use Cyrillic а for Latin a etc.).
function maybeShowPunycodeNote() {
  try {
    const host = new URL(blockedUrl).hostname;
    if (!host.includes("xn--")) return;
    const decoded = host
      .split(".")
      .map((label) => (label.startsWith("xn--") ? punycodeDecode(label.slice(4)) : label))
      .join(".");
    if (decoded !== host) {
      punycodeNote.hidden = false;
      punycodeNote.textContent =
        `This address actually displays as ${decoded} — the characters may look like a familiar site but are different letters.`;
    }
  } catch {}
}

// ---- Mode-specific rendering ----

if (mode === "blocked") {
  // Site is on the user's own blocklist.
  card.classList.add("blocked");
  iconEl.textContent = "\u{1F6D1}";
  titleEl.textContent = "Site blocked by you";
  subtitleEl.textContent =
    "You added this site to your personal blocklist. It stays blocked on this browser until you remove it from the extension popup.";
  blockedUrlEl.textContent = blockedUrl;
  renderReasonList(["You added this domain to your Blocked sites list"]);
  proceedBtn.textContent = "Unblock this site";
  backBtn.textContent = "Go back";

  backBtn.addEventListener("click", () => {
    if (history.length > 2) history.go(-2);
    else location.href = "about:blank";
  });
  proceedBtn.addEventListener("click", async () => {
    try {
      const domain = new URL(blockedUrl).hostname;
      await api.runtime.sendMessage({ type: "blocklist-remove", domain });
      location.href = blockedUrl;
    } catch {
      location.href = "about:blank";
    }
  });
} else if (mode === "download") {
  // Download risk analysis result — file paused mid-download.
  card.classList.add("download");
  const dlid = Number(params.get("dlid"));
  const file = params.get("file") || "file";
  const why = (params.get("why") || "Executable file type").split("|");
  const highRisk = why.length >= 3;

  iconEl.textContent = highRisk ? "\u{1F6D1}" : "\u{26A0}\u{FE0F}";
  titleEl.textContent = highRisk ? "Dangerous download paused" : "Risky download paused";
  subtitleEl.textContent = highRisk
    ? "Multiple malware indicators — this is almost certainly NOT a file you want."
    : "Only continue if you meant to download this exact file.";
  blockedUrlEl.textContent = file + "\n\n" + blockedUrl;
  renderReasonList(why);
  backBtn.textContent = "Cancel download";
  proceedBtn.textContent = highRisk ? "Resume anyway (not recommended)" : "Resume download";

  backBtn.addEventListener("click", async () => {
    await api.runtime.sendMessage({ type: "download-cancel", dlid });
    window.close();
  });
  proceedBtn.addEventListener("click", async () => {
    await api.runtime.sendMessage({ type: "download-resume", dlid });
    window.close();
  });
} else {
  // Default nav / list warnings (heuristic phishing, chain, ad URL, threat feed).
  const reasonStr = params.get("reason") || "Flagged as dangerous";
  blockedUrlEl.textContent = blockedUrl;
  renderReasonList(splitReasons(reasonStr));
  if (hopsParam) renderChain(hopsParam);
  maybeShowPunycodeNote();

  // Choose title/subtitle based on which signal fired.
  if (mode === "list") {
    iconEl.textContent = "\u{1F6D1}";
    titleEl.textContent = "Dangerous site blocked";
    subtitleEl.textContent =
      "This domain appears on a public threat-intelligence feed (URLhaus / PhishingArmy / curated list). Real risk of malware or credential theft.";
  } else if (reasonStr.startsWith("Suspicious redirect chain")) {
    iconEl.textContent = "\u{27A1}\u{FE0F}";
    titleEl.textContent = "Suspicious redirect blocked";
    subtitleEl.textContent =
      "The chain of pages you were being sent through matches malvertising / forced-download patterns. This is not a normal navigation.";
  } else if (reasonStr === "Popunder / ad redirect URL") {
    iconEl.textContent = "\u{1F6D1}";
    titleEl.textContent = "Popunder ad redirect blocked";
    subtitleEl.textContent =
      "The URL structure matches a popunder / click-monetization ad network. Legitimate pages don't use this URL format.";
  } else {
    iconEl.textContent = "\u{26A0}\u{FE0F}";
    titleEl.textContent = "Suspicious page blocked";
    subtitleEl.textContent =
      "Heuristic analysis of this URL raised multiple red flags. It could be phishing, brand impersonation, or scam.";
  }

  backBtn.textContent = "Go back to safety";
  backBtn.addEventListener("click", () => {
    if (history.length > 2) history.go(-2);
    else location.href = "about:blank";
  });

  if (mode === "list") {
    // Threat-list matches only get one-shot bypass — no 1-hour trust.
    proceedBtn.textContent = "Proceed once (I understand the risk)";
    footerEl.textContent = "One-time bypass only. Threat-list domains cannot be permanently trusted.";
    proceedBtn.addEventListener("click", async () => {
      try {
        const domain = new URL(blockedUrl).hostname;
        await api.runtime.sendMessage({ type: "allow-once", domain });
        location.href = blockedUrl;
      } catch {
        location.href = "about:blank";
      }
    });
  } else {
    // Heuristic hits: temp 1-hour trust. But most legit sites don't need
    // this because the auto-trust set catches them on first successful load.
    proceedBtn.textContent = "Proceed anyway (trust for 1 hour)";
    footerEl.textContent =
      "If this is a site you visit normally, once its full page loads without warning it will be added to your auto-trust set — you won't be interrupted here again.";
    proceedBtn.addEventListener("click", async () => {
      try {
        const domain = new URL(blockedUrl).hostname;
        await api.runtime.sendMessage({ type: "allowlist-add-temp", domain });
        location.href = blockedUrl;
      } catch {
        location.href = "about:blank";
      }
    });
  }
}
