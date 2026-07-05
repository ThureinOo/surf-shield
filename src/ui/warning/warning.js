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

const params = new URLSearchParams(location.search);
const blockedUrl = params.get("url") || "";
const mode = params.get("mode") || "nav";

const backBtn = document.getElementById("back");
const proceedBtn = document.getElementById("proceed");

if (mode === "blocked") {
  // Site is on the user's own blocklist.
  document.querySelector("h1").textContent = "\u{1F6D1} Site blocked by you";
  document.querySelector(".card p").textContent = "You blocked this site with Surf Shield:";
  document.getElementById("blocked-url").textContent = blockedUrl;
  document.getElementById("reason").textContent =
    "It stays blocked on this browser until you remove it (toolbar icon → Blocked sites).";
  proceedBtn.textContent = "Unblock this site";

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
  const dlid = Number(params.get("dlid"));
  const file = params.get("file") || "file";
  const why = (params.get("why") || "Executable file type").split("|");
  const highRisk = why.length >= 3;
  document.querySelector("h1").textContent = highRisk
    ? "\u{1F6D1} Dangerous download paused"
    : "⚠️ Risky download paused";
  document.getElementById("blocked-url").textContent = `${file}\n${blockedUrl}`;

  const reasonEl = document.getElementById("reason");
  reasonEl.textContent = highRisk
    ? "Multiple malware indicators — this is almost certainly NOT a file you want:"
    : "Only continue if you meant to download this exact file:";
  const ul = document.createElement("ul");
  ul.className = "reason";
  for (const r of why) {
    const li = document.createElement("li");
    li.textContent = r;
    ul.appendChild(li);
  }
  reasonEl.after(ul);

  backBtn.textContent = "Cancel download";
  proceedBtn.textContent = highRisk
    ? "Resume anyway (not recommended)"
    : "Resume download (I trust it)";

  backBtn.addEventListener("click", async () => {
    await api.runtime.sendMessage({ type: "download-cancel", dlid });
    window.close();
  });
  proceedBtn.addEventListener("click", async () => {
    await api.runtime.sendMessage({ type: "download-resume", dlid });
    window.close();
  });
} else {
  const reason = params.get("reason") || "Flagged as dangerous";
  document.getElementById("blocked-url").textContent = blockedUrl;
  document.getElementById("reason").textContent = "Reason: " + reason;

  // Punycode hostnames hide lookalike characters — show the real thing.
  try {
    const host = new URL(blockedUrl).hostname;
    if (host.includes("xn--")) {
      const decoded = host
        .split(".")
        .map((label) =>
          label.startsWith("xn--") ? punycodeDecode(label.slice(4)) : label
        )
        .join(".");
      if (decoded !== host) {
        const el = document.createElement("div");
        el.className = "reason";
        el.textContent = `This address actually displays as: ${decoded} — the characters may look like a familiar site but are different letters.`;
        document.getElementById("reason").after(el);
      }
    }
  } catch {}

  backBtn.addEventListener("click", () => {
    if (history.length > 2) history.go(-2);
    else location.href = "about:blank";
  });

  if (mode === "list") {
    // Domain is on the shared/threat blocklists: strictly one visit at a
    // time — no 1-hour window, no permanent trust. Next navigation warns again.
    proceedBtn.textContent = "Proceed once (I understand the risk)";
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
    // Heuristic flag (not on any list): temporary 1-hour trust, since
    // heuristics can false-positive and re-warning every load is hostile.
    proceedBtn.textContent = "Proceed anyway (trust for 1 hour)";
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
