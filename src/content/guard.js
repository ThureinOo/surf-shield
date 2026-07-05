// Isolated-world guard: overlay killer, noopener enforcement, bridge to background.
(() => {
  "use strict";
  const api = typeof browser !== "undefined" ? browser : chrome;
  let enabled = true;
  let overlaysOn = true;

  // Handshake with the MAIN-world hooks: they wrote a one-time nonce to the
  // DOM at document_start; grab and erase it before any page script can see
  // it. Events in either direction must carry it, so pages can't forge config
  // ("disable popups") or spoof blocked-popup stats.
  let nonce = null;
  try {
    const root = document.documentElement;
    nonce = root.getAttribute("data-ssn");
    root.removeAttribute("data-ssn");
  } catch {}

  // After an extension reload/update this content script is orphaned and
  // runtime.sendMessage throws "Extension context invalidated" — swallow it,
  // the fresh copy of the script is already running in new navigations.
  function send(msg, cb) {
    try {
      api.runtime.sendMessage(msg, (res) => {
        void api.runtime.lastError;
        if (cb) cb(res);
      });
    } catch {}
  }

  send({ type: "get-config" }, (res) => {
    if (!res) return;
    if (res.allowed) enabled = false;
    overlaysOn = enabled && res.settings.overlays !== false;
    // Forward to MAIN-world hooks (they have no runtime access).
    dispatchEvent(
      new CustomEvent("__surfshield_config", {
        detail: {
          nonce,
          popups: enabled && res.settings.popups !== false,
          notifications: enabled && res.settings.notifications !== false
        }
      })
    );
  });

  // Bridge: MAIN-world hooks report blocked popups via CustomEvent.
  addEventListener("__surfshield_blocked", (e) => {
    if (!enabled) return;
    if (!nonce || !e.detail || e.detail.nonce !== nonce) return;
    if (e.detail.kind === "clickfix") {
      send({ type: "blocked-clickfix" });
      showClickFixWarning(e.detail.sample || "");
      return;
    }
    send({ type: "blocked-popup" });
  });

  // ---- ClickFix warning banner ----
  // The page just tried to put a shell command on the clipboard ("press
  // Win+R and paste to verify you are human"). The copy was blocked, but the
  // user is mid-scam and about to follow instructions — interrupt loudly.
  let clickFixShown = false;
  function showClickFixWarning(sample) {
    if (clickFixShown) return;
    clickFixShown = true;
    const host = document.createElement("div");
    host.style.cssText =
      "position:fixed;inset:0;z-index:2147483647;background:rgba(12,12,24,.96);" +
      "display:flex;align-items:center;justify-content:center;font-family:-apple-system,'Segoe UI',Roboto,sans-serif";
    const shadow = host.attachShadow({ mode: "closed" });
    const box = document.createElement("div");
    box.style.cssText =
      "max-width:520px;background:#16213e;border:2px solid #e74c3c;border-radius:12px;" +
      "padding:28px;color:#eee;font-family:-apple-system,'Segoe UI',Roboto,sans-serif";
    const h = document.createElement("div");
    h.textContent = "\u{1F6D1} Scam blocked — do NOT follow this page's instructions";
    h.style.cssText = "font-size:19px;font-weight:700;color:#e74c3c;margin-bottom:12px";
    const p = document.createElement("div");
    p.textContent =
      "This site tried to secretly place a system command on your clipboard. " +
      "Pages that ask you to press Win+R (or open a terminal) and paste something " +
      "“to verify you are human” are installing malware that steals saved " +
      "passwords, cookies and wallets. Never paste it. Close this tab.";
    p.style.cssText = "font-size:14px;line-height:1.55;margin-bottom:14px";
    const cmd = document.createElement("div");
    cmd.textContent = "Blocked command: " + sample.slice(0, 160);
    cmd.style.cssText =
      "font-family:monospace;font-size:12px;background:#0f172a;padding:10px;" +
      "border-radius:6px;word-break:break-all;margin-bottom:18px;color:#f39c12";
    const leave = document.createElement("button");
    leave.textContent = "Leave this site";
    leave.style.cssText =
      "padding:10px 18px;border:none;border-radius:6px;font-size:14px;cursor:pointer;" +
      "background:#27ae60;color:#fff;margin-right:10px";
    leave.addEventListener("click", () => {
      location.href = "about:blank";
    });
    const stay = document.createElement("button");
    stay.textContent = "Dismiss (I understand the risk)";
    stay.style.cssText =
      "padding:10px 18px;border:1px solid #444;border-radius:6px;font-size:14px;" +
      "cursor:pointer;background:transparent;color:#888";
    stay.addEventListener("click", () => {
      host.remove();
      clickFixShown = false;
    });
    box.append(h, p, cmd, leave, stay);
    shadow.appendChild(box);
    (document.body || document.documentElement).appendChild(host);
  }

  // ---- Proactive ClickFix instruction detector ----
  // Fires BEFORE any clipboard write — scans the visible DOM for the fake-
  // verification instruction pattern ("press Win+R / ⌘+Space, open Terminal,
  // paste, hit return"). If we wait for the clipboard hook to fire, the user
  // may have already read and started following steps 1-3.
  //
  // Signals scored on visible page text. Any 3 = strong ClickFix signal.
  const CLICKFIX_KEY_HINTS = [
    "⌘ + space", "⌘+space", "cmd + space", "cmd+space", "command + space",
    "win + r", "win+r", "windows key + r", "windows + r", "run dialog",
    "ctrl + v", "⌘ + v", "⌘+v", "cmd + v", "cmd+v"
  ];
  const CLICKFIX_APP_HINTS = [
    "terminal", "powershell", "command prompt", "cmd.exe",
    "run dialog", "spotlight"
  ];
  const CLICKFIX_ACTION_HINTS = [
    "paste the copied command", "paste the command", "paste it in",
    "press return", "press enter", "hit enter", "hit return",
    "to verify you are human", "prove you are human",
    "quick verification", "security check", "human verification",
    "complete the following steps", "complete these steps to continue",
    "verify securely"
  ];

  let clickFixScanned = false;
  function scanForClickFixInstructions() {
    if (clickFixScanned || clickFixShown) return;
    if (!document.body) return;
    // Cap text scan — long articles never have all three signal classes.
    const text = (document.body.textContent || "").toLowerCase().slice(0, 8000);
    if (text.length < 40) return;

    let score = 0;
    for (const kw of CLICKFIX_KEY_HINTS) { if (text.indexOf(kw) !== -1) { score++; break; } }
    for (const kw of CLICKFIX_APP_HINTS) { if (text.indexOf(kw) !== -1) { score++; break; } }
    for (const kw of CLICKFIX_ACTION_HINTS) { if (text.indexOf(kw) !== -1) { score++; break; } }
    // Numbered step list ("1.", "2.", "3.", "4.") is another strong tell —
    // ClickFix pages are structured as ordered instructions.
    if (/(?:^|\s)1\.\s.+\s2\.\s.+\s3\.\s/.test(text)) score++;

    if (score >= 3) {
      clickFixScanned = true;
      send({ type: "blocked-clickfix" });
      showClickFixWarning("(scam instructions detected on this page — no command was pasted to your clipboard yet)");
    }
  }

  function startClickFixWatch() {
    // Scan a few times as the page settles — some ClickFix sites inject the
    // instructions after a short delay to bypass static scanners.
    scanForClickFixInstructions();
    setTimeout(scanForClickFixInstructions, 800);
    setTimeout(scanForClickFixInstructions, 2500);
    setTimeout(scanForClickFixInstructions, 6000);
  }
  if (document.readyState === "loading") {
    addEventListener("DOMContentLoaded", startClickFixWatch);
  } else {
    startClickFixWatch();
  }

  // Force noopener on _blank links so opened tabs can't hijack this one.
  addEventListener(
    "click",
    (e) => {
      if (!enabled) return;
      const a = e.target instanceof Element ? e.target.closest("a[target='_blank']") : null;
      if (a) {
        const rel = (a.getAttribute("rel") || "").toLowerCase();
        if (!rel.includes("noopener")) {
          a.setAttribute("rel", (rel + " noopener noreferrer").trim());
        }
      }
    },
    true
  );

  // ---- Invisible full-page overlay killer ----
  const neutralized = new WeakSet();

  function looksLikeClickTrap(el) {
    if (neutralized.has(el)) return false;
    if (!(el instanceof HTMLElement)) return false;
    if (el.tagName === "HTML" || el.tagName === "BODY") return false;

    const style = getComputedStyle(el);
    if (style.position !== "fixed" && style.position !== "absolute") return false;
    if (style.pointerEvents === "none") return false;

    const z = parseInt(style.zIndex, 10);
    if (isNaN(z) || z < 1000) return false;

    const rect = el.getBoundingClientRect();
    const coversViewport =
      rect.width >= innerWidth * 0.9 && rect.height >= innerHeight * 0.9;
    if (!coversViewport) return false;

    const invisible =
      parseFloat(style.opacity) < 0.05 ||
      (style.backgroundColor === "rgba(0, 0, 0, 0)" &&
        !el.textContent.trim() &&
        el.children.length === 0);
    return invisible;
  }

  function neutralize(el) {
    neutralized.add(el);
    el.style.setProperty("pointer-events", "none", "important");
    send({ type: "blocked-overlay" });
  }

  // ---- Visible interstitial-ad killer ----
  // Distinct from the click-trap killer above: this handles VISIBLE modal ads
  // that jump on top of the page 3-30s after load (dark backdrop + ad card in
  // the middle + fake close button). Pure behavioural detection — no domain
  // lists. Scored so no single signal triggers on its own.
  const domContentLoadedAt = Date.now();
  const suppressed = new WeakSet();
  let bodyScrollLocked = false;

  // Watch the body for programmatic scroll-lock (a modal-appeared tell).
  try {
    const bodyObs = new MutationObserver(() => {
      if (!document.body) return;
      const overflow = document.body.style.overflow;
      if (overflow === "hidden" || overflow === "clip") bodyScrollLocked = true;
    });
    if (document.body) {
      bodyObs.observe(document.body, { attributes: true, attributeFilter: ["style", "class"] });
    } else {
      addEventListener("DOMContentLoaded", () => {
        if (document.body) bodyObs.observe(document.body, { attributes: true, attributeFilter: ["style", "class"] });
      });
    }
  } catch {}

  function baseDomain(hostname) {
    if (!hostname) return null;
    const parts = hostname.split(".");
    return parts.slice(-2).join(".");
  }

  function isCrossSiteHref(href) {
    if (!href) return false;
    if (/^(#|javascript:|mailto:|tel:|data:|blob:|about:)/i.test(href)) return false;
    try {
      const u = new URL(href, location.href);
      if (u.protocol !== "http:" && u.protocol !== "https:") return false;
      return baseDomain(u.hostname) !== baseDomain(location.hostname);
    } catch {
      return false;
    }
  }

  function backgroundAlpha(bg) {
    // Matches rgba(r,g,b,a) or rgb(r,g,b) — returns 0 for transparent, 1 for opaque.
    const m = bg && bg.match(/rgba?\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*(?:,\s*(\d*\.?\d+))?\s*\)/);
    if (!m) return 0;
    return m[1] === undefined ? 1 : parseFloat(m[1]);
  }

  // Text keywords that mean "this modal is a legit cookie/consent/login/paywall
  // dialog, not an ad" — hits here strongly discount the score.
  const LEGIT_KEYWORDS = [
    "cookie", "consent", "gdpr", "privacy policy", "tracking",
    "subscribe", "newsletter", "sign up for our",
    "confirm your age", "over 18", "18+", "adult content", "age verification",
    "sign in", "log in", "logged out", "session expired",
    "premium", "membership", "subscription required", "paywall"
  ];

  // Well-known chat/support/consent widgets — cross-site content from these
  // hosts is legitimate and must not be scored as a floating ad.
  const LEGIT_WIDGET_HOSTS = [
    "intercom.io", "intercomcdn.com",
    "zendesk.com", "zdassets.com",
    "drift.com", "driftt.com",
    "hubspot.com", "hs-scripts.com", "hs-analytics.net",
    "tawk.to",
    "crisp.chat",
    "freshdesk.com", "freshworks.com",
    "zopim.com",
    "olark.com",
    "livechatinc.com",
    "chatra.io",
    // Consent/CMP frameworks
    "usercentrics.eu",
    "onetrust.com", "cookielaw.org",
    "cookiebot.com",
    "trustarc.com",
    "quantcast.mgr.consensu.org",
    "iabtcf.eu"
  ];

  function isLegitWidgetHref(href) {
    if (!href) return false;
    try {
      const u = new URL(href, location.href);
      if (u.protocol !== "http:" && u.protocol !== "https:") return false;
      const h = u.hostname.toLowerCase();
      return LEGIT_WIDGET_HOSTS.some((d) => h === d || h.endsWith("." + d));
    } catch {
      return false;
    }
  }

  function scoreInterstitial(el) {
    if (suppressed.has(el)) return 0;
    if (!(el instanceof HTMLElement)) return 0;
    if (el.tagName === "HTML" || el.tagName === "BODY") return 0;

    const style = getComputedStyle(el);
    if (style.position !== "fixed" && style.position !== "absolute") return 0;
    if (style.display === "none" || style.visibility === "hidden") return 0;
    if (parseFloat(style.opacity) < 0.1) return 0;

    const rect = el.getBoundingClientRect();
    // Interstitials always cover the majority of the viewport (backdrop + card).
    // Anything smaller than 70% is a corner banner, not a page-blocking modal.
    if (rect.width < innerWidth * 0.7 || rect.height < innerHeight * 0.7) return 0;

    const z = parseInt(style.zIndex, 10);
    if (isNaN(z) || z < 100) return 0;

    let score = 0;

    // Backdrop: dark translucent bg or a backdrop-filter blur. This is the
    // "dim the rest of the page" tell.
    const alpha = backgroundAlpha(style.backgroundColor);
    const hasFilter = style.backdropFilter && style.backdropFilter !== "none";
    if (alpha > 0.4 || hasFilter) score += 2;

    // Delayed injection: legit modals (age gates, cookie banners) show on
    // page load. Ad interstitials typically appear 3-30s later.
    if (Date.now() - domContentLoadedAt > 2500) score += 1;

    // Body scroll-lock set by JS after load — common to all modals, but
    // combined with the other signals it's a small positive.
    if (bodyScrollLocked) score += 1;

    // Cross-site content — the strongest ad signal.
    const links = el.querySelectorAll("a[href]");
    let hasCrossSiteAnchor = false;
    let sameOriginLinks = 0;
    for (const a of links) {
      if (isCrossSiteHref(a.getAttribute("href") || a.href)) {
        hasCrossSiteAnchor = true;
      } else if (a.href && !/^(#|javascript:)/i.test(a.href)) {
        sameOriginLinks++;
      }
    }
    if (hasCrossSiteAnchor) score += 2;

    let hasCrossSiteIframe = false;
    for (const f of el.querySelectorAll("iframe[src]")) {
      const src = f.getAttribute("src") || "";
      if (isCrossSiteHref(src)) { hasCrossSiteIframe = true; break; }
    }
    if (hasCrossSiteIframe) score += 1;

    // ---- Negative signals: things legit modals do that ads rarely do ----

    // Same-origin links only, no cross-site → probably a first-party CTA.
    if (!hasCrossSiteAnchor && !hasCrossSiteIframe && sameOriginLinks > 0) score -= 1;

    // Auth / signup forms — dead giveaway for login walls / newsletter modals.
    if (el.querySelector("input[type=password], input[type=email]")) score -= 3;

    // Keyword scan on the first 2 KB of text — cheap and catches cookie/consent
    // banners, age gates, paywalls in most languages via the English/technical
    // words their frameworks emit.
    const text = (el.textContent || "").toLowerCase().slice(0, 2000);
    for (const kw of LEGIT_KEYWORDS) {
      if (text.indexOf(kw) !== -1) { score -= 3; break; }
    }

    return score;
  }

  function killInterstitial(el) {
    if (suppressed.has(el)) return;
    suppressed.add(el);
    // Hide, don't remove — the page's own scripts may reference the node and
    // throw if it's missing. display:none is enforced with !important so the
    // ad script can't just flip it back.
    el.style.setProperty("display", "none", "important");
    // Restore scroll if the modal locked it. If a legit modal is up too we may
    // over-restore, but the FP cost is low.
    try {
      if (document.body && document.body.style.overflow === "hidden") {
        document.body.style.overflow = "";
      }
      if (document.documentElement && document.documentElement.style.overflow === "hidden") {
        document.documentElement.style.overflow = "";
      }
    } catch {}
    send({ type: "blocked-overlay" });
  }

  // Smaller floating ads (fake chat notifications, dating-scam cards, sticky
  // corner banners). Different threat model than interstitials: they don't
  // cover the page, so backdrop/scroll-lock signals don't apply. The dominant
  // tell is a cross-site link injected into a fixed card after page load.
  function scoreFloatingAd(el) {
    if (suppressed.has(el)) return 0;
    if (!(el instanceof HTMLElement)) return 0;
    if (el.tagName === "HTML" || el.tagName === "BODY") return 0;

    const style = getComputedStyle(el);
    if (style.position !== "fixed") return 0; // sticky corner ads are always position:fixed
    if (style.display === "none" || style.visibility === "hidden") return 0;
    if (parseFloat(style.opacity) < 0.1) return 0;

    const rect = el.getBoundingClientRect();
    // Skip icons/pixels and full-viewport interstitials (handled elsewhere).
    if (rect.width < 120 || rect.height < 60) return 0;
    if (rect.width >= innerWidth * 0.7 && rect.height >= innerHeight * 0.7) return 0;

    const z = parseInt(style.zIndex, 10);
    if (isNaN(z) || z < 50) return 0;

    // Legit widgets show with the page; ads inject on a timer. 1.5 s cutoff
    // is aggressive but page-load races on slow connections still land inside it.
    if (Date.now() - domContentLoadedAt < 1500) return 0;

    // Auth forms + legit keywords = never an ad.
    if (el.querySelector("input[type=password], input[type=email]")) return 0;
    const text = (el.textContent || "").toLowerCase().slice(0, 2000);
    for (const kw of LEGIT_KEYWORDS) {
      if (text.indexOf(kw) !== -1) return 0;
    }

    let score = 0;

    // Cross-site anchor as clickable content is the dominant signal.
    let hasCrossSiteAnchor = false;
    let allSameOrigin = true;
    let sawLink = false;
    for (const a of el.querySelectorAll("a[href]")) {
      const href = a.getAttribute("href") || a.href;
      if (/^(#|javascript:)/i.test(href)) continue;
      sawLink = true;
      if (isLegitWidgetHref(href)) return 0; // Intercom/Zendesk etc.
      if (isCrossSiteHref(href)) hasCrossSiteAnchor = true;
      else allSameOrigin = allSameOrigin && true;
      if (isCrossSiteHref(href)) allSameOrigin = false;
    }
    if (hasCrossSiteAnchor) score += 3;
    if (sawLink && allSameOrigin) score -= 2;

    // Cross-site iframe as content = strong ad signal.
    for (const f of el.querySelectorAll("iframe[src]")) {
      const src = f.getAttribute("src") || "";
      if (isLegitWidgetHref(src)) return 0;
      if (isCrossSiteHref(src)) { score += 2; break; }
    }

    // Body scroll-locked means it's a real modal, not a floating card — so
    // that path is handled by the interstitial detector, not this one.
    if (bodyScrollLocked) score -= 2;

    return score;
  }

  function scanInterstitials(root) {
    if (!overlaysOn || !root || !root.querySelectorAll) return;
    // Also score the root itself — MutationObserver added-node paths pass the
    // ad wrapper directly, and querySelectorAll only reaches descendants.
    if (root instanceof HTMLElement && !suppressed.has(root)) {
      if (scoreInterstitial(root) >= 4) { killInterstitial(root); return; }
      if (scoreFloatingAd(root) >= 3) { killInterstitial(root); return; }
    }
    // Only elements that could plausibly be a modal shell — cheap filter first,
    // scoring is per-element and involves getComputedStyle.
    for (const el of root.querySelectorAll("div, section, aside, dialog, [role='dialog']")) {
      if (suppressed.has(el)) continue;
      if (scoreInterstitial(el) >= 4) { killInterstitial(el); continue; }
      if (scoreFloatingAd(el) >= 3) killInterstitial(el);
    }
  }

  // Track shadow roots we've already wired up so we don't re-observe them.
  const observedRoots = new WeakSet();

  function scan(root) {
    if (!overlaysOn || !root.querySelectorAll) return;
    for (const el of root.querySelectorAll("div, a, span, iframe, section")) {
      if (looksLikeClickTrap(el)) neutralize(el);
    }
    scanInterstitials(root);
    // Recurse into any open shadow roots — full-viewport transparent overlays
    // are increasingly hidden inside shadow trees to dodge selectors.
    for (const el of root.querySelectorAll("*")) {
      if (el.shadowRoot) observeRoot(el.shadowRoot);
    }
  }

  const observer = new MutationObserver((mutations) => {
    if (!overlaysOn) return;
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node instanceof HTMLElement) {
          if (looksLikeClickTrap(node)) neutralize(node);
          scan(node);
        }
      }
      // Attribute changes on existing nodes matter for both detectors — the ad
      // often lives in the DOM at load time hidden (display:none), then a
      // timer flips display:block. Re-score the mutated element.
      if (m.type === "attributes" && m.target instanceof HTMLElement) {
        const t = m.target;
        if (scoreInterstitial(t) >= 4) { killInterstitial(t); continue; }
        if (scoreFloatingAd(t) >= 3) killInterstitial(t);
      }
    }
  });

  function observeRoot(root) {
    if (!root || observedRoots.has(root)) return;
    observedRoots.add(root);
    scan(root);
    try {
      observer.observe(root, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["style", "class", "hidden"]
      });
    } catch {}
  }

  function start() {
    observeRoot(document);
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["style", "class", "hidden"]
    });
    // Delayed re-scans catch interstitials whose timer fires after DCL — the
    // MutationObserver picks up most, but display-flip-only changes on ancestors
    // can be missed if the scored element itself wasn't mutated. Cheap safety net.
    setTimeout(() => scanInterstitials(document), 3000);
    setTimeout(() => scanInterstitials(document), 8000);
    setTimeout(() => scanInterstitials(document), 20000);
  }

  if (document.readyState === "loading") {
    addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
