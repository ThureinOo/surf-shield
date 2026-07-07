// Runs at document_start in MAIN world on youtube.com pages, BEFORE YT's own
// scripts execute. Prevents ads from ever being scheduled by patching the same
// code paths uBlock Origin's YouTube filters target:
//
//   1. Intercept assignment to `ytInitialPlayerResponse` / `playerResponse`
//      and prune ad fields from any value assigned (initial page load path).
//   2. Rewrite outbound InnerTube requests: `"clientScreen":"WATCH"` →
//      `"clientScreen":"ADUNIT"` so YT's server returns an ad-free response
//      with content buffered from t=0 (no post-ad-strip buffering stall).
//   3. Wrap fetch() and XMLHttpRequest responses to strip any ad markers
//      that slip through step 2 (SPA navigation safety net).
//   4. Fake `google_ad_status = 1` so YT's anti-adblock detector believes
//      ads loaded and never shows the nag modal.
//
// This is the primary defense; src/content/youtube.js remains as a DOM-level
// fallback for cases where YT changes something and this bundle misses.
(() => {
  "use strict";
  if (window.__ssYtBundle) return;
  window.__ssYtBundle = true;

  console.log("[SS-YT-bundle] injected @", location.href);

  const AD_KEYS = ["adPlacements", "adSlots", "playerAds"];
  const PLAYER_URL_RE = /\/youtubei\/v1\/(?:player|next|get_watch)/;

  // Renaming ad JSON keys (rather than deleting the values) is 30-50x
  // cheaper than JSON parse+stringify. YT's player looks up these exact
  // strings and treats "not found" as "no ads". Single alternation regex
  // = one native pass, one allocation, ~5x faster than three sequential
  // split/join replacements over the same 2MB body.
  const AD_KEY_RE = /"(adPlacements|adSlots|playerAds)"/g;

  // Fast substring check — bail before running the regex if the body
  // doesn't contain any ad key at all.
  const hasAdMarkers = (text) =>
    text.includes('"adPlacements"') ||
    text.includes('"adSlots"') ||
    text.includes('"playerAds"');

  const stripAdMarkers = (text) => text.replace(AD_KEY_RE, '"noAd_$1"');

  // Recursively delete ad keys from an already-parsed object. Used only by
  // the assignment-intercept path (protectGlobal) where we're handed a live
  // JS object, not a JSON string.
  const prune = (obj) => {
    if (!obj || typeof obj !== "object") return;
    if (Array.isArray(obj)) { for (const v of obj) prune(v); return; }
    for (const k of AD_KEYS) if (k in obj) delete obj[k];
    for (const k in obj) prune(obj[k]);
  };

  // ---- 1. Lock global player-response objects ----
  // Intercept `window.ytInitialPlayerResponse = {...}` so we prune the
  // ad fields before YT's player code reads them.
  const protectGlobal = (name) => {
    if (name in window && window[name] && typeof window[name] === "object") {
      prune(window[name]); // in case an inline script beat us to it
    }
    let stored = window[name];
    try {
      Object.defineProperty(window, name, {
        configurable: true,
        get() { return stored; },
        set(v) {
          if (v && typeof v === "object") prune(v);
          stored = v;
        },
      });
    } catch {}
  };
  protectGlobal("ytInitialPlayerResponse");
  protectGlobal("playerResponse");

  try {
    Object.defineProperty(window, "google_ad_status", {
      configurable: true,
      get() { return 1; },
      set() {},
    });
  } catch {}

  const shouldPrune = (u) => typeof u === "string" && PLAYER_URL_RE.test(u);

  // Rewrite `"clientScreen":"WATCH"` → `"clientScreen":"ADUNIT"` in outbound
  // /player request bodies. Tells YT's server this is an ad-preview client,
  // so it returns an ad-free response AND buffers content from t=0.
  const rewriteBody = (body) => {
    if (typeof body !== "string") return body;
    if (!body.includes('"clientScreen":"WATCH"')) return body;
    console.log("[SS-YT-bundle] rewrote outbound WATCH->ADUNIT");
    return body.split('"clientScreen":"WATCH"').join('"clientScreen":"ADUNIT"');
  };

  // ---- 2. Wrap fetch() ----
  const origFetch = window.fetch;
  window.fetch = function (input, init) {
    const url = typeof input === "string" ? input : input && input.url;
    if (shouldPrune(url) && init && init.body) {
      const nb = rewriteBody(init.body);
      if (nb !== init.body) init = Object.assign({}, init, { body: nb });
    }
    const p = origFetch.call(this, input, init);
    if (!shouldPrune(url)) return p;
    return p.then((res) =>
      res.clone().text().then((text) => {
        if (!hasAdMarkers(text)) return res;
        const cleaned = stripAdMarkers(text);
        return new Response(cleaned, {
          status: res.status,
          statusText: res.statusText,
          headers: res.headers,
        });
      }).catch(() => res)
    );
  };

  // ---- 3. Wrap XMLHttpRequest ----
  const XHR = XMLHttpRequest.prototype;
  const origOpen = XHR.open;
  const origSend = XHR.send;
  XHR.open = function (method, url, ...rest) {
    this.__ssPruneUrl = url;
    return origOpen.call(this, method, url, ...rest);
  };
  XHR.send = function (body) {
    if (shouldPrune(this.__ssPruneUrl) && body != null) {
      body = rewriteBody(body);
    }
    if (shouldPrune(this.__ssPruneUrl)) {
      this.addEventListener("readystatechange", () => {
        if (this.readyState !== 4) return;
        try {
          const raw = this.responseText;
          if (!raw || !hasAdMarkers(raw)) return;
          const cleaned = stripAdMarkers(raw);
          Object.defineProperty(this, "responseText", {
            configurable: true, get() { return cleaned; },
          });
          Object.defineProperty(this, "response", {
            configurable: true, get() { return cleaned; },
          });
        } catch {}
      });
    }
    return origSend.call(this, body);
  };
})();
