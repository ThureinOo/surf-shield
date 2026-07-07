// Hides leftover ad containers using generic cosmetic selectors from the
// bundled filter lists (network blocking leaves empty frames behind).
(() => {
  "use strict";
  // YouTube handled entirely by src/content/youtube-bundle.js — running
  // 13k generic selectors against YT's DOM was adding seconds to page load.
  if (/(?:^|\.)youtube(?:-nocookie)?\.com$/.test(location.hostname)) return;
  const api = typeof browser !== "undefined" ? browser : chrome;

  // Orphaned-script safety: sendMessage throws after an extension reload.
  function send(msg, cb) {
    try {
      api.runtime.sendMessage(msg, (res) => {
        void api.runtime.lastError;
        cb(res);
      });
    } catch {}
  }

  send({ type: "get-config" }, (config) => {
    if (!config || config.allowed || config.settings.cosmetics === false) return;

    send({ type: "get-cosmetics" }, (res) => {
      if (!res || !Array.isArray(res.selectors) || res.selectors.length === 0) return;

      // Chunked rules: one invalid selector voids only its chunk of 50,
      // not the whole stylesheet — cheaper than validating each selector.
      const CHUNK = 50;
      let css = "";
      for (let i = 0; i < res.selectors.length; i += CHUNK) {
        css += res.selectors.slice(i, i + CHUNK).join(",") + "{display:none !important;}\n";
      }
      const style = document.createElement("style");
      style.textContent = css;
      (document.head || document.documentElement).appendChild(style);
    });
  });
})();
