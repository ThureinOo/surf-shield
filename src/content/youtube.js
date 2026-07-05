// YouTube-specific ad handler. Runs at document_start on youtube.com only.
//
// Three responsibilities:
//   1. CSS-hide the static ads YouTube renders in its own DOM (sidebar promo,
//      masthead ad, home-feed sponsored cards, in-player text overlay, etc.)
//   2. Auto-skip in-video ads by fast-forwarding the ad segment and clicking
//      the "Skip Ad" button as soon as it appears
//   3. Dismiss YouTube's anti-adblock nag modal when it shows up
//
// Note: YouTube renames its DOM classes roughly every 2–6 weeks. When ads
// start slipping through, update HIDE_SELECTORS / SKIP_SELECTORS below.
(() => {
  "use strict";
  if (window.__ssYouTubeHooked) return;
  window.__ssYouTubeHooked = true;

  // ---- 1. CSS-based ad hiding ----
  // Injected at document_start so the ads never flash on first paint.
  const HIDE_SELECTORS = [
    // Home / feed / channel-page ad cards
    "ytd-ad-slot-renderer",
    "ytd-in-feed-ad-layout-renderer",
    "ytd-display-ad-renderer",
    "ytd-promoted-sparkles-web-renderer",
    "ytd-promoted-sparkles-text-search-renderer",
    "ytd-promoted-video-renderer",
    "ytd-search-pyv-renderer",
    "ytd-banner-promo-renderer",
    "ytd-statement-banner-renderer",
    "ytd-mealbar-promo-renderer",
    "ytd-companion-slot-renderer",
    "ytd-action-companion-ad-renderer",
    "ytd-single-option-survey-renderer",
    "ytd-brand-video-shelf-renderer",
    "ytd-brand-video-singleton-renderer",
    // Watch-page sidebar
    "ytd-compact-promoted-item-renderer",
    "ytd-watch-next-secondary-results-renderer ytd-ad-slot-renderer",
    // Shorts / Reel ads
    "ytd-reel-video-renderer[is-ad]",
    "ytm-companion-ad-renderer",
    // In-player overlays
    ".ytp-ad-overlay-container",
    ".ytp-ad-text-overlay",
    ".ytp-featured-product",
    ".ytp-suggested-action",
    "#player-ads",
    "#masthead-ad",
    "#below-the-player",
    // YouTube Music
    "ytmusic-mealbar-promo-renderer",
    "ytmusic-statement-banner-renderer",
    "ytmusic-companion-ad-renderer"
  ];

  function injectCss() {
    const css = HIDE_SELECTORS.join(",\n") + " { display: none !important; }";
    const s = document.createElement("style");
    s.textContent = css;
    (document.head || document.documentElement).appendChild(s);
  }
  injectCss();

  // ---- 2. In-video ad skipper ----
  // YouTube tags the player with `ad-showing` / `ad-interrupting` during ads.
  // When either is set: seek the video element to the end of the ad segment
  // (YouTube treats that as "ad finished") and click any visible Skip button.
  const SKIP_SELECTORS = [
    ".ytp-ad-skip-button-modern",
    ".ytp-ad-skip-button",
    ".ytp-skip-ad-button",
    ".ytp-ad-skip-button-container button",
    "button.ytp-ad-skip-button"
  ];

  function tryFastForwardAd() {
    const video = document.querySelector("video.html5-main-video");
    if (video && Number.isFinite(video.duration) && video.duration > 0) {
      try { video.currentTime = video.duration; } catch {}
      // Some ads are muted-eligible; keep it that way while we skip.
      try { video.muted = true; } catch {}
    }
    for (const sel of SKIP_SELECTORS) {
      const btn = document.querySelector(sel);
      if (btn && !btn.disabled) {
        try { btn.click(); return; } catch {}
      }
    }
  }

  function watchPlayer(player) {
    const check = () => {
      if (
        player.classList.contains("ad-showing") ||
        player.classList.contains("ad-interrupting")
      ) {
        tryFastForwardAd();
      }
    };
    check();
    new MutationObserver(check).observe(player, {
      attributes: true,
      attributeFilter: ["class"]
    });
  }

  // The player element is added asynchronously. Poll briefly, then attach
  // once found; also watch for SPA navigation (YouTube swaps pages without
  // full reloads) via the yt-navigate-finish event.
  function bindWhenReady() {
    const player = document.querySelector(".html5-video-player");
    if (player) {
      watchPlayer(player);
      return true;
    }
    return false;
  }
  if (!bindWhenReady()) {
    const poll = setInterval(() => {
      if (bindWhenReady()) clearInterval(poll);
    }, 500);
    setTimeout(() => clearInterval(poll), 30000);
  }
  document.addEventListener("yt-navigate-finish", () => {
    // Fresh player instance after SPA nav — re-attach observer.
    setTimeout(bindWhenReady, 250);
  });

  // ---- 3. Anti-adblock nag dismiss ----
  // When YouTube detects blocking it shows a modal ("Ad blockers violate
  // YouTube's Terms of Service"). Remove it and resume playback if paused.
  const NAG_SELECTORS = [
    "tp-yt-paper-dialog:has(ytd-enforcement-message-view-model)",
    "ytd-enforcement-message-view-model",
    "tp-yt-paper-dialog[aria-label*='Ad block' i]",
    "tp-yt-paper-dialog[aria-label*='blocker' i]"
  ];

  function killNag() {
    let killed = false;
    for (const sel of NAG_SELECTORS) {
      try {
        for (const el of document.querySelectorAll(sel)) {
          el.remove();
          killed = true;
        }
      } catch {} // :has() unsupported in some browsers; ignore syntax throws
    }
    if (killed) {
      const video = document.querySelector("video.html5-main-video");
      if (video && video.paused) try { video.play(); } catch {}
      // Unblock scrolling if the nag locked it.
      if (document.body && document.body.style.overflow === "hidden") {
        document.body.style.overflow = "";
      }
    }
  }

  new MutationObserver(killNag).observe(document.documentElement, {
    childList: true,
    subtree: true
  });
})();
