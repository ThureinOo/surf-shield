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
  // Debug: remove after mid-roll behavior is confirmed. Filter in DevTools
  // console with the string [SS-YT] to see only Surf Shield events.
  console.log("[SS-YT] activated on", location.href);

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

  // Grid-cell / row-item wrappers whose inner ad content is already
  // covered by HIDE_SELECTORS above. Hiding just the inner element leaves
  // an empty grid slot (visible as a missing first card on the homepage
  // row). Using `:has()` collapses the entire wrapper so the surrounding
  // grid reflows to fill the space. `:has()` is supported in Chrome 105+,
  // Safari 15.4+, Firefox 121+ — universal on any browser that runs MV3.
  const AD_WRAPPER_SELECTORS = [
    // Home / channel / feed grid cells
    "ytd-rich-item-renderer:has(ytd-ad-slot-renderer)",
    "ytd-rich-item-renderer:has(ytd-in-feed-ad-layout-renderer)",
    "ytd-rich-item-renderer:has(ytd-display-ad-renderer)",
    "ytd-rich-item-renderer:has(ytd-promoted-video-renderer)",
    "ytd-rich-item-renderer:has(ytd-promoted-sparkles-web-renderer)",
    "ytd-rich-item-renderer:has(ytd-brand-video-shelf-renderer)",
    "ytd-rich-item-renderer:has(ytd-brand-video-singleton-renderer)",
    // Section rows (banners, mealbars, promo shelves)
    "ytd-rich-section-renderer:has(ytd-statement-banner-renderer)",
    "ytd-rich-section-renderer:has(ytd-mealbar-promo-renderer)",
    "ytd-rich-section-renderer:has(ytd-banner-promo-renderer)",
    "ytd-rich-section-renderer:has(ytd-brand-video-shelf-renderer)",
    "ytd-rich-section-renderer:has(ytd-brand-video-singleton-renderer)",
    // Watch-page sidebar
    "ytd-item-section-renderer:has(ytd-compact-promoted-item-renderer)",
    "ytd-item-section-renderer:has(ytd-ad-slot-renderer)",
    // Search results
    "ytd-item-section-renderer:has(ytd-search-pyv-renderer)",
    "ytd-item-section-renderer:has(ytd-promoted-sparkles-text-search-renderer)",
    // Shorts shelf slots
    "ytd-reel-video-renderer:has(ytd-ad-slot-renderer)",
  ];

  function injectCss() {
    const all = HIDE_SELECTORS.concat(AD_WRAPPER_SELECTORS);
    const css = all.join(",\n") + " { display: none !important; }";
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

  function isAdShowing() {
    const p = document.querySelector(".html5-video-player");
    return !!p && (
      p.classList.contains("ad-showing") ||
      p.classList.contains("ad-interrupting")
    );
  }

  function tryFastForwardAd() {
    const video = document.querySelector("video.html5-main-video");
    if (!video) return;

    try { video.muted = true; } catch {}

    const d = video.duration;
    if (Number.isFinite(d) && d > 0) {
      if (!video.__ssSeekLogged) {
        console.log(`[SS-YT] seek: duration=${d.toFixed(1)}s -> seeking to end`);
        video.__ssSeekLogged = true;
      }
      try { video.currentTime = d; } catch {}
      // Nudge YT's state machine — some ad flows freeze at the seek and
      // wait on tracker responses. Firing `ended` unblocks the transition.
      if (!video.__ssEndedFired) {
        video.__ssEndedFired = true;
        try { video.dispatchEvent(new Event("ended")); } catch {}
      }
    } else {
      // Mid-roll ads: `.ad-showing` fires BEFORE the ad video's metadata
      // loads, so `duration` is NaN at this instant and the seek is a
      // no-op. Retry on metadata events. The `isAdShowing` guard is
      // critical — without it, `timeupdate` on the content video after
      // the ad ends would seek the user's own video to its end.
      if (!video.__ssAdRetry) {
        video.__ssAdRetry = true;
        console.log(`[SS-YT] seek deferred: duration=${d} - waiting for metadata`);
        const retry = () => {
          if (!isAdShowing()) return;
          const dur = video.duration;
          if (Number.isFinite(dur) && dur > 0) {
            if (!video.__ssRetryLogged) {
              console.log(`[SS-YT] metadata ready: duration=${dur.toFixed(1)}s -> seeking to end`);
              video.__ssRetryLogged = true;
            }
            try { video.currentTime = dur; } catch {}
          }
        };
        video.addEventListener("durationchange", retry);
        video.addEventListener("loadedmetadata", retry);
        video.addEventListener("timeupdate", retry);
      }
      // Fallback: if the seek is impossible (e.g. Infinity for a
      // live-style ad), compress it. Restored in watchPlayer.
      if (!video.__ssRateBoosted) {
        try {
          video.playbackRate = 16;
          video.__ssRateBoosted = true;
          console.log("[SS-YT] rate boost: -> 16x (fallback)");
        } catch {}
      }
    }

    for (const sel of SKIP_SELECTORS) {
      const btn = document.querySelector(sel);
      if (btn && !btn.disabled) {
        if (!video.__ssSkipLogged) {
          console.log(`[SS-YT] skip button clicked: ${sel}`);
          video.__ssSkipLogged = true;
        }
        try { btn.click(); return; } catch {}
      }
    }
  }

  function watchPlayer(player) {
    if (player.__ssWatched) return; // survive SPA nav re-attach attempts
    player.__ssWatched = true;

    let lastAdState = null;
    const check = () => {
      const isAd =
        player.classList.contains("ad-showing") ||
        player.classList.contains("ad-interrupting");
      if (isAd !== lastAdState) {
        // Skip the null->false initial transition (no ad at page load).
        if (lastAdState !== null || isAd) {
          console.log(`[SS-YT] ad state: ${isAd ? "showing" : "ended"} @ ${new Date().toISOString().slice(11, 19)}`);
        }
        lastAdState = isAd;
        if (!isAd) {
          const video = document.querySelector("video.html5-main-video");
          if (video) {
            if (video.__ssRateBoosted) {
              try { video.playbackRate = 1; } catch {}
              video.__ssRateBoosted = false;
              console.log("[SS-YT] rate restored: 1x");
            }
            // Reset per-ad log guards (NOT __ssAdRetry — that's a
            // per-video-element listener flag, kept for the video's life).
            video.__ssSeekLogged = false;
            video.__ssRetryLogged = false;
            video.__ssSkipLogged = false;
            video.__ssEndedFired = false;
          }
        }
      }
      if (isAd) tryFastForwardAd();
    };
    check();
    new MutationObserver(check).observe(player, {
      attributes: true,
      attributeFilter: ["class"]
    });
    // Belt-and-braces: catches back-to-back ads (class stays `ad-showing`
    // across them so the observer doesn't refire) and the skip button
    // YouTube renders seconds after ad start.
    const id = setInterval(() => {
      if (!player.isConnected) { clearInterval(id); return; }
      check();
    }, 500);
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
