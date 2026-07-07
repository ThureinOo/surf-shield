// Runs in the page's MAIN world at document_start.
// Wraps window.open so only genuine, recent user clicks on real links can open windows.
(() => {
  "use strict";
  if (window.__surfShieldHooked) return;
  window.__surfShieldHooked = true;
  // YouTube is a first-party trusted site — no popunder ads, no synthetic
  // click-hijack redirects. The iframe.contentWindow / click / form-submit
  // wrappers were fighting YT's own SPA and iframe machinery, adding several
  // seconds of load time. Skip on YT; YT ad handling lives in youtube-bundle.js.
  if (/(?:^|\.)youtube(?:-nocookie)?\.com$/.test(location.hostname)) return;

  const GESTURE_WINDOW_MS = 1000;
  const CROSS_SITE_OPEN_BUDGET = 2;
  // Well-known IdP popup hosts — "Sign in with X" flows often go through a
  // redirector on the parent site, so lastClickedHref doesn't match the popup
  // target. Let these through without consuming the popup budget, provided the
  // user still made a genuine click.
  const OAUTH_HOSTS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "appleid.apple.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "www.facebook.com",
    "www.linkedin.com",
    "api.twitter.com",
    "x.com",
    "discord.com",
    "slack.com",
    "auth0.com",
    "okta.com",
    "onelogin.com"
  ];
  function isOAuthPopup(host) {
    if (!host) return false;
    return OAUTH_HOSTS.some((h) => host === h || host.endsWith("." + h));
  }
  let crossSiteOpens = 0;
  let lastTrustedClick = 0;
  let lastClickWasSafe = false;
  let lastClickedHref = null;
  let guardsOn = true;
  let notificationsBlocked = true;

  // Handshake nonce: written to the DOM here (before any page script runs),
  // read + removed synchronously by the isolated-world guard. Config events
  // without it are page-forged and ignored — otherwise a malicious site could
  // dispatch {popups:false} and switch these guards off.
  const NONCE = crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2);
  try {
    document.documentElement.setAttribute("data-ssn", NONCE);
  } catch {}

  // Config arrives from the isolated-world guard once it has read settings
  // and the allowlist ("Trust this site" must disable these hooks too).
  addEventListener("__surfshield_config", (e) => {
    if (!e.detail || e.detail.nonce !== NONCE) return;
    guardsOn = e.detail.popups !== false;
    notificationsBlocked = e.detail.notifications !== false;
  });

  function isSafeClickTarget(target) {
    if (!(target instanceof Element)) return false;
    const el = target.closest("a, button, input, select, textarea, [role='button'], [role='link'], video, audio, summary, label");
    if (!el) return false;
    const style = getComputedStyle(el);
    if (parseFloat(style.opacity) < 0.05 || style.visibility === "hidden") return false;
    return true;
  }

  function hostOf(u) {
    try {
      return new URL(u, location.href).hostname.replace(/^www\./, "");
    } catch {
      return null;
    }
  }

  addEventListener(
    "click",
    (e) => {
      if (!e.isTrusted) return;
      lastTrustedClick = Date.now();
      lastClickWasSafe = isSafeClickTarget(e.target);
      const a = e.target instanceof Element ? e.target.closest("a[href]") : null;
      const href = a ? a.getAttribute("href") : null;
      lastClickedHref =
        href && !/^(#|javascript:)/i.test(href) ? new URL(href, location.href).href : null;
    },
    true
  );

  function report() {
    dispatchEvent(
      new CustomEvent("__surfshield_blocked", { detail: { kind: "popup", nonce: NONCE } })
    );
  }

  const nativeOpen = window.open.bind(window);
  window.open = function (url, name, features) {
    if (!guardsOn) return nativeOpen(url, name, features);
    const sinceClick = Date.now() - lastTrustedClick;
    const hasGesture = sinceClick >= 0 && sinceClick <= GESTURE_WINDOW_MS;

    if (!hasGesture || !lastClickWasSafe) {
      report();
      return null;
    }

    // Click-hijack check: user clicked a real link, but the page tries to
    // open a window to a *different* third-party domain than the link points
    // to (classic popunder on download sites). Block it.
    const baseDomain = (h) => (h ? h.split(".").slice(-2).join(".") : null);
    const openHost = hostOf(url);
    const openBase = baseDomain(openHost);
    const pageBase = baseDomain(hostOf(location.href));
    const isOAuth = isOAuthPopup(openHost);
    if (lastClickedHref && openBase && !isOAuth) {
      const clickedBase = baseDomain(hostOf(lastClickedHref));
      if (openBase !== clickedBase && openBase !== pageBase) {
        report();
        return null;
      }
    }
    // Non-link clicks (buttons, divs): page-wide click listeners hijack these
    // to open ad tabs — the "click N times before your download" gauntlet.
    // OAuth-style popups from buttons are legitimate, so allow a small
    // per-page budget of cross-site opens instead of hard-blocking.
    // Known IdPs (accounts.google.com, appleid.apple.com, ...) skip the budget.
    if (!lastClickedHref && openBase && openBase !== pageBase && !isOAuth) {
      if (crossSiteOpens >= CROSS_SITE_OPEN_BUDGET) {
        report();
        return null;
      }
      crossSiteOpens++;
    }
    // Consume the gesture: one click = at most one window (kills popunders
    // that open several tabs per click).
    lastTrustedClick = 0;

    const win = nativeOpen(url, name, features);
    if (win) {
      try {
        win.opener = null;
      } catch {}
    }
    return win;
  };

  // Prevent the page from restoring the native window.open.
  try {
    Object.defineProperty(window, "open", {
      value: window.open,
      writable: false,
      configurable: false
    });
  } catch {}

  // ---- Popunder de-cloak ----
  // After opening an ad tab, popunder scripts call window.blur()/self.blur()
  // to push it behind the current window so the user doesn't notice. No
  // legitimate page needs to blur its own window — make it a no-op.
  try {
    const nativeBlur = window.blur.bind(window);
    window.blur = function () {
      if (guardsOn) return;
      return nativeBlur();
    };
  } catch {}

  // ---- Synthetic-click popunder blocker ----
  // Ad scripts create <a target="_blank" href="https://ad.example/..."> and
  // dispatch a fake click; browsers navigate anchors even for untrusted
  // clicks, bypassing the window.open wrapper. Kill those here.
  function blockUntrustedNav(e) {
    if (!guardsOn || e.isTrusted) return;
    const a = e.target instanceof Element ? e.target.closest("a[href]") : null;
    if (!a) return;
    const targetsBlank = (a.getAttribute("target") || "").toLowerCase() === "_blank";
    const crossSite = hostOf(a.href) && hostOf(a.href) !== hostOf(location.href);
    if (targetsBlank || crossSite) {
      e.preventDefault();
      e.stopImmediatePropagation();
      report();
    }
  }
  addEventListener("click", blockUntrustedNav, true);
  addEventListener("mousedown", blockUntrustedNav, true);
  addEventListener("auxclick", blockUntrustedNav, true);

  // element.click() skips event dispatch to listeners in some engines, so
  // also patch the anchor prototype: programmatic .click() on a _blank or
  // cross-site anchor needs a recent genuine user gesture.
  const nativeClick = HTMLElement.prototype.click;
  HTMLAnchorElement.prototype.click = function () {
    const fresh = Date.now() - lastTrustedClick <= GESTURE_WINDOW_MS;
    const targetsBlank = (this.getAttribute("target") || "").toLowerCase() === "_blank";
    if (guardsOn && targetsBlank && !fresh) {
      report();
      return;
    }
    return nativeClick.call(this);
  };

  // Block synthetic _blank form submits (another popunder vector).
  addEventListener(
    "submit",
    (e) => {
      if (!guardsOn || e.isTrusted) return;
      const form = e.target;
      if (form && (form.getAttribute("target") || "").toLowerCase() === "_blank") {
        e.preventDefault();
        e.stopImmediatePropagation();
        report();
      }
    },
    true
  );

  // ---- Fresh-iframe native grab defense ----
  // Anti-adblock scripts create an about:blank iframe and use its clean,
  // unhooked contentWindow.open. Content-script injection into such frames
  // races with the page, so also trap the getters and hook the child's
  // window.open on first access.
  function hookChildWindow(w) {
    try {
      if (!w || w.__surfShieldHooked) return;
      w.__surfShieldHooked = true;
      const childOpen = w.open.bind(w);
      w.open = function (url, name, features) {
        if (!guardsOn) return childOpen(url, name, features);
        const fresh = Date.now() - lastTrustedClick <= GESTURE_WINDOW_MS;
        if (!fresh || !lastClickWasSafe) {
          report();
          return null;
        }
        // Same cross-site budget as the top window — iframes must not be a
        // way around the click-gauntlet limit. IdP popups still skip the budget.
        const baseDomain = (h) => (h ? h.split(".").slice(-2).join(".") : null);
        const openHost = hostOf(url);
        const openBase = baseDomain(openHost);
        const pageBase = baseDomain(hostOf(location.href));
        if (!lastClickedHref && openBase && openBase !== pageBase && !isOAuthPopup(openHost)) {
          if (crossSiteOpens >= CROSS_SITE_OPEN_BUDGET) {
            report();
            return null;
          }
          crossSiteOpens++;
        }
        lastTrustedClick = 0;
        const win = childOpen(url, name, features);
        if (win) {
          try {
            win.opener = null;
          } catch {}
        }
        return win;
      };
    } catch {}
  }

  for (const [proto, prop] of [
    [HTMLIFrameElement.prototype, "contentWindow"],
    [HTMLIFrameElement.prototype, "contentDocument"],
    [HTMLObjectElement.prototype, "contentWindow"]
  ]) {
    try {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || !desc.get) continue;
      Object.defineProperty(proto, prop, {
        ...desc,
        get() {
          const value = desc.get.call(this);
          if (prop === "contentDocument") {
            if (value) hookChildWindow(value.defaultView);
          } else {
            hookChildWindow(value);
          }
          return value;
        }
      });
    } catch {}
  }

  // ---- ClickFix / clipboard-hijack blocker ----
  // Fake-CAPTCHA pages ("prove you're human: press Win+R and paste") copy a
  // PowerShell one-liner to the clipboard — the dominant infostealer delivery
  // method. No legitimate site silently puts shell commands on your clipboard.
  // Substring match on lowercased text — cheap, ReDoS-proof, and runs on every
  // clipboard write, so it must stay fast even on multi-megabyte pastes.
  const SHELL_MARKERS = [
    // Windows
    "powershell", "pwsh", "mshta", "msiexec", "wscript", "cscript",
    "rundll32", "regsvr32", "bitsadmin", "certutil",
    "cmd.exe", "cmd /c", "cmd/c",
    "iex ", "iex(", "invoke-expression", "invoke-webrequest",
    "downloadstring", "frombase64string",
    "-encodedcommand", "-windowstyle hidden", "hidden -command",
    // macOS / Linux
    "osascript", "osascript -e", "do shell script",
    "/bin/sh", "/bin/bash", "/bin/zsh",
    "bash -c", "sh -c", "zsh -c",
    "python -c", "python3 -c", "perl -e", "ruby -e",
    "chmod +x", "chmod 755", "chmod 777",
    // Cross-platform droppers
    "curl ", "curl -", "wget ",
    "| bash", "| sh", "| zsh",
    "eval $(", "eval \"$(",
    "base64 -d", "base64 --decode"
  ];

  function reportClickFix(sample) {
    dispatchEvent(
      new CustomEvent("__surfshield_blocked", {
        detail: { kind: "clickfix", nonce: NONCE, sample: String(sample).slice(0, 300) }
      })
    );
  }

  function isShellCommand(text) {
    if (typeof text !== "string" || text.length < 8) return false;
    // Only scan the leading window — legitimate huge copies (whole articles,
    // code blocks) never *start* with a shell dropper, and this caps cost.
    const head = text.slice(0, 2048).toLowerCase();
    for (let i = 0; i < SHELL_MARKERS.length; i++) {
      if (head.indexOf(SHELL_MARKERS[i]) !== -1) return true;
    }
    return false;
  }

  if (navigator.clipboard && navigator.clipboard.writeText) {
    const nativeWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = function (text) {
      if (guardsOn && isShellCommand(text)) {
        reportClickFix(text);
        // Resolve (don't reject) so the page thinks it worked and doesn't
        // fall back to another copy technique.
        return Promise.resolve();
      }
      return nativeWriteText(text);
    };
  }
  if (navigator.clipboard && navigator.clipboard.write) {
    const nativeWrite = navigator.clipboard.write.bind(navigator.clipboard);
    navigator.clipboard.write = async function (items) {
      if (guardsOn && items) {
        try {
          for (const item of items) {
            if (item.types && item.types.includes("text/plain")) {
              const text = await (await item.getType("text/plain")).text();
              if (isShellCommand(text)) {
                reportClickFix(text);
                return;
              }
            }
          }
        } catch {}
      }
      return nativeWrite(items);
    };
  }

  // Legacy path: page selects a hidden textarea and calls execCommand("copy").
  const nativeExecCommand = document.execCommand.bind(document);
  document.execCommand = function (command, ...rest) {
    if (guardsOn && String(command).toLowerCase() === "copy") {
      let text = "";
      try {
        const sel = document.getSelection();
        text = sel ? sel.toString() : "";
        const active = document.activeElement;
        if (!text && active && typeof active.value === "string") {
          text = active.value.slice(
            active.selectionStart || 0,
            active.selectionEnd == null ? undefined : active.selectionEnd
          ) || active.value;
        }
      } catch {}
      if (isShellCommand(text)) {
        reportClickFix(text);
        return true; // pretend it worked
      }
    }
    return nativeExecCommand(command, ...rest);
  };

  // "Click Allow to continue" push-notification scams. Wrapped (not
  // replaced) so the options toggle / allowlist can let it through.
  if ("Notification" in window) {
    try {
      const nativeRequest = Notification.requestPermission.bind(Notification);
      Notification.requestPermission = (...args) =>
        notificationsBlocked ? Promise.resolve("denied") : nativeRequest(...args);
    } catch {}
  }

  // Same-tab click-hijack guard. The popup guards above cover `window.open`,
  // anchor clicks, and form submits — but a page-level handler like
  // `document.addEventListener('click', () => location.href = evil)` bypasses
  // all of them. This block wraps every navigation API that can steer the
  // current tab (`location.assign`, `location.replace`, `location.href =`)
  // and applies the same "recent-click + cross-origin + not-on-a-link"
  // heuristic already used for popups. Blocks cost the site's fake budget,
  // then falls through so real user-initiated cross-origin navigation still
  // works.
  function shouldBlockNav(url) {
    if (!guardsOn) return false;
    const target = hostOf(url);
    if (!target) return false;
    const base = (h) => (h ? h.split(".").slice(-2).join(".") : null);
    const targetBase = base(target);
    const pageBase = base(hostOf(location.href));
    if (!targetBase || targetBase === pageBase) return false; // same-origin
    if (isOAuthPopup(target)) return false;
    const sinceClick = Date.now() - lastTrustedClick;
    if (sinceClick < 0 || sinceClick > GESTURE_WINDOW_MS) return false; // no gesture
    if (lastClickedHref) {
      const clickedBase = base(hostOf(lastClickedHref));
      if (clickedBase === targetBase) return false; // legit link click
    }
    if (lastClickWasSafe && lastClickedHref) return false; // clicked a link somewhere else
    console.warn("[surf-shield] blocked click-hijack nav ->", url);
    report();
    return true;
  }

  const LocationProto = Location.prototype;
  try {
    const origAssign = LocationProto.assign;
    LocationProto.assign = function (url) {
      if (shouldBlockNav(url)) return;
      return origAssign.call(this, url);
    };
  } catch {}
  try {
    const origReplace = LocationProto.replace;
    LocationProto.replace = function (url) {
      if (shouldBlockNav(url)) return;
      return origReplace.call(this, url);
    };
  } catch {}
  try {
    const hrefDesc = Object.getOwnPropertyDescriptor(LocationProto, "href");
    if (hrefDesc && hrefDesc.set) {
      const origSet = hrefDesc.set;
      Object.defineProperty(LocationProto, "href", {
        configurable: true,
        get: hrefDesc.get,
        set(url) {
          if (shouldBlockNav(url)) return;
          return origSet.call(this, url);
        },
      });
    }
  } catch {}
})();
