// Pure constants + scoring functions extracted from background.js.
// Nothing here has state or side effects — it's safe to import from
// anywhere in the service worker.

// ---- Brand impersonation lists ----
export const BRANDS = [
  "paypal", "google", "facebook", "instagram", "apple", "icloud",
  "microsoft", "outlook", "amazon", "netflix", "whatsapp", "telegram",
  "binance", "coinbase", "metamask", "steam", "roblox", "spotify"
];

export const OFFICIAL_DOMAINS = {
  paypal: ["paypal.com", "paypal.me"],
  google: ["google.com", "goo.gl", "withgoogle.com", "google.dev"],
  facebook: ["facebook.com", "fb.com", "fb.me"],
  instagram: ["instagram.com"],
  apple: ["apple.com"],
  icloud: ["icloud.com"],
  microsoft: ["microsoft.com", "live.com", "microsoftonline.com"],
  outlook: ["outlook.com", "live.com"],
  amazon: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "a.co"],
  netflix: ["netflix.com"],
  whatsapp: ["whatsapp.com", "wa.me"],
  telegram: ["telegram.org", "t.me"],
  binance: ["binance.com"],
  coinbase: ["coinbase.com"],
  metamask: ["metamask.io"],
  steam: ["steampowered.com", "steamcommunity.com"],
  roblox: ["roblox.com"],
  spotify: ["spotify.com"]
};

export const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "top", "xyz", "icu", "cyou",
  "rest", "sbs", "cfd", "zip", "mov", "click", "gdn", "work"
]);

// Hosting/CDN domains whose subdomains legitimately look random
// (d3k9x1abc.cloudfront.net) — never DGA-score these.
export const INFRA_DOMAINS = [
  "cloudfront.net", "amazonaws.com", "azureedge.net", "azurewebsites.net",
  "akamaized.net", "akamaihd.net", "fastly.net", "cloudflare.net",
  "googleusercontent.com", "gstatic.com", "githubusercontent.com",
  "netlify.app", "vercel.app", "pages.dev", "web.app", "firebaseapp.com",
  "herokuapp.com", "windows.net", "cdn77.org", "b-cdn.net"
];

// Ad-URL fingerprints — very specific query strings and paths that
// legitimate sites basically never emit. Used by the phishing/chain
// scoring and by the DNR backstop.
export const AD_URL_PATTERNS = [
  /[?&]utm_medium=pop(?:under|up)/i,
  /[?&]zoneid=\d+/i,
  /\/afu\.php\?/,
  /\/sklnk\/\d+/,
  /\/partitial\/\d+/,
  /\/click\?trvid=\d+/,
  /[?&]ad_campaign_id=\d+/i,
  /[?&]subzone_id=/i,
  /[?&]cost=0\.\d+&currency=/i
];

// ---- Chain-score tuning ----
export const CHAIN_WINDOW_MS = 3000;
export const CHAIN_MAX_HOPS = 3;
export const CHAIN_SCORE_THRESHOLD = 5;

// ---- Auto-trust TTL ----
export const SEEN_TTL_MS = 30 * 86400 * 1000;

// ---- Activity ring buffer cap ----
export const STATS_EVENTS_MAX = 300;

// ---- Utility functions ----

export function safeHostOf(u) {
  try { return new URL(u).hostname; } catch { return null; }
}

export function etldPlusOne(hostname) {
  // Naive eTLD+1: good enough for heuristic scoring.
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const twoPartTlds = new Set(["co.uk", "com.au", "co.jp", "com.br", "co.in", "com.tr", "com.mx"]);
  const lastTwo = parts.slice(-2).join(".");
  if (twoPartTlds.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

export function levenshtein(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 99;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[a.length][b.length];
}

// DGA-ish label check: malware C2 and disposable malvertising domains are
// machine-generated (xj3kq9vbn2m.top). Contributing signal only — never
// enough to block on its own.
export function looksGenerated(label) {
  if (label.length < 10) return false;
  if (label.includes("-")) return false; // human names hyphenate; DGAs rarely do
  const letters = label.replace(/[^a-z]/g, "");
  const digits = label.replace(/[^0-9]/g, "");
  // Long consonant runs — pronounceable words don't have 5 in a row.
  if (/[bcdfghjklmnpqrstvwxz]{5,}/.test(label)) return true;
  // Heavy letter/digit interleaving (x9k2j4q8...).
  const transitions = (label.match(/[a-z][0-9]|[0-9][a-z]/g) || []).length;
  if (digits.length >= 3 && transitions >= 3) return true;
  // Very low vowel ratio across a long, unhyphenated label.
  const vowels = (letters.match(/[aeiouy]/g) || []).length;
  if (letters.length >= 10 && vowels / letters.length < 0.2) return true;
  return false;
}

export function phishingScore(urlStr) {
  let url;
  try {
    url = new URL(urlStr);
  } catch {
    return { score: 0, reasons: [] };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return { score: 0, reasons: [] };

  const host = url.hostname.toLowerCase();
  const base = etldPlusOne(host);
  const reasons = [];
  let score = 0;

  if (host.startsWith("xn--") || host.includes(".xn--")) {
    score += 2;
    reasons.push("Punycode (lookalike character) domain");
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    score += 2;
    reasons.push("Raw IP address instead of a domain name");
  }
  if (url.username) {
    score += 2;
    reasons.push("Credentials embedded in URL (user@host trick)");
  }
  const tld = host.split(".").pop();
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 1;
    reasons.push(`High-abuse TLD (.${tld})`);
  }
  if (host.split(".").length >= 5) {
    score += 1;
    reasons.push("Excessive subdomain nesting");
  }
  const isInfra = INFRA_DOMAINS.some((d) => host === d || host.endsWith("." + d));
  if (!isInfra && looksGenerated(base.split(".")[0])) {
    score += 2;
    reasons.push("Machine-generated (DGA-style) domain name");
  }
  if (url.protocol === "http:" && /login|signin|account|verify|secure|wallet/i.test(urlStr)) {
    score += 1;
    reasons.push("Login-related page served over insecure HTTP");
  }

  // Brand impersonation: brand appears in hostname but domain isn't official.
  const baseLabel = base.split(".")[0];
  for (const brand of BRANDS) {
    const official = OFFICIAL_DOMAINS[brand] || [];
    if (official.includes(base)) break;
    // Google has ~150 regional ccTLDs (google.co.uk, google.de, google.co.jp,
    // …), a dozen infrastructure domains (googleusercontent.com used for
    // Drive file content, googleapis.com, gstatic.com, googletagmanager.com,
    // google-analytics.com, googleadservices.com, googlesyndication.com),
    // AND owns three exclusive gTLDs — .google, .goog, .gmail — under which
    // every hostname is Google's (projectzero.google, store.google, ...).
    // Listing every one is unmaintainable — pattern-match instead.
    if (brand === "google") {
      // Any google.<tld> where the TLD isn't itself in the suspicious set
      // (google.tk is not a real Google property; google.co.uk is).
      if (baseLabel === "google" && !SUSPICIOUS_TLDS.has(base.split(".").pop())) break;
      if (/\.(?:google|goog|gmail)$/.test(host)) break; // Google-exclusive gTLDs
      if (/^(?:googleusercontent|googleapis|gstatic|googletagmanager|google-analytics|googleadservices|googlesyndication)\.com$/.test(base)) break;
    }
    if (host.includes(brand) && !official.some((d) => host === d || host.endsWith("." + d))) {
      score += 3;
      reasons.push(`Impersonates "${brand}" (official: ${official[0]})`);
      break;
    }
    const dist = levenshtein(baseLabel, brand);
    if (dist > 0 && dist <= 1 && baseLabel.length >= 5) {
      score += 3;
      reasons.push(`Typosquat of "${brand}" (${baseLabel})`);
      break;
    }
  }

  return { score, reasons };
}

// Ranks the badness of a committed redirect chain. Returns { score, reasons }.
// The reasons array is what the warning page shows the user so they understand
// *why* the chain looked malicious.
export function chainScore(chain, currentUrl) {
  const reasons = [];
  let score = 0;
  const hops = chain.hops || [];
  if (hops.length < 2) return { score, reasons };

  // 4+ hops through unrelated domains is a hard block on its own — no
  // legitimate flow needs that many.
  if (hops.length >= 4) {
    return { score: 99, reasons: [`Redirect chain through ${hops.length} unrelated domains`] };
  }
  if (hops.length === 3) { score += 3; reasons.push("3-hop redirect chain"); }
  else if (hops.length === 2) { score += 1; reasons.push("2-hop redirect chain"); }

  // Timing: sub-second per-hop average = automated JS redirects, not human
  // clicks through an OAuth flow.
  const span = hops[hops.length - 1].time - hops[0].time;
  const avg = span / Math.max(1, hops.length - 1);
  if (avg < 300) { score += 2; reasons.push("Sub-second automated redirects"); }
  else if (avg < 800) { score += 1; }

  // Per-hop reputation signals — reuse the same signals the phishing scorer uses.
  let sus = 0, dga = 0, rawIp = 0, puny = 0;
  for (const hop of hops) {
    const host = hop.host;
    const tld = host.split(".").pop();
    if (SUSPICIOUS_TLDS.has(tld)) sus++;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) rawIp++;
    if (host.startsWith("xn--") || host.includes(".xn--")) puny++;
    const isInfra = INFRA_DOMAINS.some((d) => host === d || host.endsWith("." + d));
    const baseLabel = etldPlusOne(host).split(".")[0];
    if (!isInfra && looksGenerated(baseLabel)) dga++;
  }
  if (sus)   { score += sus;      reasons.push(`${sus} hop(s) on high-abuse TLDs`); }
  if (dga)   { score += dga * 2;  reasons.push(`${dga} machine-generated domain(s) in chain`); }
  if (rawIp) { score += rawIp * 2; reasons.push(`${rawIp} raw-IP hop(s)`); }
  if (puny)  { score += puny;     reasons.push(`${puny} punycode hop(s)`); }

  // Any hop URL (or the final destination) matches a known ad-redirect URL pattern.
  const hopUrls = hops.map((h) => h.url).filter(Boolean);
  const matchesAdPattern = (u) => u && AD_URL_PATTERNS.some((re) => re.test(u));
  if (hopUrls.some(matchesAdPattern) || matchesAdPattern(currentUrl)) {
    score += 3;
    reasons.push("Chain routed through a known ad-URL pattern");
  }

  // Chain landed in a tab that was opened from a popup — typical of
  // forced-download / popunder-then-redirect flows.
  if (chain.fromPopup) {
    score += 2;
    reasons.push("Chain started in a popup tab");
  }

  return { score, reasons };
}
