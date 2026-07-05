# Surf Shield

Cross-browser (Chrome + Firefox, Manifest V3) extension that protects against
malicious ads, popunders, forced redirects, phishing sites, and risky downloads.

## Features

- **Ads & trackers** — ~29k declarativeNetRequest rules built from AdGuard Popups, EasyPrivacy, and EasyList (`rules/generated.json`) plus handcrafted rules for popunder networks and rotating-domain URL patterns (`rules/ads.json`)
- **Popups & popunders** — MAIN-world guards: one window per genuine user click, click-hijack destination matching, a 2-per-page budget for cross-site opens from non-link clicks (kills "click 5 times" download gauntlets while keeping OAuth popups working), synthetic-click and `.click()` blocking, `_blank` form-submit blocking, fresh-iframe `window.open` traps, `window.blur()` popunder de-cloaking (`src/content/page_hooks.js`)
- **Invisible click-trap overlays** — full-viewport transparent high-z-index elements get `pointer-events: none` (`src/content/guard.js`)
- **Redirect chains** — 3+ rapid cross-domain redirects are cut with a warning page
- **Phishing** — heuristic scoring: punycode lookalikes (decoded on the warning page), IP hosts, credential-in-URL, high-abuse TLDs, brand typosquats, DGA-style machine-generated domain names, provenance boost (arriving from a threat-listed site or right after an ad block raises the score)
- **Risky downloads** — .exe/.scr/.bat etc. are paused with a warning tab (Resume / Cancel)
- **Cosmetic filtering** — ~13k element-hiding selectors (`rules/cosmetic.json`)
- **Remote blocklist** — fetched daily from this repo (`remote/blocklist.json`); edits reach all users within 24 hours, no release needed
- **Threat-intel feeds** — URLhaus, Hagezi TIF Mini, and Phishing Army aggregated daily into `remote/threat-domains.json`; sub-resources from malware domains are blocked silently, direct visits and phishing domains get the warning page (bypassable one visit at a time only)
- **Stealer-delivery protection** — download risk scoring (double extensions, fake installer names, ad-redirect provenance) and ClickFix clipboard-hijack blocking (pages that copy hidden shell commands "to verify you are human") — Windows + macOS payloads
- **Visible interstitial + floating-ad killer** — behavioural scoring: fixed-position elements with dark backdrop / cross-site anchor / delayed injection / body scroll-lock are hidden; legit chat widgets (Intercom, Zendesk, Drift, HubSpot, OneTrust, Cookiebot, etc.) and cookie/consent/login modals are recognised and left alone (`src/content/guard.js`)
- **One-click scam reporting** — popup button files a GitHub issue via a Cloudflare Worker (no GitHub account needed for the user); reports arrive in this repo pre-triaged, rate-limited and deduped (`worker/`)

## User guide

### Install (unpacked, for testing)

**Chrome / Edge / Brave**
1. `chrome://extensions` → enable Developer mode
2. "Load unpacked" → select this folder

**Firefox** (128+)
1. `about:debugging#/runtime/this-firefox`
2. "Load Temporary Add-on…" → select `manifest.json`
3. Remember to **Reload** the add-on after every code change

### The popup (toolbar icon)

- **Stats** — popups, overlays, redirects, phishing attempts, clipboard scams, and risky downloads blocked
- **Trust this site** — disables protection for the current site (adds to your allowlist) until you remove it. "Re-enable protection" undoes it. Disabled for domains on the shared/threat blocklists — those can only be bypassed one visit at a time from the warning page.
- **Block** — instantly blocks the current site in *your* browser only (personal blocklist). "Unblock" undoes it.
- **Check on VirusTotal** — opens the current domain's VirusTotal report
- **Report this site as scam** — one click sends a report to the maintainer via the Cloudflare Worker (no GitHub account required); pick a reason chip (phishing / fake support popup / malicious ad / suspicious download / other), add optional context, hit Send. The button is hidden when the extension is loaded on `chrome://`, extension pages, or forks that haven't deployed a Worker
- **Trusted sites / Blocked sites** — your lists; remove any entry with ✕

### Options page (gear icon)

Eight independent toggles: ads, cosmetic filtering, popups, overlays, phishing,
redirects, notification prompts, download protection.

### Warning pages

- **Navigation warning** — shows why a page was blocked (with decoded punycode hostname for lookalikes); "Go back" or proceed. Proceeding on a list-flagged domain (shared/threat blocklists) is valid for **one visit only** — next visit warns again; proceeding on a heuristic warning trusts the site for 1 hour
- **Download warning** — risky file paused; Resume or Cancel

## Project layout

```
manifest.json          extension manifest (must stay at root)
src/
  background.js        service worker: DNR rules, warnings, downloads, feeds, stats
  content/             injected scripts: page_hooks (MAIN world), guard, cosmetic
  ui/                  popup, options, warning page, onboarding page
rules/
  ads.json             handcrafted popunder/ad-network rules
  generated.json       auto-built from AdGuard/EasyList (weekly workflow)
  cosmetic.json        element-hiding selectors (weekly workflow)
remote/                fetched by users daily from raw.githubusercontent.com
icons/                 toolbar + store icons
scripts/               maintainer tools (build-rules.mjs, block.mjs, build-threat-feeds.mjs)
tests/                 attack simulations (test.html)
worker/                Cloudflare Worker that proxies user scam reports into GitHub Issues
.github/workflows/     automation (filter rebuild, threat feeds, blocklist validation)
```

## Maintenance guide

### Filter lists (automated, weekly)

`.github/workflows/update-filter-rules.yml` runs every Monday (or manually via
"Run workflow"): rebuilds `rules/generated.json` + `rules/cosmetic.json` and opens a
PR. **Your job:** review, merge, bump the `manifest.json` version, and cut a
release — static rules only reach users through an extension update.

Manual rebuild any time:

```
node scripts/build-rules.mjs
```

### Remote blocklist (instant, no release)

Edit `remote/blocklist.json` on GitHub — add a domain to `domains` (ads/popups)
or `phishingDomains`, bump `version`, set `updated`. All users pick it up
within 24 hours via the daily alarm.

`.github/workflows/validate-blocklist.yml` checks every change: valid JSON,
required keys, valid domain syntax, no duplicates, valid regex patterns, and
refuses protected domains (google.com, github.com, ...).

### Threat feeds (automated, daily)

`.github/workflows/update-threat-feeds.yml` runs `scripts/build-threat-feeds.mjs`
daily: pulls URLhaus + Hagezi TIF Mini (malware) and Phishing Army (phishing),
validates/dedupes/caps (15k malware, 8k phishing), and commits
`remote/threat-domains.json` directly. No action needed unless a feed URL dies
(the script aborts rather than shipping an empty bucket).

### Adding domains to the blocklist (maintainer only)

Users can only block sites in their own browser; the shared list is curated by
you. Two ways to add:

**Locally** (validates, dedupes, refuses protected domains, bumps version):

```
node scripts/block.mjs evil.com https://other.bad/page
node scripts/block.mjs --phishing fake-login.top   # warning page instead of silent block
node scripts/block.mjs --push evil.com             # also commit + push
```

**From anywhere** (e.g. GitHub mobile app): Actions → "Block domain(s)" →
Run workflow → paste domains, pick ads/phishing. Only accounts with write
access can trigger it. Verify a domain first — the popup's VirusTotal button
or virustotal.com; an addition blocks the site for every user.

### Releasing

1. Confirm all simulations pass: `python3 -m http.server 8080` in the repo root, open
   `http://localhost:8080/tests/test.html` — 17 attack simulations with PASS/FAIL.
   **Clear Trusted sites in the popup first** — a leftover trusted test domain makes
   tests 10–13 silently pass through.
2. Real-world spot check on a shady download flow.
3. Verify the report Worker is live:
   ```
   curl -sS -X POST https://surf-shield-report.thureinoo.workers.dev \
     -H "content-type: application/json" \
     -d '{"url":"https://release-check.example/x","reason":"phishing","notes":"pre-release health check","version":"health"}'
   ```
   Expect `{"ok":true,"issue":<N>,...}`. Close the resulting issue.
4. Confirm `src/ui/popup/popup.js` `REPORT_ENDPOINT` still points at the production
   Worker URL (not an empty string or a dev override) — otherwise the popup's
   Report button will silently be hidden for all users.
5. Bump `version` in `manifest.json` (AMO rejects any version it has seen before).
6. Build the package (run from the repo root; manifest must be at the zip's top level):

   ```
   zip -r ../surf-shield-X.Y.Z.zip . -x ".git/*" ".github/*" "scripts/*" "tests/*" \
     "_metadata/*" "remote/*" "worker/*" ".gitignore" ".DS_Store" "*/.DS_Store"
   ```

   Exclusions:
   - `remote/` — users fetch it from GitHub at runtime; never read from the package
   - `worker/` — Cloudflare Worker source; runs on Cloudflare, not shipped in the extension
   - `scripts/`, `tests/`, `.github/` — maintainer tooling only
7. Upload: [AMO Developer Hub](https://addons.mozilla.org/developers/) → Surf Shield →
   **Upload New Version** (reuse the reviewer notes: link this repo, note that
   `rules/generated.json` + `rules/cosmetic.json` are reproducible with
   `node scripts/build-rules.mjs`, and that the linter's "coin miner" hit is a
   blocking rule from EasyList). Chrome Web Store dashboard once registered there.
8. Tag the release: `git tag vX.Y.Z && git push --tags`

**Worker deploys are decoupled from extension releases.** If you change the Worker
code, run `cd worker && wrangler deploy` — same URL, updated code, no extension
release needed. Only bump `manifest.json` when you change extension code that
users need to receive via a store update.

### When a new bypass appears

1. Identify the mechanism (DevTools, network log — what opened the tab / made the request?)
2. Rotating ad domains → add a URL-shape pattern (`zoneid=`, `afu.php`, ...) to `rules/ads.json` or `remote/blocklist.json` `patterns`; fixed domains → remote blocklist
3. New DOM/JS trick → extend `src/content/page_hooks.js` / `src/content/guard.js`
4. Add a simulation for it to `tests/test.html`

### User scam reports (Cloudflare Worker → GitHub Issues)

Users hit the popup's **🚩 Report this site as scam** button; a Cloudflare
Worker validates the report, rate-limits it, dedupes recent reports of the
same domain, and files it as a GitHub Issue on this repo. Reporters never
need a GitHub account.

**Architecture**

```
extension popup  ─(POST JSON)→  Cloudflare Worker  ─(GitHub API + PAT)→  GitHub Issue
                                     │
                                     └─ KV: rate limit (5/IP/hour) + dedupe (24h/hostname)
```

The Worker source lives in `worker/` — full deploy checklist in
[worker/README.md](worker/README.md). One-time setup takes ~30 minutes.

**Triaging incoming reports**

New reports appear at
<https://github.com/ThureinOo/surf-shield/issues?q=is%3Aissue+label%3Auser-report+is%3Aopen>.
Filter locally:

```
gh issue list --repo ThureinOo/surf-shield --label user-report --state open
```

For each report:

1. **Verify** the domain is actually malicious. Options:
   - VirusTotal — `https://www.virustotal.com/gui/domain/<domain>`
   - urlscan.io — `https://urlscan.io/search/#domain:<domain>` (shows a real screenshot)
   - Open in a private window with the extension on
2. **Accept** — add the domain to `remote/blocklist.json`, then close the issue. Three paths:
   - Local: `node scripts/block.mjs --push evil.example` (ads) or `node scripts/block.mjs --phishing --push evil.example` (phishing warning page). Auto-commits and pushes.
   - Actions UI: **Actions → "Block domain(s)" → Run workflow** (requires approval via the `blocklist-approval` environment).
   - Manual edit of `remote/blocklist.json` on GitHub.
   Close with a link to the commit:
   ```
   gh issue close <N> --repo ThureinOo/surf-shield --reason completed --comment "Blocked. Live for all users within 24h."
   ```
   Or add `closes #N` to the commit message so the push auto-closes the issue.
3. **Reject** — comment briefly and close as *not planned*:
   ```
   gh issue close <N> --repo ThureinOo/surf-shield --reason "not planned" --comment "Legitimate site, no malicious activity found."
   ```

Closing an issue does **nothing** to the blocklist by itself — it's just admin
state. The block-list edit is what actually protects users. Sequence matters:
verify → edit blocklist → push → close.

Dedupe: the Worker keeps 24h `dup:<hostname>` entries in KV. During that
window, repeat reports of the same domain post a comment on the original
issue instead of opening a new one — even if you've already closed it. After
24h, a fresh report opens a new issue.

**Rotating the GitHub token**

Fine-grained tokens expire (max 366 days). GitHub emails you 7 days before.
If a token expires, the Worker returns `{"error":"upstream failure"}` (502)
and popups show "Failed". No data is lost — the user can retry after rotation.

Rotation is atomic and takes 5 minutes:

1. Generate a new fine-grained PAT at
   <https://github.com/settings/personal-access-tokens/new> — scope only
   `ThureinOo/surf-shield`, permission only *Issues: read+write*, expiry 1 year.
2. Replace the Worker secret:
   ```
   cd worker
   wrangler secret put GITHUB_TOKEN
   ```
   Paste the new token. Cloudflare rolls the secret atomically — no redeploy.
3. Smoke-test:
   ```
   curl -X POST https://surf-shield-report.thureinoo.workers.dev \
     -H "content-type: application/json" \
     -d '{"url":"https://evil.example/rotation-test","reason":"phishing","notes":"post-rotation check","version":"health"}'
   ```
   Expect `{"ok":true,"issue":<N>,...}`. Close the resulting issue.
4. Revoke the old token at
   <https://github.com/settings/personal-access-tokens>.

Set a calendar reminder for 11 months out. Add a monthly smoke-test to your
calendar too — catches broken tokens before a real user does.

**Redeploying the Worker after code changes**

```
cd worker
wrangler deploy
```

Same URL, updated code, live instantly. No user-facing downtime.

**Monitoring**

Cloudflare dashboard → Workers & Pages → `surf-shield-report`:

- **Logs** tab — real-time request stream (useful when debugging)
- **Metrics** tab — request volume, error rate, CPU time
- **Settings → Variables** — inspect (but not read) the current `GITHUB_TOKEN` secret
- **Workers KV → REPORTS_KV** — see current rate-limit and dedupe entries

Free-tier limits: 100k requests/day, 1GB KV storage. A user base of tens of
thousands stays well under that. If you ever get close, the same code runs
on Cloudflare's paid tier ($5/mo, 10M requests/day) with no changes needed.

## License

GPL-3.0 — see [LICENSE](LICENSE). Modified redistributions must remain open source under the same license.

## Notes

- Heuristics may rarely flag legitimate sites; proceeding on a heuristic warning trusts the site for 1 hour, and the popup's "Trust this site" turns protection off permanently until removed. List-flagged domains can never be permanently trusted — one visit at a time only
- Dynamic DNR rule ID ranges: 10000–14999 allowlist, 15000–19999 personal blocklist, 20000–29999 remote list, 30000+ threat feeds
