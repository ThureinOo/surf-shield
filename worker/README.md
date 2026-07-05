# Surf Shield report Worker

Cloudflare Worker that accepts scam reports from the extension popup and
files them as GitHub Issues on this repo. Users never touch GitHub — the
Worker holds a bot token and creates issues on their behalf.

Free tier is 100k requests/day. At realistic report volumes (~5/month per
1000 users), you will not pay.

## Deploy (~30 minutes, one time)

### 1. Prerequisites

```
npm install -g wrangler
wrangler login   # opens browser, log in to Cloudflare
```

If you don't have a Cloudflare account, sign up first at
[cloudflare.com](https://cloudflare.com) — free.

### 2. Create a GitHub bot token

- Go to <https://github.com/settings/personal-access-tokens/new>
- Choose **fine-grained**, expires 90+ days
- **Repository access:** only this repo (`ThureinOo/surf-shield`)
- **Permissions:** *Issues → Read and write*. Nothing else.
- Copy the token — you'll paste it in step 4.

### 3. (Optional but recommended) Create a KV namespace

Enables rate limiting (5 reports per IP per hour) and dedupe (repeat reports
of the same domain within 24h become comments on the first issue).

```
cd worker
wrangler kv namespace create REPORTS_KV
```

Wrangler prints an `id`. Uncomment the `[[kv_namespaces]]` block in
`wrangler.toml` and paste the id there.

### 4. Deploy

```
cd worker
wrangler deploy
```

Wrangler prints the URL, e.g. `https://surf-shield-report.<your>.workers.dev`.

Set the GitHub token as a Worker secret:

```
wrangler secret put GITHUB_TOKEN
# paste the token from step 2 when prompted
```

### 5. Wire the extension to the Worker URL

Open `src/ui/popup/popup.js` and set:

```js
const REPORT_ENDPOINT = "https://surf-shield-report.<your>.workers.dev";
```

Reload the extension (`chrome://extensions` → refresh). The "Report this site
as scam" button in the popup is now live.

If `REPORT_ENDPOINT` is left empty, the button is hidden — safe default so
forks/OSS installs without their own Worker don't 404.

## What the Worker does

- Accepts `POST /` with JSON `{ url, reason, notes, version }`
- Validates: URL is HTTP(S), reason ∈ known set, notes ≤ 500 chars
- Refuses reports against a protected-domain list (google.com etc.)
- Rate limits: 5 reports per IP per hour (via KV)
- Dedupes: same hostname reported within 24h posts a comment on the existing
  issue instead of opening a new one
- Creates the GitHub Issue labelled `user-report, triage`
- Returns `{ ok: true, issue: <number> }` on success

Reporter identity is *not* stored. The Cloudflare geo header (`cf-ipcountry`)
is included on issues so you can see rough geographic patterns; the IP itself
is only used for rate-limit keying and a short deterministic differentiator
in dedupe comments.

## Triage workflow

New reports appear at
<https://github.com/ThureinOo/surf-shield/issues?q=is%3Aissue+label%3Auser-report+is%3Aopen>.

For a legitimate report:

1. Verify the domain — VirusTotal, urlscan.io, open in a sandboxed VM.
2. Add to `remote/blocklist.json` (`domains` for silent block, `phishingDomains`
   for warning page). Use `node scripts/block.mjs <domain>` locally, or trigger
   the "Block domain(s)" workflow with the approval gate.
3. Close the issue as *"added in v0.3.x"* — reporter watches the issue and gets
   notified.

For a false report: close with a short reason. The dedupe cache means the same
domain won't spam you again for 24h.

## Local testing

```
cd worker
wrangler dev
```

Wrangler runs a local server. Send a test report:

```
curl -X POST http://127.0.0.1:8787/ \
  -H "content-type: application/json" \
  -d '{"url":"https://evil.example/phish","reason":"phishing","notes":"test","version":"0.2.1"}'
```

Response should be `{"ok":true,"issue":<n>,"url":"..."}`. In `wrangler dev`
without a real `GITHUB_TOKEN` secret set locally, the create-issue call fails
with 502 — that is expected. To actually test end-to-end, create a
`.dev.vars` file (added to `.gitignore`) with:

```
GITHUB_TOKEN=your_token_here
```

## Rotating the GitHub token

Recommended quarterly.

1. Create a new fine-grained token (step 2 above).
2. `wrangler secret put GITHUB_TOKEN` — paste the new one.
3. Revoke the old token at <https://github.com/settings/personal-access-tokens>.

The old Worker code keeps running through the swap — no downtime.
