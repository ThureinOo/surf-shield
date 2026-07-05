// Cloudflare Worker: proxies user reports from the Surf Shield popup into
// GitHub Issues on this repo. The extension user never needs a GitHub account
// — this Worker holds a bot token and files the issue on their behalf.
//
// Deploy: see worker/README.md.
// Required secret: GITHUB_TOKEN (fine-grained PAT, scope: `Issues: read+write`
//                                on ThureinOo/surf-shield, no other permissions).
// Optional binding:  REPORTS_KV (KV namespace) — enables rate limiting + dedupe.
//                    Without it the endpoint still works, just relies on
//                    Cloudflare's built-in DDoS protection.
//
// The Worker is public and reachable from any extension install; validation
// and rate limits below are the only defenses against abuse. Do not remove.

const REPO_OWNER = "ThureinOo";
const REPO_NAME = "surf-shield";

const VALID_REASONS = new Set([
  "phishing", "fake-support", "malicious-ad", "suspicious-download", "other"
]);
const MAX_NOTES_LEN = 500;
const MAX_URL_LEN = 2048;
const RATE_LIMIT_PER_HOUR = 5;
const DEDUPE_WINDOW_HOURS = 24;

// Never let a report file an issue "against" one of these — the extension
// itself uses the same list to refuse blocklist entries. Prevents someone
// gaming the queue by mass-reporting google.com etc.
const PROTECTED_DOMAINS = [
  "google.com", "youtube.com", "facebook.com", "github.com",
  "microsoft.com", "apple.com", "amazon.com", "wikipedia.org", "cloudflare.com"
];

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400"
};

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (request.method !== "POST") return json({ error: "method not allowed" }, 405);

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid JSON" }, 400);
    }

    const { url, reason, notes, version } = body || {};
    if (typeof url !== "string" || url.length > MAX_URL_LEN || !isValidHttpUrl(url)) {
      return json({ error: "invalid url" }, 400);
    }
    if (!VALID_REASONS.has(reason)) {
      return json({ error: "invalid reason" }, 400);
    }
    const cleanNotes = typeof notes === "string" ? notes.slice(0, MAX_NOTES_LEN) : "";
    const cleanVersion = typeof version === "string" ? version.slice(0, 32) : "unknown";

    const hostname = new URL(url).hostname.toLowerCase();
    if (PROTECTED_DOMAINS.some((p) => hostname === p || hostname.endsWith("." + p))) {
      return json({ error: "cannot report protected domain" }, 400);
    }

    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const country = request.headers.get("cf-ipcountry") || "??";

    // Rate limit + dedupe when KV is bound. If not bound, both are no-ops.
    if (env.REPORTS_KV) {
      const hour = Math.floor(Date.now() / 3600000);
      const rlKey = `rl:${ip}:${hour}`;
      const count = parseInt((await env.REPORTS_KV.get(rlKey)) || "0", 10);
      if (count >= RATE_LIMIT_PER_HOUR) {
        return json({ error: "rate limit exceeded — try again in an hour" }, 429);
      }
      // Fire-and-forget writes (Worker will let them settle before returning).
      await env.REPORTS_KV.put(rlKey, String(count + 1), { expirationTtl: 3600 });

      const dedupeKey = `dup:${hostname}`;
      const existingIssue = await env.REPORTS_KV.get(dedupeKey);
      if (existingIssue) {
        const issueNumber = parseInt(existingIssue, 10);
        const commentStatus = await commentOnIssue(env.GITHUB_TOKEN, issueNumber,
          formatDedupeComment(reason, cleanNotes, country, ip));
        if (commentStatus === "ok") {
          return json({ ok: true, issue: issueNumber, deduped: true, commented: true });
        }
        if (commentStatus === "gone") {
          // Issue was deleted on GitHub — the KV entry is stale. Drop it and
          // fall through to open a fresh issue instead of failing silently.
          await env.REPORTS_KV.delete(dedupeKey);
        } else {
          // Real failure (rate limit, auth, network). Report status but do
          // NOT fall through — retrying create would double-file legit reports.
          return json({ ok: true, issue: issueNumber, deduped: true, commented: false });
        }
      }
    }

    const issue = await createIssue(env.GITHUB_TOKEN, {
      hostname, url, reason, notes: cleanNotes, version: cleanVersion, country
    });
    if (!issue) return json({ error: "upstream failure" }, 502);

    if (env.REPORTS_KV) {
      await env.REPORTS_KV.put(`dup:${hostname}`, String(issue.number), {
        expirationTtl: DEDUPE_WINDOW_HOURS * 3600
      });
    }

    return json({ ok: true, issue: issue.number, url: issue.html_url });
  }
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...CORS }
  });
}

function isValidHttpUrl(s) {
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

async function createIssue(token, { hostname, url, reason, notes, version, country }) {
  const title = `Report: ${hostname}`;
  const body = [
    `**Reported URL:** ${url}`,
    `**Hostname:** \`${hostname}\``,
    `**Reason:** ${reason}`,
    notes ? `**User notes:** ${notes}` : null,
    ``,
    `<details><summary>Metadata</summary>`,
    ``,
    `- Extension version: ${version}`,
    `- Reporter country (Cloudflare geo): ${country}`,
    `- Report time (UTC): ${new Date().toISOString()}`,
    `</details>`
  ].filter((x) => x !== null).join("\n");

  const res = await fetch(`https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/issues`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "User-Agent": "SurfShield-Worker/1.0",
      Accept: "application/vnd.github+json"
    },
    body: JSON.stringify({ title, body, labels: ["user-report", "triage"] })
  });
  if (!res.ok) {
    console.error("GitHub API createIssue failed:", res.status, await res.text());
    return null;
  }
  return await res.json();
}

async function commentOnIssue(token, issueNumber, body) {
  const res = await fetch(
    `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/issues/${issueNumber}/comments`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "User-Agent": "SurfShield-Worker/1.0",
        Accept: "application/vnd.github+json"
      },
      body: JSON.stringify({ body })
    }
  );
  if (res.ok) return "ok";
  // 404 = issue was deleted; 410 = issue was permanently removed. Either way
  // the dedupe target is gone and the caller should open a fresh issue.
  if (res.status === 404 || res.status === 410) return "gone";
  console.error("GitHub commentOnIssue failed:", res.status, await res.text());
  return "error";
}

function formatDedupeComment(reason, notes, country, ip) {
  return [
    `Another user reported this site.`,
    `**Reason:** ${reason}`,
    notes ? `**Notes:** ${notes}` : null,
    `**Reporter country:** ${country}`,
    ``,
    `<sub>Reporter differentiator: \`${cheapHash(ip)}\` (used for dedupe only, not identifying)</sub>`
  ].filter((x) => x !== null).join("\n");
}

function cheapHash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16).padStart(8, "0");
}
