#!/usr/bin/env node
// Aggregates public threat-intel feeds into remote/threat-domains.json.
// Run by .github/workflows/update-threat-feeds.yml daily; can be run locally:
//   node scripts/build-threat-feeds.mjs
// Requires Node 18+.

import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { Resolver } from "node:dns/promises";

// malware bucket -> silent DNR block; phishing bucket -> warning page on visit.
const FEEDS = [
  { name: "URLhaus", bucket: "malware", format: "hosts", url: "https://urlhaus.abuse.ch/downloads/hostfile/" },
  { name: "Hagezi TIF Mini", bucket: "malware", format: "adblock", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt" },
  { name: "Phishing Army", bucket: "phishing", format: "domains", url: "https://phishing.army/download/phishing_army_blocklist.txt" }
];

const MAX_MALWARE = 15000;
const MAX_PHISHING = 8000;

const PROTECTED = ["google.com", "youtube.com", "facebook.com", "github.com", "microsoft.com", "apple.com", "amazon.com", "wikipedia.org", "cloudflare.com"];
const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/;

function domainOk(d) {
  return (
    d.length <= 253 &&
    DOMAIN_RE.test(d) &&
    !PROTECTED.some((p) => d === p || d.endsWith("." + p))
  );
}

function parse(text, format) {
  const out = [];
  for (let line of text.split("\n")) {
    line = line.trim().toLowerCase();
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    if (format === "hosts") {
      const parts = line.split(/\s+/);
      if (parts.length < 2 || !/^(127\.0\.0\.1|0\.0\.0\.0)$/.test(parts[0])) continue;
      line = parts[1];
    } else if (format === "adblock") {
      const m = line.match(/^\|\|([a-z0-9.-]+)\^$/);
      if (!m) continue;
      line = m[1];
    }
    line = line.replace(/^www\./, "");
    if (domainOk(line)) out.push(line);
  }
  return out;
}

const malware = new Set();
const phishing = new Set();

for (const feed of FEEDS) {
  try {
    const res = await fetch(feed.url, { headers: { "User-Agent": "surf-shield-feed-builder" } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const domains = parse(await res.text(), feed.format);
    const target = feed.bucket === "malware" ? malware : phishing;
    for (const d of domains) target.add(d);
    console.log(`${feed.name}: ${domains.length} domains`);
  } catch (e) {
    console.error(`${feed.name}: FAILED — ${e.message}`);
    // A dead feed shouldn't wipe its bucket; abort so yesterday's file survives.
    process.exit(1);
  }
}

// Overlap goes to malware (stronger action).
for (const d of malware) phishing.delete(d);

// ---- Liveness filter ----
// Dead (NXDOMAIN) entries can't hurt anyone but waste the capped rule budget,
// so only domains that still resolve make the cut. Backfills from the full
// candidate pool until the cap is reached or candidates run out.
const resolver = new Resolver();
resolver.setServers(["1.1.1.1", "8.8.8.8"]);

async function isLive(domain) {
  const query = (type) =>
    resolver.resolve(domain, type).then((r) => r.length > 0, () => false);
  const timeout = new Promise((r) => setTimeout(r, 3000, false));
  return Promise.race([
    query("A").then((ok) => ok || query("AAAA").then((ok2) => ok2 || query("CNAME"))),
    timeout
  ]);
}

const MAX_CHECKS_PER_BUCKET = 60000;
const CONCURRENCY = 200;

async function filterLive(candidates, cap, label) {
  const pool = candidates.slice(0, MAX_CHECKS_PER_BUCKET);
  const live = [];
  let checked = 0;
  let next = 0;

  async function worker() {
    while (next < pool.length && live.length < cap) {
      const domain = pool[next++];
      checked++;
      if (await isLive(domain)) live.push(domain);
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  console.log(`${label}: ${live.length} live of ${checked} checked (${candidates.length} candidates)`);
  return live.slice(0, cap).sort();
}

const out = {
  updated: new Date().toISOString().slice(0, 10),
  sources: FEEDS.map((f) => f.name),
  malware: await filterLive([...malware], MAX_MALWARE, "malware liveness"),
  phishing: await filterLive([...phishing], MAX_PHISHING, "phishing liveness")
};

const dest = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "remote", "threat-domains.json");
await writeFile(dest, JSON.stringify(out, null, 1) + "\n");
console.log(`Wrote ${out.malware.length} malware + ${out.phishing.length} phishing domains to remote/threat-domains.json`);
