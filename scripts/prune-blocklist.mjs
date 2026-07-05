#!/usr/bin/env node
// Liveness-prunes remote/blocklist.json (curated + community-approved domains).
// A domain is only removed after being dead for GRACE_DAYS consecutive daily
// checks — ad/popunder infrastructure goes dormant and comes back, so a single
// NXDOMAIN is not enough. State lives in remote/dead-tracker.json.
//   node scripts/prune-blocklist.mjs
// Requires Node 18+.

import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { Resolver } from "node:dns/promises";

const GRACE_DAYS = 7;

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const blocklistPath = path.join(root, "remote", "blocklist.json");
const trackerPath = path.join(root, "remote", "dead-tracker.json");

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

const list = JSON.parse(await readFile(blocklistPath, "utf8"));
let tracker = {};
try {
  tracker = JSON.parse(await readFile(trackerPath, "utf8"));
} catch {}

const today = new Date().toISOString().slice(0, 10);
const msPerDay = 86400000;
let removedCount = 0;

for (const bucket of ["domains", "phishingDomains"]) {
  const kept = [];
  for (const domain of list[bucket]) {
    if (await isLive(domain)) {
      delete tracker[domain];
      kept.push(domain);
      continue;
    }
    if (!tracker[domain]) tracker[domain] = today;
    const deadDays = Math.floor((Date.parse(today) - Date.parse(tracker[domain])) / msPerDay);
    if (deadDays >= GRACE_DAYS) {
      console.log(`removing ${domain} (${bucket}): dead since ${tracker[domain]}`);
      delete tracker[domain];
      removedCount++;
    } else {
      console.log(`${domain} (${bucket}): dead ${deadDays}/${GRACE_DAYS} days — keeping for now`);
      kept.push(domain);
    }
  }
  list[bucket] = kept;
}

// Drop tracker entries for domains no longer in the list at all.
const all = new Set([...list.domains, ...list.phishingDomains]);
for (const d of Object.keys(tracker)) if (!all.has(d)) delete tracker[d];

if (removedCount > 0) {
  list.version += 1;
  list.updated = today;
  await writeFile(blocklistPath, JSON.stringify(list, null, 2) + "\n");
  console.log(`Removed ${removedCount} dead domain(s); blocklist now v${list.version}`);
} else {
  console.log("No removals");
}
await writeFile(trackerPath, JSON.stringify(tracker, null, 2) + "\n");
