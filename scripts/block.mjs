#!/usr/bin/env node
// Add domains to the shared blocklist (remote/blocklist.json).
// All installs pick the change up within 24h of pushing.
//
//   node scripts/block.mjs evil.com https://other.bad/page?x=1
//   node scripts/block.mjs --phishing fake-login.top     # warning page instead of silent block
//   node scripts/block.mjs --push evil.com               # also git commit + push
//
// Accepts bare domains or full URLs (hostname is extracted, www. stripped).

import { readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const PROTECTED_DOMAINS = ["google.com", "youtube.com", "facebook.com", "github.com", "microsoft.com", "apple.com", "amazon.com", "wikipedia.org", "cloudflare.com"];
const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(\.(?!-)[a-z0-9-]{1,63})+$/;

const args = process.argv.slice(2);
const phishing = args.includes("--phishing");
const push = args.includes("--push");
const inputs = args.filter((a) => !a.startsWith("--"));

if (inputs.length === 0) {
  console.error("Usage: node scripts/block.mjs [--phishing] [--push] <domain-or-url> ...");
  process.exit(1);
}

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const listPath = path.join(root, "remote", "blocklist.json");
const list = JSON.parse(await readFile(listPath, "utf8"));

const bucket = phishing ? "phishingDomains" : "domains";
const added = [];

for (const input of inputs) {
  let host;
  try {
    host = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`).hostname;
  } catch {
    console.error(`skip (unparseable): ${input}`);
    continue;
  }
  host = host.toLowerCase().replace(/^www\./, "");
  if (!DOMAIN_RE.test(host)) {
    console.error(`skip (not a valid domain): ${host}`);
    continue;
  }
  if (PROTECTED_DOMAINS.some((d) => host === d || host.endsWith("." + d))) {
    console.error(`skip (protected domain): ${host}`);
    continue;
  }
  if (list.domains.includes(host) || list.phishingDomains.includes(host)) {
    console.log(`already listed: ${host}`);
    continue;
  }
  list[bucket].push(host);
  added.push(host);
  console.log(`+ ${host} → ${bucket}`);
}

if (added.length === 0) {
  console.log("Nothing to add.");
  process.exit(0);
}

list.version += 1;
list.updated = new Date().toISOString().slice(0, 10);
await writeFile(listPath, JSON.stringify(list, null, 2) + "\n");
console.log(`blocklist.json → v${list.version} (${added.length} added)`);

if (push) {
  const run = (cmd, a) => execFileSync(cmd, a, { cwd: root, stdio: "inherit" });
  run("git", ["add", "remote/blocklist.json"]);
  run("git", ["commit", "-m", `blocklist: add ${added.join(", ")}`]);
  run("git", ["push"]);
} else {
  console.log("Not pushed — run with --push, or commit remote/blocklist.json yourself.");
}
