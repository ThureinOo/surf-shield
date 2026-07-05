#!/usr/bin/env node
// Downloads public filter lists and compiles them into a declarativeNetRequest
// ruleset (rules/generated.json). Run before packaging:
//   node scripts/build-rules.mjs
// Requires Node 18+.

import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

// Ordered by importance; `max` caps how much of the shared budget each list
// may consume. The popup/popunder list gets priority — it's our core mission.
const LISTS = [
  { name: "AdGuard Popups", url: "https://filters.adtidy.org/extension/ublock/filters/19.txt", max: Infinity },
  { name: "EasyPrivacy", url: "https://easylist.to/easylist/easyprivacy.txt", max: 8000 },
  { name: "EasyList", url: "https://easylist.to/easylist/easylist.txt", max: Infinity }
];

// Stay under Chrome's guaranteed static-rule minimum (30k), minus our
// handcrafted ruleset.
const MAX_RULES = 29000;
const MAX_COSMETIC = 15000;

// Generic (domain-less) "##selector" cosmetic rules, plain CSS only —
// extended syntax (:has, ##+js, :style...) needs an engine we don't have.
function parseCosmetic(line) {
  if (!line.startsWith("##")) return null; // domain-specific or not cosmetic
  const sel = line.slice(2).trim();
  if (!sel || sel.length > 250) return null;
  if (sel.includes("(") || sel.includes("/") || sel.includes("{")) return null;
  if (!/^[a-zA-Z0-9 .#*_\-\[\]="'^$~|:>+,]+$/.test(sel)) return null;
  return sel;
}

const TYPE_MAP = {
  script: "script",
  image: "image",
  stylesheet: "stylesheet",
  object: "object",
  xmlhttprequest: "xmlhttprequest",
  subdocument: "sub_frame",
  document: "main_frame",
  popup: "main_frame",
  ping: "ping",
  media: "media",
  font: "font",
  websocket: "websocket",
  other: "other"
};

// Options we can't express in DNR -> drop the whole rule.
const UNSUPPORTED = new Set([
  "csp", "redirect", "redirect-rule", "removeparam", "rewrite", "replace",
  "cookie", "header", "denyallow", "genericblock", "generichide", "elemhide",
  "specifichide", "badfilter", "empty", "mp4", "webrtc", "object-subrequest",
  "jsonprune", "method", "to", "app", "extension", "stealth", "permissions"
]);

function parseLine(line) {
  line = line.trim();
  if (!line || line.startsWith("!") || line.startsWith("[")) return null;
  if (line.includes("##") || line.includes("#@#") || line.includes("#?#") || line.includes("#$#") || line.includes("#%#")) return null;
  if (line.startsWith("@@")) return null; // exceptions: skip (we'd rather overblock ads than underblock)
  if (line.startsWith("/") && line.endsWith("/")) return null; // raw regex: RE2 compat not guaranteed

  let pattern = line;
  let optionsStr = "";
  const dollar = line.lastIndexOf("$");
  // A $ inside a URL path is rare in filters; treat last $ as options separator
  // only if what follows looks like options.
  if (dollar > 0 && /^[a-z~][a-z0-9-~=|.,_*]*$/i.test(line.slice(dollar + 1))) {
    pattern = line.slice(0, dollar);
    optionsStr = line.slice(dollar + 1);
  }
  if (!pattern || pattern.length < 3) return null;
  // DNR urlFilter shares ABP tokens (||, ^, *, |) but nothing else fancy.
  if (/[()\[\]{}\\+?]/.test(pattern)) return null;

  const condition = {};
  const include = [];
  const exclude = [];
  let priority = 1;

  if (optionsStr) {
    for (const raw of optionsStr.split(",")) {
      const opt = raw.trim();
      if (!opt) continue;
      const neg = opt.startsWith("~");
      const [key, value] = (neg ? opt.slice(1) : opt).split("=");

      if (UNSUPPORTED.has(key)) return null;
      if (key === "important") { priority = 2; continue; }
      if (key === "match-case") { condition.isUrlFilterCaseSensitive = true; continue; }
      if (key === "third-party" || key === "3p") {
        condition.domainType = neg ? "firstParty" : "thirdParty";
        continue;
      }
      if (key === "first-party" || key === "1p") {
        condition.domainType = neg ? "thirdParty" : "firstParty";
        continue;
      }
      if (key === "domain" || key === "from") {
        if (!value) return null;
        const domains = value.split("|");
        if (domains.some((d) => d.startsWith("~")) && domains.some((d) => !d.startsWith("~"))) return null; // mixed: skip
        const hadPositive = domains.some((d) => !d.startsWith("~"));
        for (const d of domains) {
          // AdGuard wildcard-TLD entries (gmx.*) are not valid DNR domains.
          if (d.includes("*")) continue;
          if (d.startsWith("~")) condition.excludedInitiatorDomains = (condition.excludedInitiatorDomains || []).concat(d.slice(1));
          else condition.initiatorDomains = (condition.initiatorDomains || []).concat(d);
        }
        // All positive domains were wildcards: dropping them would turn a
        // site-scoped rule into a global one — skip the rule instead.
        if (hadPositive && !condition.initiatorDomains) return null;
        continue;
      }
      if (key in TYPE_MAP) {
        (neg ? exclude : include).push(TYPE_MAP[key]);
        continue;
      }
      return null; // unknown option: skip rule rather than misapply it
    }
  }

  if (include.length) condition.resourceTypes = [...new Set(include)];
  else if (exclude.length) condition.excludedResourceTypes = [...new Set(exclude)];
  else condition.excludedResourceTypes = ["main_frame"]; // ABP default: network requests, not page loads

  condition.urlFilter = pattern;
  return { priority, condition };
}

async function main() {
  const seen = new Set();
  const rules = [];
  const cosmetics = new Set();
  let id = 1;

  for (const list of LISTS) {
    let text;
    try {
      const res = await fetch(list.url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      text = await res.text();
    } catch (err) {
      console.error(`FAILED to fetch ${list.name}: ${err.message}`);
      continue;
    }

    let added = 0;
    for (const line of text.split("\n")) {
      if (cosmetics.size < MAX_COSMETIC) {
        const sel = parseCosmetic(line.trim());
        if (sel) cosmetics.add(sel);
      }
      if (rules.length >= MAX_RULES || added >= list.max) continue;
      const parsed = parseLine(line);
      if (!parsed) continue;
      const key = JSON.stringify(parsed.condition);
      if (seen.has(key)) continue;
      seen.add(key);
      rules.push({ id: id++, priority: parsed.priority, action: { type: "block" }, condition: parsed.condition });
      added++;
    }
    console.log(`${list.name}: +${added} rules (total ${rules.length})`);
  }

  if (rules.length === 0) {
    console.error("No rules generated — refusing to overwrite ruleset.");
    process.exit(1);
  }

  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
  const out = path.join(root, "rules", "generated.json");
  await writeFile(out, JSON.stringify(rules));
  console.log(`Wrote ${rules.length} rules -> ${out}`);

  const cosmeticOut = path.join(root, "rules", "cosmetic.json");
  await writeFile(cosmeticOut, JSON.stringify([...cosmetics]));
  console.log(`Wrote ${cosmetics.size} cosmetic selectors -> ${cosmeticOut}`);
}

main();
