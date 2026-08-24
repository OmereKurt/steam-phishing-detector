#!/usr/bin/env node
"use strict";

/**
 * Evaluation against live phishing feeds.
 *
 * The labelled corpus in test/corpus.json is hand-written: real attack shapes,
 * invented hostnames. It measures whether the scorer catches the shapes its
 * author thought of. This script measures it against hostnames attackers
 * actually registered, which is a different and much less flattering question.
 *
 *   npm run live-eval -- /path/to/online-valid.csv [openphish-feed.txt]
 *
 * PhishTank's CSV carries a `target` column naming the impersonated brand, so
 * it supports two measurements that the Tranco benchmark cannot:
 *
 *   recall      -- of the entries PhishTank labels Steam, how many fire?
 *   specificity -- across every verified-online phish, how often does a
 *                  Steam-specific scorer fire on phishing aimed at someone
 *                  else? Real phishing infrastructure is a far more
 *                  adversarial negative set than Tranco's legitimate domains.
 *
 * Neither feed is vendored, for the same reason the Tranco list is not: they
 * are rebuilt continuously, and shipping the command rather than the number is
 * the point. Get them from:
 *
 *   https://data.phishtank.com/data/online-valid.csv
 *   https://openphish.com/feed.txt
 *
 * NOTHING HERE FETCHES A PHISHING URL. Every input is treated as a string and
 * scored offline. The scorer is a pure function of a URL and a page-signal
 * object; this passes an empty object, so the credential gate reads "unknown"
 * and applies a multiplier of 1.0. That is the scorer's most generous setting,
 * which makes every count below an upper bound on how often it fires.
 */

const fs = require("fs");
const path = require("path");

const scoring = require("../src/scoring.js");

const OUTPUT = path.join(__dirname, "..", "data", "live-eval.json");
const WARN = 35;
const BLOCK = 60;

/** Minimal RFC4180-ish splitter: enough for these feeds, no dependency. */
function splitCsvLine(line) {
  const out = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") { out.push(cur); cur = ""; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

function scoreOf(url) {
  try {
    return scoring.score(url, {});
  } catch (err) {
    return null;
  }
}

/** Defang for terminal and JSON output. These are live hostile URLs. */
function defang(url) {
  return String(url).replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}

function main() {
  const csvPath = process.argv[2] || process.env.PHISHTANK_CSV;
  const feedPath = process.argv[3] || process.env.OPENPHISH_FEED;

  if (!csvPath || !fs.existsSync(csvPath)) {
    console.error("Usage: npm run live-eval -- /path/to/online-valid.csv [openphish-feed.txt]");
    console.error("Get one from https://data.phishtank.com/data/online-valid.csv");
    process.exit(1);
  }

  const lines = fs.readFileSync(csvPath, "utf8").split("\n");
  const header = splitCsvLine(lines[0]);
  const iUrl = header.indexOf("url");
  const iTarget = header.indexOf("target");
  if (iUrl === -1 || iTarget === -1) {
    console.error("Expected `url` and `target` columns; is this a PhishTank online-valid.csv?");
    process.exit(1);
  }

  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    const f = splitCsvLine(lines[i]);
    if (f.length <= iTarget) continue;
    rows.push({ url: f[iUrl], target: (f[iTarget] || "").trim() });
  }

  // ---- recall on the entries PhishTank labels Steam -------------------------
  const steam = rows.filter(r => r.target.toLowerCase() === "steam");
  const steamResults = [];
  let steamWarned = 0;
  for (const r of steam) {
    const s = scoreOf(r.url);
    if (!s) continue;
    if (s.score >= WARN) steamWarned++;
    steamResults.push({
      url: defang(r.url),
      score: s.score,
      verdict: s.verdict,
      signals: s.reasons.map(x => x.signal || x.id || String(x))
    });
  }

  // ---- specificity across every verified-online phish -----------------------
  let scored = 0;
  let warned = 0;
  let blocked = 0;
  const firedElsewhere = [];
  for (const r of rows) {
    const s = scoreOf(r.url);
    if (!s) continue;
    scored++;
    if (s.score < WARN) continue;
    warned++;
    if (s.score >= BLOCK) blocked++;
    if (r.target.toLowerCase() !== "steam") {
      firedElsewhere.push({ url: defang(r.url), target: r.target, score: s.score });
    }
  }

  console.log(`\nPhishTank verified-online: ${scored.toLocaleString()} URLs, ${steam.length} labelled Steam.\n`);

  console.log(`Recall on target="Steam" (${steamResults.length} entries)`);
  for (const r of steamResults) {
    console.log(`  ${String(r.score).padStart(3)} ${r.verdict.padEnd(8)} ${r.url.slice(0, 74)}`);
  }
  console.log(`\n  warned on ${steamWarned}/${steamResults.length}`);

  console.log(`\nSpecificity across all ${scored.toLocaleString()} phishing URLs`);
  console.log(`  warned  (>= ${WARN}): ${warned}  (${(warned / scored * 100).toFixed(4)}%)`);
  console.log(`  blocked (>= ${BLOCK}): ${blocked}`);
  console.log(`  fired on phishing not labelled Steam: ${firedElsewhere.length}`);
  for (const f of firedElsewhere) {
    console.log(`    ${String(f.score).padStart(3)} target=${(f.target || "-").padEnd(12)} ${f.url.slice(0, 60)}`);
  }

  // ---- OpenPhish, if supplied ----------------------------------------------
  let openphish = null;
  if (feedPath && fs.existsSync(feedPath)) {
    const urls = fs.readFileSync(feedPath, "utf8").split("\n").filter(l => l.startsWith("http"));
    const hits = [];
    for (const u of urls) {
      const s = scoreOf(u);
      if (s && s.score >= WARN) hits.push({ url: defang(u), score: s.score });
    }
    openphish = { scored: urls.length, warned: hits.length, hits };
    console.log(`\nOpenPhish community feed: ${urls.length} URLs, ${hits.length} warned.`);
    for (const h of hits) console.log(`    ${String(h.score).padStart(3)} ${h.url.slice(0, 70)}`);
  }

  const report = {
    generated: new Date().toISOString(),
    note: "URLs are defanged. Nothing in this pipeline fetches them.",
    phishtank: {
      scored,
      steamLabelled: steamResults.length,
      steamWarned,
      warned,
      blocked,
      firedOnNonSteam: firedElsewhere,
      steamResults
    },
    openphish
  };
  fs.writeFileSync(OUTPUT, JSON.stringify(report, null, 2) + "\n");
  console.log(`\nWrote ${path.relative(process.cwd(), OUTPUT)}`);
}

main();
