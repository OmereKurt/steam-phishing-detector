#!/usr/bin/env node
"use strict";

/**
 * Large-scale false-positive benchmark.
 *
 * Scores every domain in a Tranco top-sites list. Tranco ranks real domains by
 * traffic, so anything the scorer flags here is either a genuine brand
 * impersonation that made the list, or a false positive. Either way it is a far
 * harder negative set than any hand-written one, and it is not something the
 * scorer was tuned against.
 *
 *   npm run benchmark -- /path/to/top-1m.csv
 *
 * Domains are scored bare, with no page signals, so only the domain-based
 * signals can fire. That is the correct test for a domain analyser.
 */

const fs = require("fs");
const path = require("path");
const readline = require("readline");

const scoring = require("../src/scoring.js");

const OUTPUT = path.join(__dirname, "..", "data", "benchmark.json");

async function main() {
  const listPath = process.argv[2] || process.env.TRANCO_CSV;
  if (!listPath || !fs.existsSync(listPath)) {
    console.error("Usage: npm run benchmark -- /path/to/top-1m.csv");
    console.error("Get one from https://tranco-list.eu/");
    process.exit(1);
  }

  const stream = readline.createInterface({
    input: fs.createReadStream(listPath),
    crlfDelay: Infinity
  });

  let scored = 0;
  const flagged = [];
  const started = Date.now();

  for await (const line of stream) {
    const comma = line.indexOf(",");
    const domain = (comma === -1 ? line : line.slice(comma + 1)).trim();
    if (!domain) continue;
    const rank = comma === -1 ? scored + 1 : Number(line.slice(0, comma));

    const result = scoring.score("http://" + domain + "/");
    scored++;
    if (result.score >= scoring.BANDS.CAUTION) {
      flagged.push({
        rank: rank,
        domain: domain,
        score: result.score,
        verdict: result.verdict,
        reasons: result.reasons.filter(r => r.weight > 0).map(r => r.id)
      });
    }
  }

  const elapsed = ((Date.now() - started) / 1000).toFixed(1);
  const blocked = flagged.filter(f => f.verdict === "block");
  const warnRate = flagged.length / scored;
  const blockRate = blocked.length / scored;

  const payload = {
    _readme: [
      "False-positive benchmark against a Tranco top-sites list.",
      "Every flagged domain is listed below for inspection -- nothing is hidden",
      "behind a summary statistic. Domains are recorded as ranked, not defanged,",
      "because these are legitimate popular sites."
    ],
    generatedAt: new Date().toISOString().slice(0, 10),
    listFile: path.basename(listPath),
    domainsScored: scored,
    flaggedAtWarn: flagged.length,
    flaggedAtBlock: blocked.length,
    falsePositiveRateWarn: Number(warnRate.toFixed(8)),
    falsePositiveRateBlock: Number(blockRate.toFixed(8)),
    flagged: flagged.sort((a, b) => a.rank - b.rank)
  };
  fs.writeFileSync(OUTPUT, JSON.stringify(payload, null, 2) + "\n");

  console.log(`Scored ${scored.toLocaleString()} real domains in ${elapsed}s.\n`);
  console.log(`  Flagged at warn  (>=${scoring.BANDS.CAUTION}): ${flagged.length}  (${(warnRate * 100).toFixed(4)}%)`);
  console.log(`  Flagged at block (>=${scoring.BANDS.BLOCK}): ${blocked.length}  (${(blockRate * 100).toFixed(4)}%)`);
  console.log(`\n  1 in ${Math.round(1 / (warnRate || 1)).toLocaleString()} real domains triggers a warning.\n`);
  console.log("  Every flagged domain, by rank:");
  for (const f of flagged.slice(0, 60)) {
    console.log(`    #${String(f.rank).padStart(7)}  ${String(f.score).padStart(3)}  ${f.verdict.padEnd(8)} ${f.domain}  [${f.reasons.join(", ")}]`);
  }
  if (flagged.length > 60) console.log(`    ... and ${flagged.length - 60} more in data/benchmark.json`);
}

main();
