#!/usr/bin/env node
"use strict";

/**
 * Runs the scorer across the labelled corpus and reports detection performance.
 *
 *   npm run eval            summary table
 *   npm run eval -- --misses   also list every misclassified URL
 *
 * A phishing URL counts as detected when its score reaches the threshold, i.e.
 * when the extension shows the user something. Results are reported at several
 * thresholds rather than one, because the honest question is not "is it good"
 * but "what does it cost you to catch more".
 */

const scoring = require("../src/scoring.js");
const { loadCorpus } = require("../test/helpers/corpus.js");

const THRESHOLDS = [20, scoring.BANDS.CAUTION, scoring.BANDS.BLOCK, 80];

function scoreAll(entries) {
  return entries.map(entry => ({
    entry,
    result: scoring.score(entry.url, entry.pageSignals)
  }));
}

/** Confusion matrix and derived metrics at one threshold. */
function evaluate(scored, threshold) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const { entry, result } of scored) {
    const flagged = result.score >= threshold;
    const malicious = entry.label === "phishing";
    if (malicious && flagged) tp++;
    else if (malicious) fn++;
    else if (flagged) fp++;
    else tn++;
  }
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  const fpRate = fp + tn === 0 ? 0 : fp / (fp + tn);
  return { threshold, tp, fp, tn, fn, precision, recall, f1, fpRate };
}

function pct(n) {
  return (n * 100).toFixed(1) + "%";
}

function sweep(scored, thresholds) {
  return (thresholds || THRESHOLDS).map(t => evaluate(scored, t));
}

function bandLabel(threshold) {
  if (threshold === scoring.BANDS.BLOCK) return "block banner";
  if (threshold === scoring.BANDS.CAUTION) return "any warning";
  return "";
}

function renderTable(rows) {
  const header = "| Threshold | TP | FP | TN | FN | Precision | Recall | F1 | FP rate |";
  const divider = "|---:|---:|---:|---:|---:|---:|---:|---:|---:|";
  const body = rows.map(r => {
    const label = bandLabel(r.threshold);
    const name = label ? `**${r.threshold}** (${label})` : String(r.threshold);
    return `| ${name} | ${r.tp} | ${r.fp} | ${r.tn} | ${r.fn} | ${pct(r.precision)} | ${pct(r.recall)} | ${r.f1.toFixed(3)} | ${pct(r.fpRate)} |`;
  });
  return [header, divider].concat(body).join("\n");
}

function main() {
  const showMisses = process.argv.includes("--misses");
  const entries = loadCorpus();
  const scored = scoreAll(entries);
  const rows = sweep(scored);

  const benign = entries.filter(e => e.label === "benign").length;
  const phishing = entries.length - benign;

  const out = [];
  out.push(`Corpus: ${entries.length} labelled URLs (${phishing} phishing, ${benign} benign)`);
  out.push("");
  out.push(renderTable(rows));
  out.push("");

  const primary = rows.find(r => r.threshold === scoring.BANDS.CAUTION);
  out.push(
    `At the warn threshold (score >= ${scoring.BANDS.CAUTION}): ` +
    `${pct(primary.recall)} detection at ${pct(primary.fpRate)} false positives.`
  );

  if (showMisses) {
    out.push("");
    out.push("Misclassified at the warn threshold:");
    for (const { entry, result } of scored) {
      const flagged = result.score >= scoring.BANDS.CAUTION;
      const malicious = entry.label === "phishing";
      if (flagged === malicious) continue;
      const kind = malicious ? "FN" : "FP";
      out.push(`  ${kind}  score ${String(result.score).padStart(3)}  ${entry.defangedUrl}`);
      for (const r of result.reasons) {
        out.push(`         - ${r.id} (+${r.weight}) ${r.detail}`);
      }
    }
  }

  const report = out.join("\n");
  console.log(report);

  if (process.env.GITHUB_STEP_SUMMARY) {
    require("fs").appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      "## Detection performance\n\n" + report.replace(/^Corpus:/, "**Corpus:**") + "\n"
    );
  }
}

if (require.main === module) main();

module.exports = { scoreAll, evaluate, sweep, renderTable, THRESHOLDS };
