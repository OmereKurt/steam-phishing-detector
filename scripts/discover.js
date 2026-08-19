#!/usr/bin/env node
"use strict";

/**
 * Turns generated typosquats into measured ones.
 *
 * Generates permutations of the Steam brand domains, then asks DNS which of
 * them are actually registered. The distinction matters:
 *
 *   NXDOMAIN  the name does not exist -- nobody registered it
 *   NODATA    the name exists but has no A record -- registered, not hosted
 *   resolved  registered and pointed at a host
 *
 * DNS only. This never connects to any discovered domain, never fetches a page,
 * and never follows a link. Output is defanged.
 *
 *   npm run discover
 */

const dns = require("dns").promises;
const url = require("url");
const fs = require("fs");
const path = require("path");

const permutations = require("../src/permutations.js");
const scoring = require("../src/scoring.js");

const TARGETS = ["steamcommunity.com", "steampowered.com"];
const CONCURRENCY = 20;
const TIMEOUT_MS = 4000;
const OUTPUT = path.join(__dirname, "..", "data", "lookalikes.json");

/** Unicode labels are registered as punycode; resolve what a browser would. */
function toAscii(host) {
  if (!/[^\x00-\x7F]/.test(host)) return host;
  const ascii = url.domainToASCII(host);
  return ascii || null;
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error("timeout"), { code: "ETIMEOUT" })), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function lookup(host) {
  const ascii = toAscii(host);
  if (!ascii) return { status: "invalid" };
  try {
    const addresses = await withTimeout(dns.resolve4(ascii), TIMEOUT_MS);
    return { status: "resolved", addresses: addresses.slice(0, 2) };
  } catch (err) {
    if (err.code === "ENOTFOUND" || err.code === "ENXDOMAIN") return { status: "nxdomain" };
    if (err.code === "ENODATA") {
      // The name exists. Confirm with NS before calling it registered.
      try {
        await withTimeout(dns.resolveNs(ascii), TIMEOUT_MS);
        return { status: "registered-no-a" };
      } catch (nsErr) {
        return { status: "registered-no-a" };
      }
    }
    return { status: "error", code: err.code || "UNKNOWN" };
  }
}

async function mapLimit(items, limit, worker, onProgress) {
  const results = new Array(items.length);
  let next = 0;
  let done = 0;
  async function run() {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
      done++;
      if (onProgress && done % 100 === 0) onProgress(done, items.length);
    }
  }
  await Promise.all(Array.from({ length: limit }, run));
  return results;
}

/** hxxps-style defanging, matching test/corpus.json. */
function defang(host) {
  return host.split(".").join("[.]");
}

async function main() {
  const candidates = [];
  const seen = new Set();

  for (const target of TARGETS) {
    for (const [host, technique] of permutations.generate(target)) {
      // "steam.community.com" asks whether someone else's domain has a steam
      // subdomain, which registration data cannot answer. Excluded here; the
      // shape is still covered by the scorer's tests.
      if (technique === "subdomain-split") continue;
      if (seen.has(host)) continue;
      seen.add(host);
      candidates.push({ host, technique, target });
    }
  }

  console.log(`Generated ${candidates.length} candidates from ${TARGETS.length} Steam domains.`);
  console.log(`Resolving with concurrency ${CONCURRENCY} (DNS only, no connections)...`);

  const started = Date.now();
  const results = await mapLimit(
    candidates,
    CONCURRENCY,
    async candidate => Object.assign({}, candidate, await lookup(candidate.host)),
    (done, total) => process.stdout.write(`  ${done}/${total}\r`)
  );
  // Resolvers drop queries under load. Retry the failures once, more slowly,
  // so the registration rate is not quietly understated by transient SERVFAILs.
  const transient = results.filter(r => r.status === "error");
  if (transient.length) {
    process.stdout.write(`\n  retrying ${transient.length} transient failures...`);
    await mapLimit(transient, 5, async candidate => {
      const retried = await lookup(candidate.host);
      if (retried.status !== "error") Object.assign(candidate, retried);
    });
    const stillFailing = results.filter(r => r.status === "error").length;
    process.stdout.write(` ${transient.length - stillFailing} resolved on retry\n`);
  }

  const elapsed = ((Date.now() - started) / 1000).toFixed(1);

  const registered = results.filter(r => r.status === "resolved" || r.status === "registered-no-a");
  const byStatus = {};
  const byTechnique = {};
  for (const r of results) {
    byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    if (r.status === "resolved" || r.status === "registered-no-a") {
      byTechnique[r.technique] = (byTechnique[r.technique] || 0) + 1;
    }
  }

  // Coverage, with a large asterisk. See the note written into the output.
  const refang = h => h.split("[.]").join(".");
  let covered = 0;
  for (const r of registered) {
    const host = toAscii(r.host) || r.host;
    if (scoring.score("http://" + host + "/").score >= scoring.BANDS.CAUTION) covered++;
  }

  const payload = {
    _readme: [
      "Registered lookalike domains for Steam brands, found by generating typosquat",
      "permutations (src/permutations.js) and resolving them against DNS.",
      "",
      "Hostnames are defanged with [.] and were never connected to -- DNS only.",
      "",
      "REGISTRATION IS NOT MALICE. Some of these are Valve's own defensive",
      "registrations, some are parked or for sale, some are unrelated businesses,",
      "and some are hostile. Nothing here establishes intent, so this set is used",
      "to measure detection COVERAGE, never precision or recall.",
      "",
      "AND COVERAGE HERE IS CLOSE TO CIRCULAR. These candidates were produced by",
      "the same families of transformation the scorer measures -- omission,",
      "transposition, keyboard substitution, homoglyph. A domain generated by",
      "deleting one character is one edit from the original by construction, so",
      "of course an edit-distance check catches it. The coverage figure is a",
      "sanity check that the generator and the scorer agree, NOT a detection",
      "rate, and it must never be quoted as one.",
      "",
      "The finding worth reporting from this file is the registration rate: how",
      "much of the generated lookalike surface someone has actually bought. The",
      "scorer's only independent measurement is the Tranco false-positive",
      "benchmark in data/benchmark.json."
    ],
    generatedAt: new Date().toISOString().slice(0, 10),
    targets: TARGETS,
    candidatesTested: candidates.length,
    registeredCount: registered.length,
    byStatus: byStatus,
    registeredByTechnique: byTechnique,
    flaggedByScorer: covered,
    coverageCaveat: "Near-circular by construction -- see _readme. Not a detection rate.",
    registered: registered
      .map(r => ({
        host: defang(r.host),
        punycode: toAscii(r.host) !== r.host ? defang(toAscii(r.host)) : undefined,
        technique: r.technique,
        target: r.target,
        status: r.status
      }))
      .sort((a, b) => a.host.localeCompare(b.host))
  };

  fs.writeFileSync(OUTPUT, JSON.stringify(payload, null, 2) + "\n");

  console.log(`\nResolved ${candidates.length} names in ${elapsed}s.\n`);
  console.log(`  Registered:      ${registered.length}  (${((registered.length / candidates.length) * 100).toFixed(1)}%)`);
  for (const [status, count] of Object.entries(byStatus).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${status.padEnd(18)} ${count}`);
  }
  console.log(`\n  Registered by technique:`);
  for (const [technique, count] of Object.entries(byTechnique).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${technique.padEnd(18)} ${count}`);
  }
  console.log(`\n  Scorer flags ${covered}/${registered.length} of them at the warn threshold.`);
  console.log(`  NOTE: that is close to circular. These were generated by the same`);
  console.log(`  transformations the scorer measures, so agreement is expected. It is a`);
  console.log(`  sanity check, not a detection rate. The independent measurement is the`);
  console.log(`  Tranco false-positive benchmark.`);
  console.log(`\nWrote ${path.relative(path.join(__dirname, ".."), OUTPUT)}`);
}

main();
