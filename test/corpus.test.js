"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");

const scoring = require("../src/scoring.js");
const { loadCorpus, refang, CORPUS_PATH } = require("./helpers/corpus.js");
const { scoreAll, evaluate } = require("../scripts/evaluate.js");

const entries = loadCorpus();
const scored = scoreAll(entries);

/**
 * Performance floors. These are regression guards, not targets: they sit a
 * little below the numbers the scorer currently achieves, so a change that
 * quietly degrades detection fails CI instead of shipping. Raise them
 * deliberately when the scorer genuinely improves.
 */
const FLOORS = {
  warnPrecision: 0.95,
  warnRecall: 0.85,
  warnFalsePositiveRate: 0.05,
  blockPrecision: 1.0
};

// ---------------------------------------------------------------------------
test("corpus integrity", async t => {
  await t.test("is large enough to say anything", () => {
    assert.ok(entries.length >= 50, "only " + entries.length + " entries");
  });

  await t.test("has both classes well represented", () => {
    const phishing = entries.filter(e => e.label === "phishing").length;
    const benign = entries.length - phishing;
    assert.ok(phishing >= 20, "phishing: " + phishing);
    assert.ok(benign >= 20, "benign: " + benign);
  });

  await t.test("uses only the two known labels", () => {
    for (const e of entries) {
      assert.ok(["phishing", "benign"].includes(e.label), e.defangedUrl + " -> " + e.label);
    }
  });

  await t.test("every url field is fully defanged", () => {
    // Checked against the url values only. Prose in notes and page titles is
    // allowed to name a domain normally; what must never be live is a url.
    const raw = JSON.parse(fs.readFileSync(CORPUS_PATH, "utf8"));
    for (const entry of raw.entries) {
      assert.ok(!/https?:\/\//.test(entry.url), "undefanged scheme: " + entry.url);
      assert.ok(!/\.[a-z]{2,}/i.test(entry.url), "undefanged dot: " + entry.url);
      assert.match(entry.url, /^hxxps?:\/\//, "url does not start with a defanged scheme: " + entry.url);
    }
  });

  await t.test("every entry refangs into a parseable URL", () => {
    for (const e of entries) {
      assert.doesNotThrow(() => new URL(e.url), e.defangedUrl);
    }
  });

  await t.test("has no duplicate URLs", () => {
    const seen = new Set();
    for (const e of entries) {
      assert.ok(!seen.has(e.url), "duplicate: " + e.defangedUrl);
      seen.add(e.url);
    }
  });

  await t.test("round-trips defanging losslessly", () => {
    assert.strictEqual(refang("hxxps://steamcommunity[.]com/"), "https://steamcommunity.com/");
    assert.strictEqual(refang("hxxp://a[.]b[.]tk/x"), "http://a.b.tk/x");
  });

  await t.test("covers every attack category the scorer claims to handle", () => {
    const categories = new Set(entries.map(e => e.category));
    for (const required of ["typosquat", "homoglyph", "punycode", "embedded-domain", "brand-abuse"]) {
      assert.ok(categories.has(required), "missing category: " + required);
    }
  });

  await t.test("includes hard negatives that carry credential fields", () => {
    const hard = entries.filter(
      e => e.label === "benign" && e.pageSignals.hasCredentialField === true
    );
    assert.ok(hard.length >= 10, "only " + hard.length + " benign credential pages");
  });
});

// ---------------------------------------------------------------------------
test("detection performance", async t => {
  const warn = evaluate(scored, scoring.BANDS.CAUTION);
  const block = evaluate(scored, scoring.BANDS.BLOCK);

  await t.test(`precision at the warn threshold is at least ${FLOORS.warnPrecision}`, () => {
    assert.ok(warn.precision >= FLOORS.warnPrecision, "precision " + warn.precision.toFixed(3));
  });

  await t.test(`recall at the warn threshold is at least ${FLOORS.warnRecall}`, () => {
    assert.ok(warn.recall >= FLOORS.warnRecall, "recall " + warn.recall.toFixed(3));
  });

  await t.test(`false positive rate stays at or below ${FLOORS.warnFalsePositiveRate}`, () => {
    assert.ok(warn.fpRate <= FLOORS.warnFalsePositiveRate, "fp rate " + warn.fpRate.toFixed(3));
  });

  await t.test("the block band never fires on a benign URL", () => {
    assert.strictEqual(block.fp, 0);
    assert.ok(block.precision >= FLOORS.blockPrecision);
  });

  await t.test("recall never decreases as the threshold falls", () => {
    let previous = 0;
    for (const threshold of [80, 60, 35, 20]) {
      const r = evaluate(scored, threshold);
      assert.ok(r.recall >= previous, "recall dropped at threshold " + threshold);
      previous = r.recall;
    }
  });
});

// ---------------------------------------------------------------------------
test("per-category behaviour", async t => {
  const byCategory = category => scored.filter(x => x.entry.category === category);

  await t.test("every official Steam URL scores exactly zero", () => {
    for (const { entry, result } of byCategory("official")) {
      assert.strictEqual(result.score, 0, entry.defangedUrl + " scored " + result.score);
      assert.strictEqual(result.reasons[0].id, "official_domain");
    }
  });

  await t.test("no legitimate Steam-adjacent site is warned about", () => {
    for (const { entry, result } of byCategory("steam-adjacent")) {
      assert.ok(result.score < scoring.BANDS.CAUTION, entry.defangedUrl + " scored " + result.score);
    }
  });

  await t.test("no unrelated credential page is warned about", () => {
    for (const { entry, result } of byCategory("unrelated-login")) {
      assert.ok(result.score < scoring.BANDS.CAUTION, entry.defangedUrl + " scored " + result.score);
    }
  });

  await t.test("every typosquat and homoglyph is caught", () => {
    for (const category of ["typosquat", "homoglyph"]) {
      for (const { entry, result } of byCategory(category)) {
        assert.ok(
          result.score >= scoring.BANDS.CAUTION,
          entry.defangedUrl + " scored " + result.score
        );
      }
    }
  });

  await t.test("every embedded-domain phish is at least warned about", () => {
    for (const { entry, result } of byCategory("embedded-domain")) {
      assert.ok(
        result.score >= scoring.BANDS.CAUTION,
        entry.defangedUrl + " scored " + result.score
      );
    }
  });

  await t.test("an official domain inside the hostname always blocks", () => {
    // Domain in the hostname is the strongest shape: the victim reads a real
    // Steam domain in the URL bar. Domain in the path is weaker -- the URL bar
    // still shows the attacker's domain -- so those may land at caution.
    const hostEmbeds = byCategory("embedded-domain").filter(x =>
      x.result.reasons.some(r => r.id === "embedded_official" && /host-embed/.test(r.detail))
    );
    assert.ok(hostEmbeds.length >= 5, "expected several host-embed cases");
    for (const { entry, result } of hostEmbeds) {
      assert.strictEqual(result.verdict, "block", entry.defangedUrl + " scored " + result.score);
    }
  });

  await t.test("brand-abuse lures are the known weak spot, and stay bounded", () => {
    // These carry no lookalike domain at all, so the scorer has little to grip.
    // The test pins how many it misses: if a change fixes one, this fails and
    // the number gets revised down deliberately.
    const missed = byCategory("brand-abuse").filter(
      x => x.result.score < scoring.BANDS.CAUTION
    );
    assert.strictEqual(missed.length, 3, "missed: " + missed.map(x => x.entry.defangedUrl).join(", "));
  });
});
