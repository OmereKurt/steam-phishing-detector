"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const rule = require("../src/detection-rule.js");
const scoring = require("../src/scoring.js");
const { loadCorpus } = require("./helpers/corpus.js");

const DET = path.join(__dirname, "..", "detections");
const read = rel => fs.readFileSync(path.join(DET, rel), "utf8");

// ---------------------------------------------------------------------------
test("detection rule logic", async t => {
  await t.test("flags a materialised lookalike host", () => {
    assert.strictEqual(rule.evaluate({ host: "steamcomunity.com", uri: "/login" }), "lookalike_domain");
  });

  await t.test("flags an official domain embedded in someone else's hostname", () => {
    assert.strictEqual(
      rule.evaluate({ host: "steamcommunity.com.trade-skins.tk", uri: "/" }),
      "embedded_official_host"
    );
  });

  await t.test("flags an official brand label carried by another registrable domain", () => {
    assert.strictEqual(
      rule.evaluate({ host: "steamcommunity-login.tk", uri: "/" }),
      "embedded_official_label"
    );
  });

  await t.test("does NOT flag an official domain that only appears in a path", () => {
    // Deliberate. Measured on the corpus, path embedding adds 2 detections and
    // 6 false positives: archives, URL scanners and translators all carry a
    // Steam domain in a path legitimately. The extension suppresses those with
    // a credential-field check that no proxy log can reproduce.
    assert.strictEqual(rule.evaluate({ host: "web.archive.org", uri: "/web/2024/https://steamcommunity.com/" }), null);
    assert.strictEqual(rule.evaluate({ host: "www.virustotal.com", uri: "/gui/domain/steamcommunity.com" }), null);
  });

  await t.test("official Steam hosts and their subdomains never fire", () => {
    for (const host of ["steamcommunity.com", "store.steampowered.com", "cdn.steamstatic.com"]) {
      assert.strictEqual(rule.evaluate({ host, uri: "/login" }), null, host);
    }
  });

  await t.test("unrelated traffic does not fire", () => {
    for (const host of ["example.com", "github.com", "en.wikipedia.org"]) {
      assert.strictEqual(rule.evaluate({ host, uri: "/login" }), null, host);
    }
  });

  await t.test("IDN lookalikes are matched in their on-the-wire xn-- form", () => {
    // A proxy logs the punycode label, never the Unicode the victim saw, so the
    // rule has to carry the encoded form or it never matches in production.
    const wire = new URL("https://stеampowered.com/").hostname;
    assert.ok(wire.startsWith("xn--"), "expected an xn-- label, got " + wire);
    assert.strictEqual(rule.evaluate({ host: wire, uri: "/" }), "lookalike_domain");
  });

  await t.test("every materialised host is one the scorer would also warn on", () => {
    // The rule must never be broader than the extension. If this fails, the
    // generator is publishing a domain the product itself would stay quiet on.
    for (const host of rule.LOOKALIKES.keys()) {
      const score = scoring.score("https://" + host + "/", {}).score;
      assert.ok(score >= rule.WARN, host + " is in the rule but scores " + score);
    }
  });
});

// ---------------------------------------------------------------------------
test("generated artefacts", async t => {
  await t.test("every dialect carries the same official-domain allowlist", () => {
    for (const rel of ["steam-phishing-domain.sigma.yml", "splunk/steam-phishing-domain.spl",
                       "sentinel/steam-phishing-domain.kql", "cortex-xsiam/steam-phishing-domain.xql"]) {
      const text = read(rel);
      for (const domain of scoring.OFFICIAL_DOMAINS) {
        assert.ok(text.includes(domain), rel + " is missing " + domain);
      }
    }
  });

  await t.test("the lookup carries exactly the materialised set", () => {
    const lines = read("lookups/steam-lookalike-domains.csv").trim().split("\n");
    assert.strictEqual(lines[0], "host,signal");
    assert.strictEqual(lines.length - 1, rule.LOOKALIKES.size);
    for (const line of lines.slice(1)) {
      const [host, signal] = line.split(",");
      assert.ok(rule.LOOKALIKES.has(host), host + " is in the lookup but not materialised");
      assert.strictEqual(rule.LOOKALIKES.get(host), signal);
    }
  });

  await t.test("Sigma rules are tagged with the technique they detect", () => {
    const high = read("steam-phishing-domain.sigma.yml");
    assert.ok(high.includes("attack.t1566.002"), "expected T1566.002");
    assert.ok(high.includes("logsource:"));
    assert.ok(high.includes("condition:"));
  });

  await t.test("regex escaping is single-backslash in every dialect", () => {
    // A doubled backslash means "escaped backslash, then any character" in all
    // three query languages -- silently the wrong pattern, and it still parses.
    for (const rel of ["splunk/steam-phishing-domain.spl", "sentinel/steam-phishing-domain.kql",
                       "cortex-xsiam/steam-phishing-domain.xql"]) {
      assert.ok(!/\\\\\./.test(read(rel)), rel + " contains a double-escaped dot");
    }
  });

  await t.test("no dialect inlines the lookalike list", () => {
    // The list is data and belongs in a lookup. Inlining 600+ literals produces
    // a query nobody can review and that has to be re-pasted on every rebuild.
    for (const rel of ["splunk/steam-phishing-domain.spl", "sentinel/steam-phishing-domain.kql",
                       "cortex-xsiam/steam-phishing-domain.xql"]) {
      const text = read(rel);
      const inlined = [...rule.LOOKALIKES.keys()].filter(h => text.includes(h)).length;
      assert.ok(inlined < 10, rel + " inlines " + inlined + " lookalike hosts; use the lookup");
    }
  });
});

// ---------------------------------------------------------------------------
test("coverage against the labelled corpus", async t => {
  const c = rule.coverageAgainstCorpus(loadCorpus());

  await t.test("every corpus URL parsed; none silently skipped", () => {
    // A dropped entry inflates every ratio below it, which is how a coverage
    // number quietly becomes a lie. Corpus URLs are defanged on disk.
    assert.deepStrictEqual(c.unparseable, []);
  });

  await t.test("the rule never fires where the scorer would not", () => {
    assert.strictEqual(c.ruleOnly, 0,
      "rule fired on " + c.ruleOnly + " URLs the scorer keeps quiet on");
  });

  await t.test("the rule catches a documented share of what the scorer catches", () => {
    // A floor, not an equality. The SIEM rule cannot see page signals and
    // cannot run edit distance, so it is expected to catch less. Pinning the
    // ratio means a regression in the generator surfaces as a failing test
    // rather than as quieter dashboards. Measured at 27/35 on 2026-08-24.
    assert.ok(c.rule > 0, "rule caught nothing");
    assert.ok(c.rule / c.scorer >= 0.75,
      `rule caught ${c.rule}/${c.scorer} of what the scorer catches`);
  });

  await t.test("the rule fires on nothing the corpus labels benign", () => {
    let falsePositives = 0;
    for (const entry of loadCorpus()) {
      if (entry.label === "phishing") continue;
      const parsed = new URL(entry.url);
      if (rule.evaluate({ host: parsed.hostname, uri: parsed.pathname + parsed.search })) {
        falsePositives++;
      }
    }
    assert.strictEqual(falsePositives, 0, falsePositives + " benign URLs fired");
  });
});
