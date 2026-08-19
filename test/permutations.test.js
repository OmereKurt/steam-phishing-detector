"use strict";

const test = require("node:test");
const assert = require("node:assert");
const url = require("node:url");

const p = require("../src/permutations.js");
const scoring = require("../src/scoring.js");

const CANDIDATES = p.generate("steamcommunity.com");
const HOSTS = new Set(CANDIDATES.keys());

function techniqueOf(host) {
  return CANDIDATES.get(host);
}

// ---------------------------------------------------------------------------
test("domain splitting", async t => {
  await t.test("separates label from suffix", () => {
    assert.deepStrictEqual(p.splitDomain("steamcommunity.com"), { label: "steamcommunity", tld: "com" });
    assert.deepStrictEqual(p.splitDomain("example.co.uk"), { label: "example", tld: "co.uk" });
  });
});

// ---------------------------------------------------------------------------
test("techniques produce the shapes they claim", async t => {
  await t.test("omission drops exactly one character", () => {
    for (const host of p.techniques.omission("steam")) {
      assert.strictEqual(host.length, 4, host);
    }
    assert.ok(p.techniques.omission("steam").includes("stea"));
  });

  await t.test("transposition swaps an adjacent pair", () => {
    const out = p.techniques.transposition("steam");
    assert.ok(out.includes("tseam"), "expected tseam");
    assert.ok(out.includes("setam"), "expected setam");
    for (const host of out) assert.strictEqual(host.length, 5, host);
  });

  await t.test("transposition skips doubled letters, which swap to themselves", () => {
    assert.ok(!p.techniques.transposition("aab").includes("aab"));
  });

  await t.test("replacement uses physically adjacent keys only", () => {
    for (const host of p.techniques.replacement("st")) {
      const changed = [...host].findIndex((c, i) => c !== "st"[i]);
      const original = "st"[changed];
      assert.ok(p.KEYBOARD[original].includes(host[changed]), host);
    }
  });

  await t.test("bitsquatting flips one bit and stays a legal domain label", () => {
    for (const host of p.techniques.bitsquatting("steam")) {
      assert.match(host, /^[a-z0-9-]+$/, host);
      const diff = [...host].filter((c, i) => c !== "steam"[i]).length;
      assert.strictEqual(diff, 1, host);
    }
  });

  await t.test("ascii homoglyphs cover the classic substitutions", () => {
    const out = p.techniques["homoglyph-ascii"]("steamcommunity");
    assert.ok(out.includes("steamcommunlty"), "l for i");
    assert.ok(out.includes("5teamcommunity"), "5 for s");
    assert.ok(p.techniques["homoglyph-ascii"]("steampowered").includes("stearnpowered"), "rn for m");
  });

  await t.test("unicode homoglyphs punycode into valid hostnames", () => {
    const out = p.techniques["homoglyph-unicode"]("steamcommunity");
    assert.ok(out.length > 0);
    for (const label of out) {
      const ascii = url.domainToASCII(label + ".com");
      assert.ok(ascii && ascii.startsWith("xn--"), label + " -> " + ascii);
      assert.doesNotThrow(() => new URL("http://" + ascii + "/"));
    }
  });

  await t.test("hyphenation inserts a single hyphen", () => {
    assert.ok(p.techniques.hyphenation("steamcommunity").includes("steam-community"));
  });

  await t.test("combosquat attaches attacker vocabulary both ways", () => {
    const out = p.techniques.combosquat("steamcommunity");
    assert.ok(out.includes("steamcommunity-login"));
    assert.ok(out.includes("loginsteamcommunity"));
  });

  await t.test("combosquat skips words the brand already contains", () => {
    assert.ok(!p.techniques.combosquat("steamcommunity").some(h => h.includes("communitycommunity")));
  });
});

// ---------------------------------------------------------------------------
test("generated candidate set", async t => {
  await t.test("is substantial", () => {
    assert.ok(HOSTS.size > 300, "only " + HOSTS.size + " candidates");
  });

  await t.test("never contains the original domain", () => {
    assert.ok(!HOSTS.has("steamcommunity.com"));
  });

  await t.test("produces no malformed labels", () => {
    for (const host of HOSTS) {
      const label = host.slice(0, host.indexOf("."));
      assert.ok(!label.startsWith("-") && !label.endsWith("-"), host);
      assert.ok(label.length > 0, host);
    }
  });

  await t.test("is deterministic", () => {
    assert.deepStrictEqual([...p.generate("steamcommunity.com").keys()].sort(), [...HOSTS].sort());
  });

  await t.test("tags every candidate with the technique that made it", () => {
    for (const [host, technique] of CANDIDATES) {
      assert.strictEqual(typeof technique, "string", host);
      assert.ok(technique.length > 0, host);
    }
  });

  await t.test("rediscovers the typosquats written by hand in the corpus", () => {
    // These were invented for test/corpus.json before the generator existed.
    // The generator finding them independently is a check on both.
    for (const host of ["steamcommnuity.com", "steamcomunity.com", "steamcommunlty.com", "steamcommunity.co"]) {
      assert.ok(HOSTS.has(host), "generator did not produce " + host + " (" + techniqueOf(host) + ")");
    }
  });

  await t.test("swaps the TLD while keeping the brand intact", () => {
    assert.ok(HOSTS.has("steamcommunity.net"));
    assert.ok(HOSTS.has("steamcommunity.tk"));
  });
});

// ---------------------------------------------------------------------------
test("generator and scorer agree", async t => {
  await t.test("single-edit permutations land within the scorer's distance window", () => {
    // A sanity check that the two halves of the project share a definition of
    // "close". Not a detection metric -- these are close by construction.
    const singleEdit = ["omission", "repetition", "transposition", "replacement"];
    let checked = 0;
    for (const [host, technique] of CANDIDATES) {
      if (!singleEdit.includes(technique)) continue;
      const registrable = scoring.registrableDomain(host);
      assert.ok(
        scoring.lookalikeDistance(registrable).distance <= 2,
        host + " (" + technique + ") fell outside the distance window"
      );
      checked++;
    }
    assert.ok(checked > 50, "only checked " + checked);
  });

  await t.test("tld-swap candidates are caught by the brand-label comparison", () => {
    const swapped = [...CANDIDATES].filter(([, tech]) => tech === "tld-swap").map(([h]) => h);
    for (const host of swapped.slice(0, 10)) {
      assert.ok(scoring.score("http://" + host + "/").score >= scoring.WEIGHTS.EDIT_DISTANCE, host);
    }
  });
});
