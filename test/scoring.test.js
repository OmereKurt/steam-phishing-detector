"use strict";

const test = require("node:test");
const assert = require("node:assert");
const s = require("../src/scoring.js");

const W = s.WEIGHTS;

/** Convenience: the set of reason ids a URL fires. */
function ids(url, pageSignals) {
  return s.score(url, pageSignals).reasons.map(r => r.id);
}

// ---------------------------------------------------------------------------
test("Damerau-Levenshtein", async t => {
  await t.test("identical strings are distance 0", () => {
    assert.strictEqual(s.damerauLevenshtein("steamcommunity", "steamcommunity"), 0);
  });

  await t.test("counts a single adjacent transposition as one edit", () => {
    assert.strictEqual(s.damerauLevenshtein("steamcommnuity", "steamcommunity"), 1);
  });

  await t.test("counts a single deletion as one edit", () => {
    assert.strictEqual(s.damerauLevenshtein("steamcomunity", "steamcommunity"), 1);
  });

  await t.test("counts a single substitution as one edit", () => {
    assert.strictEqual(s.damerauLevenshtein("sfeamcommunity", "steamcommunity"), 1);
  });

  await t.test("is unrestricted, not optimal string alignment", () => {
    // OSA reports 3 here because it forbids editing a transposed substring
    // again. True Damerau-Levenshtein reports 2.
    assert.strictEqual(s.damerauLevenshtein("ca", "abc"), 2);
  });

  await t.test("is symmetric", () => {
    assert.strictEqual(
      s.damerauLevenshtein("steampowered", "stearnpowered"),
      s.damerauLevenshtein("stearnpowered", "steampowered")
    );
  });

  await t.test("handles empty input", () => {
    assert.strictEqual(s.damerauLevenshtein("", "abc"), 3);
    assert.strictEqual(s.damerauLevenshtein("abc", ""), 3);
    assert.strictEqual(s.damerauLevenshtein("", ""), 0);
  });
});

// ---------------------------------------------------------------------------
test("homoglyph skeleton", async t => {
  await t.test("collapses rn onto m", () => {
    assert.strictEqual(s.skeleton("stearnpowered"), s.skeleton("steampowered"));
  });

  await t.test("collapses Cyrillic lookalikes onto Latin", () => {
    assert.strictEqual(s.skeleton("stеamcommunity"), s.skeleton("steamcommunity"));
    assert.strictEqual(s.skeleton("ѕteampowered"), s.skeleton("steampowered"));
  });

  await t.test("collapses digit substitutions", () => {
    assert.strictEqual(s.skeleton("steamc0mmunity"), s.skeleton("steamcommunity"));
  });

  await t.test("collapses l and i onto one class", () => {
    assert.strictEqual(s.skeleton("steamcommunlty"), s.skeleton("steamcommunity"));
  });

  await t.test("keeps genuinely different brands apart", () => {
    assert.notStrictEqual(s.skeleton("steamdb"), s.skeleton("steamcommunity"));
    assert.notStrictEqual(s.skeleton("steamcharts"), s.skeleton("steampowered"));
  });
});

// ---------------------------------------------------------------------------
test("hostname parsing", async t => {
  await t.test("extracts the registrable domain", () => {
    assert.strictEqual(s.registrableDomain("store.steampowered.com"), "steampowered.com");
    assert.strictEqual(s.registrableDomain("steampowered.com"), "steampowered.com");
    assert.strictEqual(s.registrableDomain("a.b.c.evil.tk"), "evil.tk");
  });

  await t.test("handles two-part public suffixes", () => {
    assert.strictEqual(s.registrableDomain("shop.example.co.uk"), "example.co.uk");
    assert.strictEqual(s.registrableDomain("example.com.au"), "example.com.au");
  });

  await t.test("tolerates a trailing dot", () => {
    assert.strictEqual(s.registrableDomain("steampowered.com."), "steampowered.com");
  });
});

// ---------------------------------------------------------------------------
test("official-domain allowlist", async t => {
  await t.test("accepts official domains and their subdomains", () => {
    assert.ok(s.isOfficialHost("steamcommunity.com"));
    assert.ok(s.isOfficialHost("store.steampowered.com"));
    assert.ok(s.isOfficialHost("help.steampowered.com"));
  });

  await t.test("rejects the suffix-confusion bypasses", () => {
    assert.ok(!s.isOfficialHost("steamcommunity.com.evil.tk"), "domain as subdomain");
    assert.ok(!s.isOfficialHost("evilsteamcommunity.com"), "brand as a prefix");
    assert.ok(!s.isOfficialHost("steamcommunity.com-login.tk"), "hyphen after the domain");
    assert.ok(!s.isOfficialHost("notsteampowered.com"));
  });

  await t.test("stays silent on an official page carrying every other signal", () => {
    // A Steam-branded credential page with login and market keywords in the URL.
    const r = s.score("https://store.steampowered.com/login/?redir=market", {
      hasCredentialField: true,
      title: "Sign In - Steam",
      imageAltTexts: ["Steam logo"]
    });
    assert.strictEqual(r.score, 0);
    assert.strictEqual(r.verdict, "silent");
    assert.deepStrictEqual(r.reasons.map(x => x.id), ["official_domain"]);
  });
});

// ---------------------------------------------------------------------------
test("signals fire individually", async t => {
  await t.test("edit distance", () => {
    const r = s.score("https://steamcommnuity.com/");
    const hit = r.reasons.find(x => x.id === "edit_distance");
    assert.ok(hit, "expected edit_distance to fire");
    assert.strictEqual(hit.weight, W.EDIT_DISTANCE);
  });

  await t.test("edit distance catches the correct brand under the wrong TLD", () => {
    assert.ok(ids("https://steampowered.net/").includes("edit_distance"));
  });

  await t.test("homoglyph", () => {
    const hit = s.score("https://stearnpowered.com/").reasons.find(x => x.id === "homoglyph");
    assert.ok(hit);
    assert.strictEqual(hit.weight, W.HOMOGLYPH);
  });

  await t.test("embedded official domain, all four shapes", () => {
    const shape = url => {
      const r = s.score(url).reasons.find(x => x.id === "embedded_official");
      assert.ok(r, "expected embedded_official for " + url);
      return r.detail;
    };
    assert.match(shape("https://steamcommunity.com.trade-skins.tk/"), /host-embed/);
    assert.match(shape("https://steamcommunity-login.tk/"), /label-embed/);
    assert.match(shape("https://trade-offer.gq/steamcommunity.com/login"), /path-embed/);
    assert.match(shape("https://evil.tk/go?site=steamcommunity.com"), /query-embed/);
  });

  await t.test("reference parameters are not treated as embedding", () => {
    assert.ok(!ids("https://login.urlscan.io/?next=/domain/steamcommunity.com").includes("embedded_official"));
    assert.ok(!ids("https://sso.example.io/auth?redirect_uri=https://steamcommunity.com/login").includes("embedded_official"));
    assert.ok(!ids("https://www.google.com/search?q=steamcommunity.com+login").includes("embedded_official"));
  });

  await t.test("punycode", () => {
    const hit = s.score("https://xn--stampowered-pkj.com/").reasons.find(x => x.id === "punycode");
    assert.ok(hit);
    assert.strictEqual(hit.weight, W.PUNYCODE);
  });

  await t.test("branding, from title or image alt text", () => {
    assert.ok(ids("https://unrelated.example/", { title: "Steam Community" }).includes("branding"));
    assert.ok(ids("https://unrelated.example/", { imageAltTexts: ["Steam logo"] }).includes("branding"));
    assert.ok(!ids("https://unrelated.example/", { title: "Hacker News" }).includes("branding"));
  });

  await t.test("risky TLD", () => {
    for (const tld of s.RISKY_TLDS) {
      assert.ok(ids("https://something." + tld + "/").includes("risky_tld"), "." + tld);
    }
    assert.ok(!ids("https://something.com/").includes("risky_tld"));
  });

  await t.test("login keyword", () => {
    assert.ok(ids("https://unrelated.example/login").includes("login_keyword"));
    assert.ok(ids("https://unrelated.example/tradeoffer/new").includes("login_keyword"));
    assert.ok(!ids("https://unrelated.example/about").includes("login_keyword"));
  });
});

// ---------------------------------------------------------------------------
test("credential gate", async t => {
  const url = "https://steamcommnuity.com/login";

  await t.test("halves the score when no password field is present", () => {
    const withField = s.score(url, { hasCredentialField: true }).score;
    const without = s.score(url, { hasCredentialField: false }).score;
    assert.strictEqual(without, Math.round(withField * s.CREDENTIAL_MULTIPLIER.absent));
  });

  await t.test("treats unknown as present, so URL-only scoring is not penalised", () => {
    assert.strictEqual(s.score(url, {}).score, s.score(url, { hasCredentialField: true }).score);
  });

  await t.test("silences a branded page that cannot take credentials", () => {
    // The fan-wiki case: Steam branding, a trade keyword, no password field.
    const r = s.score("https://steamcommunity.fandom.com/wiki/Trading", {
      hasCredentialField: false,
      title: "Trading - Steam Community Wiki",
      imageAltTexts: ["Steam logo"]
    });
    assert.strictEqual(r.verdict, "silent");
  });

  await t.test("is a multiplier, never a scoring signal", () => {
    const r = s.score(url, { hasCredentialField: true });
    const gate = r.reasons.find(x => x.id === "credential_field");
    assert.ok(gate);
    assert.strictEqual(gate.weight, 0, "the gate must contribute no weight of its own");
  });
});

// ---------------------------------------------------------------------------
test("verdict bands", async t => {
  await t.test("maps scores onto the documented bands", () => {
    const bandOf = n => (n >= s.BANDS.BLOCK ? "block" : n >= s.BANDS.CAUTION ? "caution" : "silent");
    assert.strictEqual(bandOf(s.BANDS.BLOCK), "block");
    assert.strictEqual(bandOf(s.BANDS.BLOCK - 1), "caution");
    assert.strictEqual(bandOf(s.BANDS.CAUTION), "caution");
    assert.strictEqual(bandOf(s.BANDS.CAUTION - 1), "silent");
  });

  await t.test("a stacked lookalike blocks", () => {
    const r = s.score("https://steamcommunity.com.trade-skins.tk/login", {
      hasCredentialField: true,
      title: "Steam Community :: Sign In"
    });
    assert.strictEqual(r.verdict, "block");
  });

  await t.test("caps the raw score at 100", () => {
    const r = s.score("https://xn--stearnc0mmunlty.steamcommunity.com-login.tk/login/market", {
      hasCredentialField: true,
      title: "Steam Community"
    });
    assert.ok(r.score <= 100, "score was " + r.score);
  });
});

// ---------------------------------------------------------------------------
test("input handling", async t => {
  await t.test("prepends a scheme to a bare hostname", () => {
    assert.strictEqual(s.score("steamcommunity.com").verdict, "silent");
    assert.ok(s.score("steamcommnuity.com/login").score > 0);
  });

  await t.test("stays silent on schemes it cannot judge", () => {
    for (const url of ["chrome://extensions", "about:blank", "file:///tmp/x.html"]) {
      const r = s.score(url);
      assert.strictEqual(r.verdict, "silent", url);
      assert.strictEqual(r.reasons[0].id, "unscorable_scheme");
    }
  });

  await t.test("fails open on an unparseable URL", () => {
    const r = s.score("http://xn--steampwered-x4a.com/");
    assert.strictEqual(r.verdict, "silent");
    assert.strictEqual(r.reasons[0].id, "unparseable_url");
  });

  await t.test("returns the documented shape", () => {
    const r = s.score("https://steamcommnuity.com/login", { hasCredentialField: true });
    assert.strictEqual(typeof r.score, "number");
    assert.ok(["block", "caution", "silent"].includes(r.verdict));
    assert.ok(Array.isArray(r.reasons));
    for (const reason of r.reasons) {
      assert.strictEqual(typeof reason.id, "string");
      assert.strictEqual(typeof reason.weight, "number");
      assert.strictEqual(typeof reason.detail, "string");
    }
  });

  await t.test("is pure: repeated calls agree and inputs are not mutated", () => {
    const signals = { hasCredentialField: true, title: "Steam", imageAltTexts: ["Steam logo"] };
    const snapshot = JSON.stringify(signals);
    const a = s.score("https://steamcommnuity.com/login", signals);
    const b = s.score("https://steamcommnuity.com/login", signals);
    assert.deepStrictEqual(a, b);
    assert.strictEqual(JSON.stringify(signals), snapshot);
  });
});
