/**
 * The SIEM-expressible subset of the scorer.
 *
 * src/scoring.js is a weighted accumulator with a credential-field gate. A
 * query language is a pattern matcher. This module is the honest intersection:
 * exactly what a Sigma rule can express, implemented in JS so it can be tested
 * against sample events and measured against the full scorer.
 *
 * Every artefact under detections/ is generated from this module, so the
 * published rules cannot drift from the logic these tests exercise. What they
 * can still drift from is the extension, and that gap is what
 * coverageAgainstCorpus() exists to quantify rather than assume.
 */
(function (root, factory) {
  const api = factory(require("./scoring.js"), require("./permutations.js"));
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.SteamDetectionRule = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (scoring, permutations) {
  "use strict";

  const WARN = scoring.BANDS.CAUTION;

  /**
   * Hosts the scorer warns on for edit distance or homoglyph alone.
   *
   * Generated candidates are filtered through the scorer itself, so nothing
   * reaches a rule that the extension would not also flag. Keys are the
   * on-the-wire form: IDNA is applied first, because a Cyrillic lookalike
   * appears in a proxy log as its xn-- label, never as the Unicode a victim saw.
   */
  function materialiseLookalikes() {
    const hosts = new Map();
    for (const target of scoring.IMPERSONATION_TARGETS) {
      for (const [host] of permutations.generate(target, {})) {
        const result = scoring.score("https://" + host + "/", {});
        if (result.score < WARN) continue;
        const fired = result.reasons.map(r => r.id);
        if (!fired.includes("edit_distance") && !fired.includes("homoglyph")) continue;
        let wire = host;
        try { wire = new URL("https://" + host + "/").hostname; } catch (err) { /* keep raw */ }
        hosts.set(wire, fired.includes("homoglyph") ? "homoglyph" : "edit_distance");
      }
    }
    return new Map([...hosts].sort((a, b) => a[0].localeCompare(b[0])));
  }

  const LOOKALIKES = materialiseLookalikes();

  function isOfficial(host) {
    return scoring.OFFICIAL_DOMAINS.some(d => host === d || host.endsWith("." + d));
  }

  /**
   * Evaluate the high-confidence rule against one log event.
   * Returns the signal name, or null. Mirrors the emitted Sigma condition:
   *   (lookalike_host or embedded_official_host or embedded_official_uri)
   *   and not official_host
   */
  function evaluate(event) {
    const host = String(event.host || "").toLowerCase().replace(/\.$/, "");
    const uri = String(event.uri || "").toLowerCase();
    if (!host) return null;
    if (isOfficial(host)) return null;

    if (LOOKALIKES.has(host)) return "lookalike_domain";

    // Mirrors embeddedOfficial() in the scorer. An earlier version required a
    // dot after the official domain, which quietly missed the commonest shape
    // of all -- steamcommunity.com-login.gift-cs.ml, where the separator is a
    // hyphen -- and every label-embed such as steamcommunity-login.tk.
    for (const official of scoring.OFFICIAL_DOMAINS) {
      if (host.includes(official) && !host.endsWith(official)) return "embedded_official_host";
    }
    const registrable = scoring.registrableDomain(host);
    const brand = scoring.brandLabel(registrable);
    for (const official of scoring.OFFICIAL_DOMAINS) {
      const officialBrand = scoring.brandLabel(official);
      if (brand !== officialBrand && brand.includes(officialBrand)) return "embedded_official_label";
    }
    // The scorer's path-embed and query-embed shapes are deliberately NOT here.
    // Measured against the labelled corpus they buy 2 more phishing URLs and
    // cost 6 false positives -- web.archive.org, virustotal.com, urlscan.io and
    // translate.google.com all legitimately carry an official Steam domain in a
    // path or a redirect parameter. The extension stays quiet on them only
    // because the credential gate halves a page with no password field, and a
    // proxy log carries no such information. Trading three false positives for
    // one catch is the trade this project rejects elsewhere; it is rejected
    // here too, and the two URLs stay uncovered.
    return null;
  }

  /**
   * How much of the extension's behaviour survives the translation.
   *
   * Runs both the rule and the full scorer over the labelled corpus and returns
   * the confusion between them. This is the number that says what deploying the
   * SIEM rule actually buys, as opposed to what the extension does.
   */
  function coverageAgainstCorpus(corpus) {
    let rule = 0, scorer = 0, both = 0, scorerOnly = 0, ruleOnly = 0, total = 0;
    const missed = [];
    const unparseable = [];
    for (const entry of corpus) {
      if (entry.label !== "phishing") continue;
      total++;
      let parsed;
      try {
        parsed = new URL(entry.url);
      } catch (err) {
        // Surfaced rather than skipped. A silently dropped entry inflates every
        // ratio below, which is exactly how a coverage number becomes a lie --
        // corpus URLs are defanged on disk and must be refanged by the caller.
        unparseable.push(entry.url);
        continue;
      }
      const ruleHit = evaluate({ host: parsed.hostname, uri: parsed.pathname + parsed.search }) !== null;
      // The scorer gets the page signals the extension would have; the rule gets
      // only what a proxy log carries. That asymmetry is the measurement.
      const scorerHit = scoring.score(entry.url, entry.pageSignals || {}).score >= WARN;
      if (ruleHit) rule++;
      if (scorerHit) scorer++;
      if (ruleHit && scorerHit) both++;
      if (scorerHit && !ruleHit) { scorerOnly++; missed.push(entry.url); }
      if (ruleHit && !scorerHit) ruleOnly++;
    }
    return { total, rule, scorer, both, scorerOnly, ruleOnly, missed, unparseable };
  }

  return { materialiseLookalikes, evaluate, coverageAgainstCorpus, LOOKALIKES, WARN };
});
