/**
 * Steam phishing scoring engine.
 *
 * Pure module: no Chrome APIs, no DOM, no network, no I/O. It is loaded by the
 * extension as a plain content script and by the Node test suite via require(),
 * which is what makes it measurable against a labelled corpus outside a browser.
 *
 *   score(url, pageSignals) -> { score, verdict, reasons }
 *
 * See docs/DESIGN.md for the reasoning behind every weight and threshold.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.SteamPhishScoring = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // Configuration
  // ---------------------------------------------------------------------------

  /**
   * Registrable domains Valve actually operates. Subdomains are covered.
   * Used for the allowlist and for embedding checks.
   */
  const OFFICIAL_DOMAINS = [
    "steampowered.com",
    "steamcommunity.com",
    "steamgames.com",
    "steamstatic.com",
    "valvesoftware.com"
  ];

  /**
   * The subset worth measuring lookalike distance against: the domains a user
   * actually types a Steam password into. Nobody signs in at a CDN host, so
   * steamstatic.com, steamgames.com and valvesoftware.com are allowlisted but
   * are not impersonation targets.
   *
   * This distinction is not cosmetic. Scoring the Tranco top million with all
   * five as targets produced 17 warnings, and a third of them were real
   * businesses sitting two edits from a generic label -- stargames.de and
   * dreamgames.com near "steamgames", slamstatic.com near "steamstatic",
   * validsoftware.ro near "valvesoftware". None of those impersonate a login
   * page. See docs/DESIGN.md.
   */
  const IMPERSONATION_TARGETS = [
    "steampowered.com",
    "steamcommunity.com"
  ];

  /** Signal weights. Tuned against test/corpus.json — see docs/DESIGN.md. */
  const WEIGHTS = {
    EDIT_DISTANCE: 40,
    HOMOGLYPH: 35,
    EMBEDDED_OFFICIAL: 35,
    OFFICIAL_TLD_SWAP: 30,
    PUNYCODE: 30,
    BRANDING: 15,
    RISKY_TLD: 10,
    LOGIN_KEYWORD: 10
  };

  /**
   * The credential gate is a multiplier, not a signal. A page with no password
   * field cannot take credentials, so it cannot complete the attack this tool
   * exists to interrupt. Halving rather than zeroing keeps a lookalike domain
   * visible at caution level without shouting on every Steam fan wiki.
   */
  const CREDENTIAL_MULTIPLIER = {
    present: 1.0,
    absent: 0.5,
    unknown: 1.0
  };

  /** Verdict bands, applied to the final score. */
  const BANDS = { BLOCK: 60, CAUTION: 35 };

  /** Maximum edit distance still considered a lookalike of an official domain. */
  const MAX_LOOKALIKE_DISTANCE = 2;

  /** Free-registration TLDs with a long history of disposable abuse domains. */
  const RISKY_TLDS = ["tk", "ml", "ga", "cf", "gq"];

  /** Inherited verbatim from the original extension. */
  const LOGIN_KEYWORD_PATTERN = /login|signin|authenticate|trade|market/;

  /** Schemes where a warning would be meaningless or impossible. */
  const SCORABLE_PROTOCOLS = ["http:", "https:"];

  /**
   * Query parameters whose value is a reference to another page rather than a
   * claim about this one. An official Steam domain sitting in a redirect target
   * or a search box is being pointed at, not impersonated, so it must not count
   * as domain embedding. Added after the corpus surfaced both false positives
   * at the warn threshold -- see the tuning note in docs/DESIGN.md.
   */
  const REFERENCE_PARAMS = new Set([
    "next", "redirect", "redirect_uri", "redirect_url", "returnurl", "return",
    "return_to", "continue", "dest", "destination", "url", "u", "q", "query",
    "target", "goto", "callback", "service"
  ]);

  /**
   * Two-part public suffixes. This is a deliberately small stand-in for the
   * Public Suffix List: enough to parse the corpus correctly without vendoring
   * a 15k-line dataset into a browser extension. Documented as a limitation.
   */
  const MULTI_PART_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au", "co.nz", "com.br",
    "com.mx", "com.ar", "co.jp", "co.kr", "com.cn",
    "com.tr", "co.in", "com.sg", "co.za", "com.tw"
  ]);

  // ---------------------------------------------------------------------------
  // Damerau-Levenshtein edit distance (unrestricted)
  // ---------------------------------------------------------------------------

  /**
   * Unrestricted Damerau-Levenshtein distance: insertions, deletions,
   * substitutions and transpositions of adjacent characters.
   *
   * The unrestricted form is used rather than the cheaper optimal string
   * alignment variant because transposition is the single most common domain
   * typo -- steamcommnuity.com is one transposition from the real thing -- and
   * OSA silently mis-handles sequences where a transposed character is later
   * edited again.
   */
  function damerauLevenshtein(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;

    const INF = a.length + b.length;
    const lastRowOfChar = new Map();
    const d = [];
    for (let i = 0; i < a.length + 2; i++) {
      d.push(new Array(b.length + 2).fill(0));
    }

    d[0][0] = INF;
    for (let i = 0; i <= a.length; i++) {
      d[i + 1][0] = INF;
      d[i + 1][1] = i;
    }
    for (let j = 0; j <= b.length; j++) {
      d[0][j + 1] = INF;
      d[1][j + 1] = j;
    }

    for (let i = 1; i <= a.length; i++) {
      let lastMatchCol = 0;
      for (let j = 1; j <= b.length; j++) {
        const lastMatchRow = lastRowOfChar.get(b[j - 1]) || 0;
        const k = lastMatchRow;
        const l = lastMatchCol;
        let cost = 1;
        if (a[i - 1] === b[j - 1]) {
          cost = 0;
          lastMatchCol = j;
        }
        d[i + 1][j + 1] = Math.min(
          d[i][j] + cost,                                  // substitution
          d[i + 1][j] + 1,                                 // insertion
          d[i][j + 1] + 1,                                 // deletion
          d[k][l] + (i - k - 1) + 1 + (j - l - 1)          // transposition
        );
      }
      lastRowOfChar.set(a[i - 1], i);
    }

    return d[a.length + 1][b.length + 1];
  }

  // ---------------------------------------------------------------------------
  // Homoglyph normalisation
  // ---------------------------------------------------------------------------

  /**
   * Characters that render close enough to a Latin letter to fool a reader,
   * collapsed onto one representative per visual class. Covers Cyrillic and
   * Greek lookalikes, digit substitutions and accented Latin.
   */
  const CONFUSABLE_CLASSES = {
    a: "аα4@",
    b: "6ь",
    // sigma is here because IDNA folds Greek lunate sigma into it during URL
    // parsing, so the lunate form -- which is what actually resembles a c --
    // never reaches this map. Matching the folded form is the only way to see it.
    c: "сϲσ",
    d: "ԁ",
    e: "еε3",
    g: "ɡ 9",
    h: "һ",
    i: "l1|іı!ӏ",
    j: "ј",
    k: "к",
    m: "м",
    n: "пո",
    o: "0оοө",
    p: "рρ",
    q: "ԛ",
    s: "5ѕ$",
    t: "7тτ",
    u: "υս",
    v: "νѵ",
    w: "ԝω",
    x: "хχ",
    y: "уγ",
    z: "2"
  };

  /** Multi-character sequences that read as a single letter. */
  const MULTI_CHAR_CONFUSABLES = [
    [/rn/g, "m"],
    [/vv/g, "w"],
    [/cl/g, "d"]
  ];

  const CONFUSABLE_MAP = (function () {
    const map = new Map();
    for (const representative of Object.keys(CONFUSABLE_CLASSES)) {
      for (const ch of CONFUSABLE_CLASSES[representative]) {
        if (ch !== " ") map.set(ch, representative);
      }
    }
    return map;
  })();

  /**
   * Reduce a string to its visual skeleton. Two strings with the same skeleton
   * are indistinguishable to a human reading a URL bar in a hurry.
   */
  function skeleton(input) {
    let s = String(input).toLowerCase();
    // Fold confusables once before NFKD as well as after. NFKD rewrites some of
    // the very characters CONFUSABLE_CLASSES names -- Greek lunate sigma, listed
    // as a `c` confusable, decomposes to a plain sigma the map has never heard
    // of -- so a single pass after normalisation silently loses them.
    s = Array.from(s).map(ch => CONFUSABLE_MAP.get(ch) || ch).join("");
    s = s.normalize("NFKD").replace(/[̀-ͯ]/g, "");
    for (const [pattern, replacement] of MULTI_CHAR_CONFUSABLES) {
      s = s.replace(pattern, replacement);
    }
    let out = "";
    for (const ch of s) {
      out += CONFUSABLE_MAP.get(ch) || ch;
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Punycode decoding (RFC 3492)
  // ---------------------------------------------------------------------------

  /**
   * Decode one punycode label back to Unicode.
   *
   * This exists because of an ordering problem that silently disabled the
   * homoglyph signal for every real IDN. `new URL()` applies IDNA before
   * anything here runs, so a hostname typed as Cyrillic reaches score() already
   * normalised to `xn--`. skeleton() then compares the ASCII punycode string,
   * which resembles nothing, and the homoglyph signal never fires. Only
   * `punycode` fired, at weight 30 -- below the warn threshold -- so the entire
   * IDN homograph class, the attack the signal was written for, scored silent.
   *
   * Decoding restores the label the victim actually saw, which is the only
   * string a visual-confusability test has any business comparing.
   *
   * Implemented here rather than pulled in because the scorer ships into a
   * content script and carries no dependencies. Returns null when the input is
   * not decodable, so a malformed label degrades to "not a homoglyph" instead
   * of throwing inside a page.
   */
  const PUNY = { base: 36, tmin: 1, tmax: 26, skew: 38, damp: 700, initialBias: 72, initialN: 128 };

  function punyDigit(code) {
    if (code >= 0x30 && code <= 0x39) return code - 0x30 + 26; // 0-9 -> 26..35
    if (code >= 0x61 && code <= 0x7a) return code - 0x61;      // a-z -> 0..25
    if (code >= 0x41 && code <= 0x5a) return code - 0x41;      // A-Z -> 0..25
    return -1;
  }

  function punyAdapt(delta, numPoints, firstTime) {
    let d = firstTime ? Math.floor(delta / PUNY.damp) : Math.floor(delta / 2);
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > Math.floor(((PUNY.base - PUNY.tmin) * PUNY.tmax) / 2)) {
      d = Math.floor(d / (PUNY.base - PUNY.tmin));
      k += PUNY.base;
    }
    return k + Math.floor(((PUNY.base - PUNY.tmin + 1) * d) / (d + PUNY.skew));
  }

  function punycodeDecode(label) {
    const input = String(label);
    if (!/^xn--/i.test(input)) return null;
    const encoded = input.slice(4);
    if (!encoded) return null;

    const delim = encoded.lastIndexOf("-");
    const output = [];
    if (delim > -1) {
      for (const ch of encoded.slice(0, delim)) {
        if (ch.charCodeAt(0) > 0x7f) return null;
        output.push(ch.codePointAt(0));
      }
    }

    let n = PUNY.initialN;
    let i = 0;
    let bias = PUNY.initialBias;

    for (let idx = delim > -1 ? delim + 1 : 0; idx < encoded.length; ) {
      const oldi = i;
      let w = 1;
      for (let k = PUNY.base; ; k += PUNY.base) {
        if (idx >= encoded.length) return null;
        const digit = punyDigit(encoded.charCodeAt(idx++));
        if (digit < 0) return null;
        i += digit * w;
        const t = k <= bias ? PUNY.tmin : (k >= bias + PUNY.tmax ? PUNY.tmax : k - bias);
        if (digit < t) break;
        w *= PUNY.base - t;
        if (!Number.isFinite(w) || i > 0x10ffff * 64) return null;
      }
      const out = output.length + 1;
      bias = punyAdapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      if (n > 0x10ffff) return null;
      output.splice(i, 0, n);
      i++;
    }

    try {
      return String.fromCodePoint.apply(null, output);
    } catch (err) {
      return null;
    }
  }

  /** The hostname as a reader saw it: every xn-- label decoded where possible. */
  function displayHostname(hostname) {
    return String(hostname).toLowerCase().split(".").map(l => punycodeDecode(l) || l).join(".");
  }

  // ---------------------------------------------------------------------------
  // Hostname helpers
  // ---------------------------------------------------------------------------

  /** eTLD+1, using the small suffix list above. */
  function registrableDomain(hostname) {
    const labels = String(hostname).toLowerCase().replace(/\.$/, "").split(".");
    if (labels.length <= 2) return labels.join(".");
    const lastTwo = labels.slice(-2).join(".");
    const take = MULTI_PART_SUFFIXES.has(lastTwo) ? 3 : 2;
    return labels.slice(-take).join(".");
  }

  /** The brand-bearing label: steamcommunity from steamcommunity.com. */
  function brandLabel(registrable) {
    const labels = String(registrable).split(".");
    return labels.length > 1 ? labels.slice(0, -1).join(".") : labels[0];
  }

  function publicSuffix(registrable) {
    const labels = String(registrable).split(".");
    return labels[labels.length - 1] || "";
  }

  function isOfficialHost(hostname) {
    const host = String(hostname).toLowerCase().replace(/\.$/, "");
    return OFFICIAL_DOMAINS.some(d => host === d || host.endsWith("." + d));
  }

  const OFFICIAL_BRANDS = OFFICIAL_DOMAINS.map(d => brandLabel(d));
  const TARGET_BRANDS = IMPERSONATION_TARGETS.map(d => brandLabel(d));

  // ---------------------------------------------------------------------------
  // Individual signals
  // ---------------------------------------------------------------------------

  /**
   * Smallest Damerau-Levenshtein distance between this host and any official
   * domain, measured both on the full registrable domain and on the brand label
   * alone. The brand-label comparison is what catches a correct brand under the
   * wrong TLD -- steampowered.net is distance 0 on the label and 3 on the full
   * domain. Distance 0 is only reachable here because official hosts are
   * allowlisted and returned before this runs.
   */
  function lookalikeDistance(registrable) {
    const brand = brandLabel(registrable);
    let best = Infinity;
    let match = null;
    for (let i = 0; i < IMPERSONATION_TARGETS.length; i++) {
      const d = Math.min(
        damerauLevenshtein(registrable, IMPERSONATION_TARGETS[i]),
        damerauLevenshtein(brand, TARGET_BRANDS[i])
      );
      if (d < best) {
        best = d;
        match = IMPERSONATION_TARGETS[i];
      }
    }
    return { distance: best, match };
  }

  /** Same visual skeleton as an official brand, but not the same characters. */
  /**
   * The registrable label is one Valve actually uses, on a TLD Valve does not.
   *
   * This exists because IMPERSONATION_TARGETS is deliberately narrower than
   * OFFICIAL_DOMAINS: measuring edit distance against steamgames.com and
   * steamstatic.com produced real false positives (stargames.de, dreamgames.com,
   * slamstatic.com), so those domains are allowlisted but not scored against.
   * That left a gap. steamgames.net is not a typo of anything -- it is the exact
   * label Valve publishes, resold under a different suffix -- and nothing scored
   * it. An exact label match needs no distance metric, so it reintroduces the
   * missing coverage without the near-miss false positives that closing the gap
   * with edit distance would have cost.
   */
  function officialLabelTldSwap(registrable) {
    const brand = brandLabel(registrable);
    return OFFICIAL_BRANDS.indexOf(brand) === -1 ? null : brand;
  }

  function homoglyphMatch(registrable) {
    const brand = brandLabel(registrable);
    const brandSkeleton = skeleton(brand);
    for (let i = 0; i < TARGET_BRANDS.length; i++) {
      const official = TARGET_BRANDS[i];
      if (brand !== official && brandSkeleton === skeleton(official)) {
        return IMPERSONATION_TARGETS[i];
      }
    }
    return null;
  }

  /**
   * An official domain riding somewhere it does not own. Four shapes:
   *   host-embed   steamcommunity.com.trade-skins.tk
   *   label-embed  steamcommunity-login.tk
   *   path-embed   trade-skins.tk/steamcommunity.com/login
   *   query-embed  trade-skins.tk/go?site=steamcommunity.com
   *
   * Query values under REFERENCE_PARAMS are skipped: a redirect target or a
   * search term that names Steam is a reference to Steam, not a disguise.
   */
  function embeddedOfficial(hostname, pathname, search) {
    const host = String(hostname).toLowerCase();
    const brand = brandLabel(registrableDomain(host));
    const path = String(pathname || "").toLowerCase();

    for (const official of OFFICIAL_DOMAINS) {
      if (host.includes(official) && !host.endsWith(official)) {
        return { kind: "host-embed", official: official };
      }
    }
    for (let i = 0; i < OFFICIAL_BRANDS.length; i++) {
      const officialBrand = OFFICIAL_BRANDS[i];
      if (brand !== officialBrand && brand.includes(officialBrand)) {
        return { kind: "label-embed", official: OFFICIAL_DOMAINS[i] };
      }
    }
    for (const official of OFFICIAL_DOMAINS) {
      if (path.includes(official)) {
        return { kind: "path-embed", official: official };
      }
    }
    for (const [key, value] of parseQuery(search)) {
      if (REFERENCE_PARAMS.has(key)) continue;
      for (const official of OFFICIAL_DOMAINS) {
        if (value.includes(official)) {
          return { kind: "query-embed", official: official };
        }
      }
    }
    return null;
  }

  /** Query string to [key, value] pairs, lowercased and percent-decoded. */
  function parseQuery(search) {
    const pairs = [];
    const raw = String(search || "").replace(/^\?/, "");
    if (!raw) return pairs;
    for (const part of raw.split("&")) {
      if (!part) continue;
      const eq = part.indexOf("=");
      const key = (eq === -1 ? part : part.slice(0, eq)).toLowerCase();
      const rawValue = eq === -1 ? "" : part.slice(eq + 1);
      let value = rawValue.split("+").join(" ");
      try {
        value = decodeURIComponent(value);
      } catch (err) {
        // Malformed percent-encoding: fall back to the raw value.
      }
      pairs.push([key, value.toLowerCase()]);
    }
    return pairs;
  }

  function punycodeLabel(hostname) {
    return String(hostname).toLowerCase().split(".").find(l => l.startsWith("xn--")) || null;
  }

  function hasSteamBranding(pageSignals) {
    const brandingPattern = /steam/i;
    if (brandingPattern.test(pageSignals.title || "")) return "page title";
    const alts = Array.isArray(pageSignals.imageAltTexts) ? pageSignals.imageAltTexts : [];
    if (alts.some(t => brandingPattern.test(String(t)))) return "image alt text";
    return null;
  }

  // ---------------------------------------------------------------------------
  // Public entry point
  // ---------------------------------------------------------------------------

  function verdictFor(value) {
    if (value >= BANDS.BLOCK) return "block";
    if (value >= BANDS.CAUTION) return "caution";
    return "silent";
  }

  /**
   * Score one URL.
   *
   * @param {string} url         Absolute URL. A bare host gets http:// prepended.
   * @param {object} pageSignals Optional DOM-derived facts:
   *        {boolean} hasCredentialField  password input present; omit if unknown
   *        {string}  title               document title
   *        {string[]} imageAltTexts      alt text of images on the page
   * @returns {{score: number, verdict: string, reasons: Array}}
   */
  function score(url, pageSignals) {
    const signals = pageSignals || {};
    const reasons = [];

    let parsed;
    try {
      const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(String(url)) ? String(url) : "http://" + url;
      parsed = new URL(withScheme);
    } catch (err) {
      return { score: 0, verdict: "silent", reasons: [reason("unparseable_url", 0, "URL could not be parsed")] };
    }

    if (SCORABLE_PROTOCOLS.indexOf(parsed.protocol) === -1) {
      return { score: 0, verdict: "silent", reasons: [reason("unscorable_scheme", 0, parsed.protocol + " is not scored")] };
    }

    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");

    // Allowlist short-circuit. Valve's own domains never warn, whatever else is
    // on the page -- steamcommunity.com/market is a login-keyword, credential-
    // bearing, Steam-branded page and must stay silent.
    if (isOfficialHost(hostname)) {
      return {
        score: 0,
        verdict: "silent",
        reasons: [reason("official_domain", 0, hostname + " is an official Steam domain")]
      };
    }

    const registrable = registrableDomain(hostname);
    const pathAndQuery = (parsed.pathname + parsed.search).toLowerCase();
    const urlText = hostname + pathAndQuery;

    const lookalike = lookalikeDistance(registrable);
    const nearTarget = lookalike.distance <= MAX_LOOKALIKE_DISTANCE;
    if (nearTarget) {
      reasons.push(reason(
        "edit_distance",
        WEIGHTS.EDIT_DISTANCE,
        "Damerau-Levenshtein distance " + lookalike.distance + " from " + lookalike.match
      ));
    }

    // Only when edit distance did not already fire. A label that is an exact
    // official label is also zero edits from one, so scoring both would count
    // the same evidence twice and push known squats from caution into block.
    const tldSwap = nearTarget ? null : officialLabelTldSwap(registrable);
    if (tldSwap) {
      reasons.push(reason(
        "official_tld_swap",
        WEIGHTS.OFFICIAL_TLD_SWAP,
        tldSwap + " is a domain label Valve publishes, on a suffix it does not use"
      ));
    }

    // Run confusability against the hostname as it was *displayed*, not as IDNA
    // left it. `new URL()` has already punycoded any non-Latin label by the time
    // score() is called, and a skeleton comparison against `xn--stampowered-pkj`
    // matches nothing -- which silently disabled this signal for the entire IDN
    // homograph class it was written to catch. Decoding first restores the
    // string the victim actually read. Falls back to the registrable domain, so
    // ASCII homoglyphs (rn for m) behave exactly as before.
    const displayRegistrable = registrableDomain(displayHostname(hostname));
    const homoglyph = homoglyphMatch(displayRegistrable) || homoglyphMatch(registrable);
    if (homoglyph) {
      reasons.push(reason("homoglyph", WEIGHTS.HOMOGLYPH, "Renders identically to " + homoglyph + " after confusable normalisation"));
    }

    const embedded = embeddedOfficial(hostname, parsed.pathname, parsed.search);
    if (embedded) {
      reasons.push(reason("embedded_official", WEIGHTS.EMBEDDED_OFFICIAL, embedded.official + " embedded in the URL (" + embedded.kind + ")"));
    }

    const puny = punycodeLabel(hostname);
    if (puny) {
      reasons.push(reason("punycode", WEIGHTS.PUNYCODE, "Punycode/IDN label " + puny + " may render as non-Latin characters"));
    }

    const branding = hasSteamBranding(signals);
    if (branding) {
      reasons.push(reason("branding", WEIGHTS.BRANDING, "Steam branding in " + branding));
    }

    if (RISKY_TLDS.indexOf(publicSuffix(registrable)) !== -1) {
      reasons.push(reason("risky_tld", WEIGHTS.RISKY_TLD, "." + publicSuffix(registrable) + " is a free-registration TLD with high abuse rates"));
    }

    if (LOGIN_KEYWORD_PATTERN.test(urlText)) {
      reasons.push(reason("login_keyword", WEIGHTS.LOGIN_KEYWORD, "URL contains a login, trade or market keyword"));
    }

    const raw = Math.min(reasons.reduce((sum, r) => sum + r.weight, 0), 100);

    let gate = "unknown";
    if (signals.hasCredentialField === true) gate = "present";
    else if (signals.hasCredentialField === false) gate = "absent";

    const multiplier = CREDENTIAL_MULTIPLIER[gate];
    const final = Math.round(raw * multiplier);

    if (gate === "absent" && raw > 0) {
      reasons.push(reason("no_credential_field", 0, "No password field on the page; score halved from " + raw));
    } else if (gate === "present" && raw > 0) {
      reasons.push(reason("credential_field", 0, "Password field present; credentials can be entered here"));
    }

    return { score: final, verdict: verdictFor(final), reasons: reasons };
  }

  function reason(id, weight, detail) {
    return { id: id, weight: weight, detail: detail };
  }

  return {
    score: score,
    damerauLevenshtein: damerauLevenshtein,
    skeleton: skeleton,
    registrableDomain: registrableDomain,
    brandLabel: brandLabel,
    isOfficialHost: isOfficialHost,
    lookalikeDistance: lookalikeDistance,
    homoglyphMatch: homoglyphMatch,
    punycodeDecode: punycodeDecode,
    displayHostname: displayHostname,
    embeddedOfficial: embeddedOfficial,
    parseQuery: parseQuery,
    OFFICIAL_DOMAINS: OFFICIAL_DOMAINS,
    IMPERSONATION_TARGETS: IMPERSONATION_TARGETS,
    WEIGHTS: WEIGHTS,
    BANDS: BANDS,
    RISKY_TLDS: RISKY_TLDS,
    CREDENTIAL_MULTIPLIER: CREDENTIAL_MULTIPLIER
  };
});
