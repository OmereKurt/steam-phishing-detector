/**
 * Typosquat permutation generator.
 *
 * Given a registrable domain, produces the candidate hostnames an attacker
 * would plausibly register to impersonate it. Same idea as dnstwist, written
 * from scratch and kept pure so it can be unit tested.
 *
 * The point is not the permutations themselves -- it is that resolving them
 * against DNS turns an invented test set into a measured one. See
 * scripts/discover.js.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.SteamPhishPermutations = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  /** QWERTY physical adjacency, used for slip-of-the-finger typos. */
  const KEYBOARD = {
    q: "was", w: "qeas", e: "wrsd", r: "etdf", t: "ryfg", y: "tugh",
    u: "yihj", i: "uojk", o: "ipkl", p: "ol",
    a: "qwsz", s: "awedxz", d: "serfcx", f: "drtgvc", g: "ftyhbv",
    h: "gyujnb", j: "huikmn", k: "jiolm", l: "kop",
    z: "asx", x: "zsdc", c: "xdfv", v: "cfgb", b: "vghn", n: "bhjm", m: "njk",
    "1": "2q", "2": "13w", "3": "24e", "4": "35r", "5": "46t",
    "6": "57y", "7": "68u", "8": "79i", "9": "80o", "0": "9p"
  };

  /** ASCII characters that read as each other in a URL bar. */
  const ASCII_HOMOGLYPHS = {
    a: ["4", "@"], b: ["6", "8"], c: ["("], e: ["3"], g: ["9", "q"],
    i: ["1", "l", "!"], l: ["1", "i"], o: ["0"], q: ["g"], s: ["5", "$"],
    t: ["7"], z: ["2"], u: ["v"], v: ["u"], m: ["rn"], w: ["vv"], d: ["cl"],
    n: ["m"], h: ["b"], k: ["lc"]
  };

  /** Non-Latin characters that render as Latin ones. Resolved via punycode. */
  const UNICODE_HOMOGLYPHS = {
    a: ["а", "α"], c: ["с", "ϲ"], e: ["е", "ε"],
    i: ["і", "ӏ"], j: ["ј"], o: ["о", "ο"],
    p: ["р", "ρ"], s: ["ѕ"], x: ["х", "χ"],
    y: ["у", "γ"], d: ["ԁ"], h: ["һ"], k: ["к"],
    m: ["м"], t: ["т"], b: ["ь"], q: ["ԛ"], w: ["ԝ"]
  };

  const VOWELS = "aeiou";

  /** TLDs a lookalike is plausibly registered under. */
  const TLDS = [
    "com", "net", "org", "co", "cm", "om", "cc", "io", "info", "biz",
    "online", "site", "shop", "store", "app", "live", "top", "xyz", "club",
    "tk", "ml", "ga", "cf", "gq", "ru", "cn", "su", "pw", "icu", "vip", "fun"
  ];

  /** Words attackers bolt onto a brand. */
  const COMBO_WORDS = [
    "login", "signin", "secure", "verify", "account", "wallet", "trade",
    "trades", "market", "gift", "gifts", "support", "help", "community",
    "store", "free", "official", "auth", "guard", "steam"
  ];

  const DOMAIN_CHAR = /^[a-z0-9-]$/;

  function splitDomain(domain) {
    const i = String(domain).toLowerCase().indexOf(".");
    if (i === -1) return { label: String(domain).toLowerCase(), tld: "" };
    return { label: domain.slice(0, i).toLowerCase(), tld: domain.slice(i + 1).toLowerCase() };
  }

  // -------------------------------------------------------------------------
  // Techniques. Each returns bare labels; the caller reattaches the TLD.
  // -------------------------------------------------------------------------

  /** steamcommunity -> teamcommunity, samcommunity, ... */
  function omission(label) {
    const out = [];
    for (let i = 0; i < label.length; i++) {
      out.push(label.slice(0, i) + label.slice(i + 1));
    }
    return out;
  }

  /** steamcommunity -> ssteamcommunity, stteamcommunity, ... */
  function repetition(label) {
    const out = [];
    for (let i = 0; i < label.length; i++) {
      out.push(label.slice(0, i) + label[i] + label.slice(i));
    }
    return out;
  }

  /** Adjacent character swap -- the single most common domain typo. */
  function transposition(label) {
    const out = [];
    for (let i = 0; i < label.length - 1; i++) {
      if (label[i] === label[i + 1]) continue;
      out.push(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2));
    }
    return out;
  }

  /** Hit the key next to the intended one. */
  function replacement(label) {
    const out = [];
    for (let i = 0; i < label.length; i++) {
      for (const near of KEYBOARD[label[i]] || "") {
        out.push(label.slice(0, i) + near + label.slice(i + 1));
      }
    }
    return out;
  }

  /** Catch a neighbouring key on the way past. */
  function insertion(label) {
    const out = [];
    for (let i = 0; i < label.length; i++) {
      for (const near of KEYBOARD[label[i]] || "") {
        out.push(label.slice(0, i) + near + label.slice(i));
        out.push(label.slice(0, i + 1) + near + label.slice(i + 1));
      }
    }
    return out;
  }

  /** A single flipped bit in transit or in RAM still resolves somewhere. */
  function bitsquatting(label) {
    const out = [];
    for (let i = 0; i < label.length; i++) {
      const code = label.charCodeAt(i);
      for (let bit = 0; bit < 7; bit++) {
        const flipped = String.fromCharCode(code ^ (1 << bit));
        if (DOMAIN_CHAR.test(flipped) && flipped !== label[i]) {
          out.push(label.slice(0, i) + flipped + label.slice(i + 1));
        }
      }
    }
    return out;
  }

  /** Characters that look alike to a reader, ASCII only. */
  function homoglyphAscii(label) {
    const out = [];
    for (let i = 0; i < label.length; i++) {
      for (const glyph of ASCII_HOMOGLYPHS[label[i]] || []) {
        out.push(label.slice(0, i) + glyph + label.slice(i + 1));
      }
    }
    // The reverse direction: rn -> m reads as m, so m -> rn is the attack.
    for (const [pair, single] of [["rn", "m"], ["vv", "w"], ["cl", "d"]]) {
      let idx = label.indexOf(pair);
      while (idx !== -1) {
        out.push(label.slice(0, idx) + single + label.slice(idx + pair.length));
        idx = label.indexOf(pair, idx + 1);
      }
    }
    return out;
  }

  /** Non-Latin lookalikes. Returned as Unicode; the caller punycodes them. */
  function homoglyphUnicode(label) {
    const out = [];
    for (let i = 0; i < label.length; i++) {
      for (const glyph of UNICODE_HOMOGLYPHS[label[i]] || []) {
        out.push(label.slice(0, i) + glyph + label.slice(i + 1));
      }
    }
    return out;
  }

  /** steamcommunity -> steamcommunity with each vowel swapped for another. */
  function vowelSwap(label) {
    const out = [];
    for (let i = 0; i < label.length; i++) {
      if (VOWELS.indexOf(label[i]) === -1) continue;
      for (const vowel of VOWELS) {
        if (vowel !== label[i]) out.push(label.slice(0, i) + vowel + label.slice(i + 1));
      }
    }
    return out;
  }

  /** steamcommunity -> steam-community */
  function hyphenation(label) {
    const out = [];
    for (let i = 1; i < label.length; i++) {
      if (label[i] === "-" || label[i - 1] === "-") continue;
      out.push(label.slice(0, i) + "-" + label.slice(i));
    }
    return out;
  }

  /** brand + keyword, with and without a hyphen, both orders. */
  function combosquat(label) {
    const out = [];
    for (const word of COMBO_WORDS) {
      if (label.indexOf(word) !== -1) continue;
      out.push(label + word, label + "-" + word, word + label, word + "-" + label);
    }
    return out;
  }

  // -------------------------------------------------------------------------

  const LABEL_TECHNIQUES = {
    omission: omission,
    repetition: repetition,
    transposition: transposition,
    replacement: replacement,
    insertion: insertion,
    bitsquatting: bitsquatting,
    "homoglyph-ascii": homoglyphAscii,
    "homoglyph-unicode": homoglyphUnicode,
    "vowel-swap": vowelSwap,
    hyphenation: hyphenation,
    combosquat: combosquat
  };

  /**
   * All candidates for one domain.
   * @returns {Map<string, string>} hostname -> technique that produced it
   */
  /**
   * Every string exactly one edit from the label, on the same TLD.
   *
   * generate() above answers "what would an attacker plausibly register" --
   * keyboard slips, homoglyphs, combosquats. That is the right question for
   * scripts/discover.js, which resolves the answers against DNS and should not
   * fire off thousands of lookups for strings nobody would ever buy.
   *
   * It is the wrong question for a SIEM lookup. Materialising a neighbourhood
   * for a rule needs *coverage*, not plausibility: any string within the
   * scorer's distance threshold has to be in the list or the rule is quietly
   * narrower than the product. steamcommunitiy.com is one edit from
   * steamcommunity and none of the eleven techniques produce it, so it was
   * scored 50 by the extension and missed entirely by the generated rules.
   *
   * Distance 1 only. The complete distance-2 neighbourhood of a fourteen
   * character label runs to hundreds of thousands of strings, which is a lookup
   * nobody wants and a false-positive surface nobody has measured; distance 2
   * stays technique-driven, and that limit is documented rather than hidden.
   */
  function exhaustiveNeighbourhood(domain) {
    const { label, tld } = splitDomain(domain);
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-";
    const found = new Map();

    const add = (mutated, technique) => {
      if (!mutated || mutated === label) return;
      if (mutated.startsWith("-") || mutated.endsWith("-")) return;
      if (mutated.indexOf("--") !== -1) return;
      const host = mutated + "." + tld;
      if (!found.has(host)) found.set(host, technique);
    };

    for (let i = 0; i < label.length; i++) {
      add(label.slice(0, i) + label.slice(i + 1), "exhaustive-deletion");
    }
    for (let i = 0; i < label.length; i++) {
      for (const ch of alphabet) {
        if (ch === label[i]) continue;
        add(label.slice(0, i) + ch + label.slice(i + 1), "exhaustive-substitution");
      }
    }
    for (let i = 0; i <= label.length; i++) {
      for (const ch of alphabet) {
        add(label.slice(0, i) + ch + label.slice(i), "exhaustive-insertion");
      }
    }
    for (let i = 0; i < label.length - 1; i++) {
      if (label[i] === label[i + 1]) continue;
      add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2), "exhaustive-transposition");
    }

    return found;
  }

  function generate(domain, options) {
    const opts = options || {};
    const { label, tld } = splitDomain(domain);
    const found = new Map();

    const add = (host, technique) => {
      if (!host || host === domain) return;
      if (host.startsWith("-") || host.endsWith("-")) return;
      if (!found.has(host)) found.set(host, technique);
    };

    for (const name of Object.keys(LABEL_TECHNIQUES)) {
      for (const mutated of LABEL_TECHNIQUES[name](label)) {
        add(mutated + "." + tld, name);
      }
    }

    // Same label, different TLD -- the correct brand in the wrong place.
    for (const other of opts.tlds || TLDS) {
      if (other !== tld) add(label + "." + other, "tld-swap");
    }

    // A dot where a reader expects none: steam.community
    for (let i = 1; i < label.length; i++) {
      add(label.slice(0, i) + "." + label.slice(i) + "." + tld, "subdomain-split");
    }

    return found;
  }

  return {
    generate: generate,
    exhaustiveNeighbourhood: exhaustiveNeighbourhood,
    splitDomain: splitDomain,
    techniques: LABEL_TECHNIQUES,
    TLDS: TLDS,
    COMBO_WORDS: COMBO_WORDS,
    KEYBOARD: KEYBOARD
  };
});
