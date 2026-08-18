# Design notes

Why each signal exists, what it weighs, and where the scorer fails. If you are
reading this to decide whether the numbers in the README mean anything, start at
[Honest limitations](#honest-limitations).

## The problem this actually solves

Steam credential phishing is overwhelmingly *domain* deception. The victim sees a
sign-in page that looks right and a URL that looks close enough, and types a
password. The attack is not novel malware — it is a lookalike hostname plus a
convincing form.

So the scorer analyses the hostname, and only warns where a password can actually
be typed.

## Why scoring and not rules

The previous version of this extension ANDed three conditions together:

```javascript
if (!isOfficial && looksSteam && looksLogin) showWarning();
```

Three problems. A single missing condition silences it entirely — a typosquat with
no "steam" substring in the URL is invisible. Every condition carries identical
weight, so `steamcommnuity.com` and a fan wiki are treated the same. And there is
nothing to tune: the only settings are on and off.

Weighted scoring fixes all three. Signals accumulate independently, they carry
different confidence, and the warn threshold is a dial that can be moved once you
have something to measure against.

## Signals

| Signal | Weight | What it catches |
|---|---:|---|
| `edit_distance` | 40 | Damerau-Levenshtein ≤ 2 from an official domain — `steamcommnuity.com`, `stearnpowered.com` |
| `homoglyph` | 35 | Same visual skeleton after confusable normalisation — Cyrillic `е`, `rn` for `m`, `0` for `o` |
| `embedded_official` | 35 | A real Steam domain in someone else's hostname, label, path or query |
| `punycode` | 30 | An `xn--` label, which may render as something else entirely |
| `branding` | 15 | Steam branding in the page title or image alt text |
| `risky_tld` | 10 | `.tk .ml .ga .cf .gq` — free registration, high abuse |
| `login_keyword` | 10 | `login`, `signin`, `authenticate`, `trade`, `market` in the URL |

Weights are ordered by how hard the signal is to trigger by accident. Distance from
a Valve domain is nearly impossible to hit innocently, so it leads. Steam branding
is trivially innocent — thousands of legitimate sites are about Steam — so it is
worth little on its own and only matters stacked on something else.

Raw scores are capped at 100 before the credential multiplier.

### Two notes on the edit-distance signal

**Distance is measured twice**, once on the full registrable domain and once on the
brand label alone, and the smaller wins. Without the label comparison,
`steampowered.net` scores distance 3 — `.net` against `.com` is three
substitutions — and slips through, despite being the correct brand under the wrong
TLD. On the label alone it is distance 0.

**Distance 0 is reachable and meaningful.** It means "identical brand label, and yet
not an official domain", which is exactly the wrong-TLD case. It cannot fire on a
genuine Steam domain because official hosts are allowlisted and returned before
this code runs.

**The distance is unrestricted Damerau-Levenshtein, not optimal string alignment.**
OSA is cheaper and usually close enough, but it forbids editing a region that has
already been transposed. `damerauLevenshtein("ca", "abc")` returns 2 here and 3
under OSA; there is a test pinning that.

## The credential gate

```javascript
const hasCredentialField = !!document.querySelector('input[type="password"]');
```

Applied as a **multiplier, not a signal**: ×1.0 with a password field, ×0.5 without,
×1.0 when unknown (URL-only scoring, so a missing DOM never penalises).

This is the single largest false-positive reduction available. A Steam fan wiki
scores on branding and a `trade` keyword and would sit near the warn threshold
forever; it has no password field, so it halves to silence. Meanwhile a lookalike
domain with no visible form still reaches caution rather than dropping to zero,
because the domain is suspect whether or not this particular page has a form on it.

Unknown maps to 1.0 rather than 0.5 deliberately: the harness scores URLs without a
browser, and a gate that punished missing DOM data would make every offline
measurement wrong.

## Verdict bands

| Score | Verdict | Behaviour |
|---:|---|---|
| ≥ 60 | `block` | Red banner, "Go back" offered |
| 35–59 | `caution` | Amber banner |
| < 35 | `silent` | Nothing rendered |

Two bands rather than one because the failure modes differ. A red banner on a
legitimate page trains the user to dismiss red banners; an amber one is cheap
enough to be wrong occasionally.

## Measurement

`test/corpus.json` holds 86 labelled URLs — 38 phishing, 48 benign — across
typosquats, homoglyphs, punycode, embedded domains, brand-abuse lures, official
Steam pages, legitimate Steam-adjacent sites, and unrelated sites that do have
credential forms.

Every URL is defanged (`hxxps://`, `[.]`), including the benign ones, so the rule
is uniform and nothing in the file is clickable. `test/helpers/corpus.js` refangs
before scoring.

Performance is reported at four thresholds rather than one, because the useful
question is not "is it good" but "what does more coverage cost".

### One round of tuning, recorded

The first run against the full corpus produced **94.6% precision at 92.1% recall**,
with two false positives that shared a shape:

```
FP  score 45  hxxps://login[.]urlscan[.]io/?next=/domain/steamcommunity[.]com
FP  score 45  hxxps://sso[.]blueteam-lab[.]io/auth?redirect_uri=hxxps://steamcommunity[.]com/login
```

Both are ordinary sign-in pages carrying a Steam domain in a redirect parameter —
an analyst logging into a scanning service, and any OAuth flow whose `redirect_uri`
points at Steam. The path-embed rule could not tell "points at Steam" from
"pretending to be Steam".

Fix: query values under known reference parameters (`next`, `redirect_uri`, `url`,
`q`, `continue`, and similar) no longer count as domain embedding. An official
domain named as a redirect target or a search term is a *reference* to Steam, not a
*disguise* as Steam. Path segments still count, because
`trade-offer.gq/steamcommunity.com/login` is deception.

Both false positives cleared with no loss of recall: **100% precision at 92.1%
recall**. The corresponding test is `reference parameters are not treated as
embedding`.

## Honest limitations

Read this before quoting any number above.

- **The corpus is synthetic.** Attack *shapes* come from published Steam phishing
  tradecraft; the specific hostnames are invented. This is a regression suite, not
  threat intelligence, and 86 URLs is small. 92.1% here means "misses 3 of 38 known
  patterns", not "catches 92% of Steam phishing in the wild".
- **Nothing is validated against live traffic.** No user study, no telemetry, no
  deployment. The extension has never run anywhere but a developer machine.
- **Brand-abuse lures are the known blind spot.** All three misses at the warn
  threshold — `steamwallet-generator.cf`, `steam-community-market.xyz`,
  `steamsupport-helpdesk.online` — carry no lookalike domain at all. They are
  Steam-*themed*, not Steam-*imitating*, so a domain analyser has almost nothing to
  grip. Catching them needs page-content analysis or domain reputation, neither of
  which is here.
- **IDN domains are only partially handled.** Chrome hands the content script the
  punycode form, and the homoglyph check runs on Latin characters, so it cannot see
  inside `xn--`. Those domains fire the punycode signal and typically reach caution,
  not block. Decoding punycode before normalising would close this; it is not
  implemented.
- **The public suffix list is a 20-entry stand-in.** Registrable-domain extraction
  will be wrong for exotic multi-part suffixes. Vendoring the real PSL into a
  browser extension was judged not worth the weight for this scope.
- **The allowlist is hardcoded.** Five Valve registrable domains. A regional or newly
  launched Valve domain would not be recognised, and would be scored like any other
  stranger.
- **Weights were set by judgement, then checked against the corpus.** They are not
  learned, and with 86 samples they could not be. The one change made in response to
  measurement is the reference-parameter fix documented above.
