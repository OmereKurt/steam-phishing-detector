# Steam Phishing Detector

[![CI](https://github.com/OmereKurt/steam-phishing-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/OmereKurt/steam-phishing-detector/actions/workflows/ci.yml)

A Chrome extension that scores Steam credential-phishing pages and warns before a
password is typed — plus the corpus, the DNS survey and the million-domain
benchmark that say how well it actually works.

**Scored against 1,000,000 real domains, it warns on 6 — one in 166,667.** Three of
those six are genuine Steam brand squats that belong in the list. Every number here
is reproducible with a single npm command.

![Block-level warning on a page whose hostname embeds steamcommunity.com](docs/demo.png)

## Why this repository exists

Most student phishing-detector projects claim they detect phishing. Very few can
tell you how often they are right, or what they miss, or what a false positive
costs. The scoring engine here is not the interesting part — the corpus and the
measurement are. The engine is how you get something to measure.

## How detection works

`src/scoring.js` exposes one pure function:

```javascript
score(url, pageSignals) -> { score, verdict, reasons }
```

No Chrome APIs, no DOM, no network. That is what lets it be run over a labelled
corpus in Node instead of only inside a browser.

Seven weighted signals accumulate, rather than a chain of ANDed conditions:

| Signal | Weight | Catches |
|---|---:|---|
| Damerau-Levenshtein ≤ 2 from an official domain | 40 | `steamcommnuity.com`, `stearnpowered.com`, `steampowered.net` |
| Homoglyph substitution | 35 | Cyrillic `е`, `rn` for `m`, `0` for `o` |
| Official domain embedded in host, label, path or query | 35 | `steamcommunity.com.trade-skins.tk` |
| Punycode / IDN label | 30 | `xn--stampowered-pkj.com` |
| Steam branding in title or image alt text | 15 | Page dressed as Steam |
| Free-registration TLD | 10 | `.tk .ml .ga .cf .gq` |
| Login / trade / market keyword in the URL | 10 | `/login`, `/tradeoffer/` |

Then a gate, applied as a multiplier rather than a signal:

```javascript
const hasCredentialField = !!document.querySelector('input[type="password"]');
```

No password field halves the score. A Steam fan wiki has branding, a `trade`
keyword and no way to steal a credential — so it stays silent. This is the single
biggest false-positive reduction in the design.

Verdicts: **≥ 60** red block banner · **35–59** amber caution · **< 35** silent.
Official Valve domains are allowlisted and short-circuit to zero before any signal
runs.

Full reasoning, and the limitations, in [docs/DESIGN.md](docs/DESIGN.md).

## Measured performance

Three measurements, because they answer different questions and have very
different strengths.

### 1. False positives against a million real domains

The one measurement the scorer was never tuned against, and the only one drawn
entirely from outside this repository.

```
$ npm run benchmark -- top-1m.csv
Scored 1,000,000 real domains in 23.0s.

  Flagged at warn  (>=35): 6  (0.0006%)
  Flagged at block (>=60): 1  (0.0001%)

  1 in 166,667 real domains triggers a warning.

    # 222207   75  block    wsteamcommunity.com      [edit_distance, embedded_official]
    # 317330   40  caution  steamcommunity.rip       [edit_distance]
    # 460174   40  caution  steamcommunity.tips      [edit_distance]
    # 520657   35  caution  steampoweredfamily.com   [embedded_official]
    # 773577   40  caution  cukong88login.xn--6frz82g[punycode, login_keyword]
    # 934098   40  caution  stampcommunity.org       [edit_distance]
```

Domains come from the [Tranco](https://tranco-list.eu/) top-sites list, ranked by
real traffic. Every flag is printed — nothing hides behind a summary statistic.

Reading them honestly: `wsteamcommunity.com`, `steamcommunity.rip` and
`steamcommunity.tips` are Steam brand squats and the warning is correct.
`steampoweredfamily.com` is a STEM-education site, `stampcommunity.org` belongs to
stamp collectors, and the punycode one is unrelated. So the real cost is
**three false positives per million domains**, and it is visible rather than
asserted.

### 2. How much of the lookalike surface is actually registered

`src/permutations.js` generates the typosquats an attacker would plausibly buy —
omission, transposition, keyboard slips, bitsquatting, homoglyphs, hyphenation,
TLD swaps, combosquatting. `npm run discover` then asks DNS which of them exist.

```
777 candidates generated from steamcommunity.com and steampowered.com
159 are registered  (20.5%)

  tld-swap 31 · insertion 25 · replacement 24 · omission 20 · repetition 14
  transposition 12 · combosquat 12 · bitsquatting 9 · homoglyph-ascii 6 · ...
```

One in five permutations of the two domains Steam users actually sign in to has
been bought by someone. Results are in [data/lookalikes.json](data/lookalikes.json),
defanged.

**Registration is not malice**, and this is not a detection metric. Some of those
are Valve's own defensive registrations, some are parked, some are unrelated
businesses. The scorer flags 159 of 159, and that number is close to meaningless:
these candidates were produced by the same transformations the scorer measures, so
a domain made by deleting one character is one edit from the original *by
construction*. It is a sanity check that the generator and the scorer share a
definition of "close" — nothing more, and it is labelled that way in the data file.

DNS only. Nothing here ever connected to a discovered domain.

### 3. Precision and recall on the labelled corpus

`test/corpus.json` holds 86 hand-labelled URLs — 38 phishing, 48 benign — covering
typosquats, homoglyphs, punycode, embedded domains, brand-abuse lures, official
Steam pages, legitimate Steam-adjacent sites, and unrelated credential pages. This
is the set CI enforces floors against.

```
| Threshold  | TP | FP | TN | FN | Precision | Recall |   F1  |
|-----------:|---:|---:|---:|---:|----------:|-------:|------:|
|        20  | 37 |  3 | 45 |  1 |     92.5% |  97.4% | 0.949 |
|  35 (warn) | 34 |  0 | 48 |  4 |    100.0% |  89.5% | 0.944 |
| 60 (block) | 24 |  0 | 48 | 14 |    100.0% |  63.2% | 0.774 |
```

`npm run eval:misses` lists every misclassified URL with the signals behind it.

**What it misses.** All four failures are Steam-*themed* lures with no lookalike
domain — `steamwallet-generator.cf`, `steam-community-market.xyz`,
`steamsupport-helpdesk.online`, `steamgames.net`. A domain analyser has nothing to
grip on those. They are in the corpus on purpose: a test set containing only cases
you catch measures nothing.

**What these numbers are not.** This corpus is hand-written — real attack shapes,
invented hostnames — and 86 URLs is small. It is a regression suite, not evidence
about the wild. The extension has never been deployed to a user. Full limitations
in [docs/DESIGN.md](docs/DESIGN.md#honest-limitations).

## Repository structure

```
src/scoring.js              The scorer. Pure, dependency-free, the only detection logic.
src/permutations.js         Typosquat generator: 11 techniques, dnstwist-style.
chrome-extension/           Loadable MV3 extension
  manifest.json               One permission: activeTab
  scoring.js                  Generated copy of src/scoring.js (npm run sync)
  content.js                  Collects DOM signals, calls the scorer, renders the banner
  background.js               Service worker; mirrors the verdict onto the toolbar badge
  popup.html / popup.js       Shows the current tab's verdict and the reasons for it
test/corpus.json            86 labelled URLs, all defanged
test/scoring.test.js        47 unit tests, one per signal and edge case
test/corpus.test.js         24 tests: corpus integrity and precision/recall floors
test/permutations.test.js   24 tests for the generator
data/lookalikes.json        Registered Steam lookalikes found by DNS, defanged
data/benchmark.json         Every domain flagged in the million-domain run
scripts/evaluate.js         Precision/recall/F1 across a threshold sweep
scripts/discover.js         Generates permutations and resolves them (DNS only)
scripts/benchmark.js        Scores a Tranco list end to end
scripts/sync-extension.js   Copies the scorer into the extension; --check guards drift
scripts/demo.js             Local server for the demo phishing page
docs/DESIGN.md              Signal reasoning, the tuning round, and the limitations
docs/demo/login/            Inert mock Steam sign-in page for exercising the banner
```

## Running it

Requires Node 20+. There are no dependencies to install.

```bash
npm test          # 95 tests: unit coverage plus corpus regression floors
npm run eval      # precision/recall on the labelled corpus
npm run discover  # generate typosquats, resolve them against DNS
npm run demo      # serve the demo phishing page
```

The million-domain benchmark needs a list, which is not vendored here:

```bash
curl -sSL -o top-1m.csv.zip https://tranco-list.eu/top-1m.csv.zip && unzip -o top-1m.csv.zip
npm run benchmark -- top-1m.csv
```

Load the extension:

1. `chrome://extensions/` → enable **Developer mode**
2. **Load unpacked** → select `chrome-extension/`
3. `npm run demo`, then open the URL it prints

The demo is served on `steamcommunity.com.localhost`, which browsers resolve to
loopback. The scorer reads that as an official domain embedded in someone else's
hostname — the same shape as a real embedded-domain phish — and renders the block
banner shown above. Nothing leaves your machine and the demo page's password field
is inert.

## Design decisions worth naming

- **The detection logic is a pure module.** No Chrome API can reach it, which is
  the only reason a labelled-corpus measurement is possible at all.
- **The banner renders in a closed shadow root.** A page built to deceive should
  not be able to restyle or hide the warning about itself.
- **Permissions were cut from four to one.** The previous manifest requested
  `tabs`, `activeTab`, `scripting` and `<all_urls>` host permissions. Declarative
  content scripts need none of that; the popup reads the active tab only when
  clicked.
- **CI fails if the extension's copy of the scorer drifts from the source.**
  `npm run sync:check`.
- **The corpus is fully defanged**, benign URLs included, so no rule about which
  entries are safe to click has to exist.

## What changed in 2.0

The 1.x extension made three claims this repository could not support: SSL
certificate validation (no certificate handling existed anywhere in the code),
detection rule datasets (both data files were empty), and a populated repository
structure section (it read `N/A`). Detection itself was fifteen lines — an
allowlist, a substring test for `steam`, and a keyword regex, all ANDed together.
The popup bound two click handlers to a `#checkButton` element that did not exist
in the HTML, so it threw on open and neither handler ever ran.

Those claims are gone, along with the code that failed to back them. What replaced
them is measured.

## Licence

MIT. See [LICENSE](LICENSE).

## Author

Omer Kurt — Cybersecurity Analytics and Operations, Penn State.
