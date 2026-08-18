# Steam Phishing Detector

A Chrome extension that scores Steam credential-phishing pages and warns before a
password is typed — plus the labelled corpus and test harness that say how well it
actually works.

**Measured on 86 labelled URLs: 92.1% detection at 0% false positives** at the warn
threshold. Regenerate that number yourself with `npm run eval`.

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

```
Corpus: 86 labelled URLs (38 phishing, 48 benign)

| Threshold | TP | FP | TN | FN | Precision | Recall |   F1  | FP rate |
|----------:|---:|---:|---:|---:|----------:|-------:|------:|--------:|
|        20 | 37 |  3 | 45 |  1 |     92.5% |  97.4% | 0.949 |    6.3% |
|  35 (warn)| 35 |  0 | 48 |  3 |    100.0% |  92.1% | 0.959 |    0.0% |
| 60 (block)| 25 |  0 | 48 | 13 |    100.0% |  65.8% | 0.794 |    0.0% |
|        80 |  4 |  0 | 48 | 34 |    100.0% |  10.5% | 0.190 |    0.0% |
```

Reported at four thresholds because one number hides the trade-off. `npm run
eval:misses` lists every misclassified URL with the signals behind it.

**What it misses.** All three failures at the warn threshold are Steam-*themed*
lures with no lookalike domain — `steamwallet-generator.cf`,
`steam-community-market.xyz`, `steamsupport-helpdesk.online`. A domain analyser has
nothing to grip on those. They are in the corpus on purpose: a test set containing
only cases you catch measures nothing.

**What these numbers are not.** The corpus is synthetic — real attack *shapes*,
invented hostnames — and 86 URLs is small. 92.1% means "misses 3 of 38 known
patterns", not "catches 92% of Steam phishing in the wild". Nothing here has been
validated against live traffic and the extension has never been deployed to users.
The rest of the limitations are listed in [docs/DESIGN.md](docs/DESIGN.md#honest-limitations).

## Repository structure

```
src/scoring.js              The scorer. Pure, dependency-free, the only detection logic.
chrome-extension/           Loadable MV3 extension
  manifest.json               One permission: activeTab
  scoring.js                  Generated copy of src/scoring.js (npm run sync)
  content.js                  Collects DOM signals, calls the scorer, renders the banner
  background.js               Service worker; mirrors the verdict onto the toolbar badge
  popup.html / popup.js       Shows the current tab's verdict and the reasons for it
test/corpus.json            86 labelled URLs, all defanged
test/scoring.test.js        47 unit tests, one per signal and edge case
test/corpus.test.js         24 tests: corpus integrity and precision/recall floors
scripts/evaluate.js         Precision/recall/F1 across a threshold sweep
scripts/sync-extension.js   Copies the scorer into the extension; --check guards drift
scripts/demo.js             Local server for the demo phishing page
docs/DESIGN.md              Signal reasoning, the tuning round, and the limitations
docs/demo/login/            Inert mock Steam sign-in page for exercising the banner
```

## Running it

Requires Node 20+. There are no dependencies to install.

```bash
npm test          # 71 tests: unit coverage plus corpus regression floors
npm run eval      # detection performance table
npm run demo      # serve the demo phishing page
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
