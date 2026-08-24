# Steam Phishing Detector

[![CI](https://github.com/OmereKurt/steam-phishing-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/OmereKurt/steam-phishing-detector/actions/workflows/ci.yml)

A Chrome extension that scores Steam credential-phishing pages and warns before a
password is typed — plus the corpus, the DNS survey, the million-domain benchmark
and the live-feed evaluation that say how well it actually works.

**Scored against 1,000,000 real domains, it warns on 7 — one in 142,857.** Three of
those seven are genuine Steam brand squats that belong in the list. Every number
here is reproducible with a single npm command.

**Scored against 73,250 live phishing URLs, it catches two of the seven aimed at**
**Steam.** The hand-written corpus reports 92.1% recall; real attacker hostnames
give 29%. That gap, and the two defects behind it, are written up in full below
rather than left out.

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

Eight weighted signals accumulate, rather than a chain of ANDed conditions:

| Signal | Weight | Catches |
|---|---:|---|
| Damerau-Levenshtein ≤ 2 from an official domain | 40 | `steamcommnuity.com`, `stearnpowered.com`, `steampowered.net` |
| Homoglyph substitution | 35 | Cyrillic `е`, `rn` for `m`, `0` for `o` |
| Official domain embedded in host, label, path or query | 35 | `steamcommunity.com.trade-skins.tk` |
| Registrable label Valve publishes, on a suffix it does not use | 30 | `steamgames.net`, `steamstatic.io` |
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

Four measurements, because they answer different questions and have very
different strengths.

### 1. False positives against a million real domains

The one measurement the scorer was never tuned against, and the only one drawn
entirely from outside this repository.

```
$ npm run benchmark -- top-1m.csv
Scored 1,000,000 real domains in 16.7s.

  Flagged at warn  (>=35): 7  (0.0007%)
  Flagged at block (>=60): 1  (0.0001%)

  1 in 142,857 real domains triggers a warning.

    # 225664   75  block    wsteamcommunity.com      [edit_distance, embedded_official]
    # 327504   40  caution  steamcommunity.rip       [edit_distance]
    # 471601   40  caution  steamcommunity.tips      [edit_distance]
    # 526087   35  caution  steampoweredfamily.com   [embedded_official]
    # 774364   40  caution  cukong88login.xn--6frz82g[punycode, login_keyword]
    # 957047   40  caution  stampcommunity.org       [edit_distance]
    # 977362   40  caution  sealcommunity.org        [edit_distance]
```

Domains come from the [Tranco](https://tranco-list.eu/) top-sites list, ranked by
real traffic. Every flag is printed — nothing hides behind a summary statistic.

Reading them honestly: `wsteamcommunity.com`, `steamcommunity.rip` and
`steamcommunity.tips` are Steam brand squats and the warning is correct.
`steampoweredfamily.com` is a STEM-education site, `stampcommunity.org` belongs to
stamp collectors, `sealcommunity.org` to conservationists, and the punycode one is
unrelated. So the real cost is **four false positives per million domains**, and it
is visible rather than asserted.

Tranco is rebuilt daily, so these counts move. The run above used the list
downloaded on 2026-08-21; an earlier snapshot flagged six rather than seven, the
extra one being `sealcommunity.org`. Re-running the command reproduces whatever
today's list says, which is the point of shipping the command rather than the
number.

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
|  35 (warn) | 35 |  0 | 48 |  3 |    100.0% |  92.1% | 0.959 |
| 60 (block) | 24 |  0 | 48 | 14 |    100.0% |  63.2% | 0.774 |
```

`npm run eval:misses` lists every misclassified URL with the signals behind it.

**What it misses.** The three remaining failures are Steam-*themed* lures with no
lookalike domain — `steamwallet-generator.cf`, `steam-community-market.xyz`,
`steamsupport-helpdesk.online`. A domain analyser has nothing to grip on those.
They are in the corpus on purpose: a test set containing only cases you catch
measures nothing.

`steamgames.net` used to be a fourth. It was never really the same class of miss —
it is the exact label Valve publishes, resold under another suffix — and it is now
caught. See below.

**What these numbers are not.** This corpus is hand-written — real attack shapes,
invented hostnames — and 86 URLs is small. It is a regression suite, not evidence
about the wild. The extension has never been deployed to a user. Full limitations
in [docs/DESIGN.md](docs/DESIGN.md#honest-limitations).

### 4. Against live phishing feeds

The corpus above is hand-written. This is the same scorer against hostnames
attackers actually registered, from PhishTank's verified-online feed
(73,250 URLs on 2026-08-24) and the OpenPhish community feed (300 URLs).

```
$ npm run live-eval -- online-valid.csv openphish-feed.txt

  Recall on target="Steam" (13 entries)      warned on 1/13
  Specificity across all 73,250 phishing URLs
    warned  (>= 35): 2  (0.0027%)
    blocked (>= 60): 0
  OpenPhish community feed: 300 URLs, 0 warned.
```

Nothing in that pipeline fetches a URL. Every input is scored as a string.

**Specificity is the good result.** Two warnings across 73,250 live phishing
URLs, and both are Steam lookalikes — one of them, `svteamconmmunity[.]com`,
PhishTank files under `Other`, so the scorer labelled it before the feed did.
Zero blocks. Zero hits on 300 OpenPhish URLs. Phishing infrastructure aimed at
Allegro, the IRS and Amazon is a far more adversarial negative set than Tranco's
legitimate domains, and a Steam-specific scorer stays quiet on it.

**Recall is the bad result, and it is worse than the corpus implies.** Start by
discounting the label: 7 of those 13 are not Steam domain phishing at all. Four
are ad-tracker and affiliate redirects, one is `www.google.com` with query
parameters, one is a generic `.html` drop. PhishTank's `target` column is
submitter-supplied and noisy. That leaves six genuine Steam-impersonation
hostnames, plus the one mislabelled `Other`:

| URL | Score | Why |
|---|---:|---|
| `login.steampowered[.]com[.]ru` | 45 | caught — embedded official domain |
| `svteamconmmunity[.]com` | 40 | caught — distance 2 |
| `steamcomunity[.]eu[.]cc` | 0 | **missed — suffix parsing** |
| `steamcomnunnlty[.]com` | 0 | missed — distance 3 |
| `steamcomunmitty[.]com` | 0 | missed — distance 3 |
| `store-steampowereed[.]ru` | 0 | missed — combosquat plus a doubled letter, distance 7 |
| `store.communitystudionsarts[.]shop` | 0 | missed — brand lure, no lookalike domain |

**Two of seven.** The labelled corpus reports 92.1% recall; real hostnames give
29%. Both numbers are honest and they measure different things — the corpus
measures the shapes I thought of, this measures the shapes attackers chose. The
gap between them is the most useful thing in this repository.


## What the live feeds exposed

Two defects, and the measured cost of fixing each. Both candidates were scored
against the Tranco top million before either was considered, for the same reason
as before: the cost of a change is a false positive rate, not an opinion.

### Defect 1: the public-suffix stand-in drops the brand label

`steamcomunity[.]eu[.]cc` scores zero. `registrableDomain` does not know
`eu.cc` is a suffix people register under, so it parses the registrable domain
as `eu.cc` and the brand label as `eu` — and `steamcomunity`, one edit from
`steamcommunity`, is discarded as a subdomain before any signal runs. The
20-entry `MULTI_PART_SUFFIXES` list is documented as a stand-in for the Public
Suffix List; this is what that shortcut actually costs.

Growing the list is endless. The alternative is to measure edit distance against
every label in the hostname rather than only the registrable brand, which needs
no suffix knowledge at all.

**Measured: catches `steamcomunity[.]eu[.]cc`, promotes `login.steampowered[.]com[.]ru`**
**from caution to block, costs 1 new false positive in the top million**
(`starcommunity.com.au`, at caution). All 103 existing tests still pass.

### Defect 2: real typosquats sit at distance 3

`steamcomnunnlty[.]com` and `steamcomunmitty[.]com` are both exactly three edits
from `steamcommunity`. `MAX_LOOKALIKE_DISTANCE` is 2, so both score zero. The
threshold was tuned against a corpus whose typosquats I wrote, and I wrote
plausible ones — attackers register uglier strings than that.

**Measured: raising the threshold to 3 catches both, and costs 6 new false**
**positives in the top million** — `telecommunity.com`, `stakecommunity.com`,
`stintcommunity.com`, `sexycommunity.it`, `sexxcommunity.com`, `telapowered.com`.
All are real businesses.

### Neither is in the scorer

The stated bar in this repository is that a signal trading one real false
positive for one caught phish is not obviously worth having. Distance 3 trades
six for two and is clearly out. Per-label distance trades one for one, which
lands exactly on the bar rather than over it — and a false positive on a
credential warning costs a user's trust in every later warning, so the tie does
not break in favour of shipping.

Both remain measurable with a one-line change and a benchmark run. That is the
point of keeping the cost of an idea cheap to find out.

## One signal added, one rejected

Closing the `steamgames.net` miss meant choosing between two candidate signals.
Both were measured against the top million before either was written into the
scorer, because the cost of a signal is a false positive rate, not an opinion.

### Added: the exact label, on the wrong suffix

`IMPERSONATION_TARGETS` is deliberately narrower than `OFFICIAL_DOMAINS` —
measuring edit distance against `steamgames.com` and `steamstatic.com` produced
real false positives (`stargames.de`, `dreamgames.com`, `slamstatic.com`), so those
domains are allowlisted but never scored against. That left a gap, and
`steamgames.net` sat in it: not a typo of anything, just the label Valve publishes
resold under another suffix.

An exact label match needs no distance metric, so it closes the gap without the
near-miss false positives that widening the edit-distance targets would have cost.
It does not stack with `edit_distance` — a label that is exactly official is also
zero edits from official, and counting both would push known caution-level squats
into block on one piece of evidence.

Cost, measured: **2 hits in the top million, both already flagged, both genuine**
**Steam brand squats.** The benchmark output is byte-identical before and after.
Recall went from 89.5% to 92.1% for nothing.

### Rejected: brand token plus service word

The obvious way to catch the other three misses is to score any domain containing
`steam` next to a service word — wallet, market, support, trade, gift, key. It
would have caught all three. It was measured and thrown away.

```
Domains in the top million containing "steam":                     227
Of those, pairing it with a service word:                          15

  steamgifts.com          steamtrades.com        steaminventoryhelper.com
  keyforsteam.de          keysforsteam.com.br    freesteamkeys.com
  steamcdkey.net          steam-account.ru       steam-trader.net
  ...
```

Most of those are legitimate: `steamgifts.com` and `steamtrades.com` are
long-running community sites, and the key resellers are businesses rather than
phishing. Adding the signal would have roughly tripled the false positive rate to
catch three corpus URLs — and `steamgifts.com` is precisely the kind of site the
credential gate was introduced to keep quiet.

The probe also produced two hits that were pure artefact: `reefgames.team` and
`vgames.team` matched because stripping dots turns `reefgames.team` into
`reefgame`**`steam`**. Substring matching across a label boundary invents brand
hits that are not there — worth knowing before trusting any containment check.

So the three brand-abuse lures stay missed, and the limitation stays in the
README. A signal that trades one real false positive for one caught phish is not
obviously worth having, and this one traded far worse than that.

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
test/scoring.test.js        55 unit tests, one per signal and edge case
test/corpus.test.js         24 tests: corpus integrity and precision/recall floors
test/permutations.test.js   24 tests for the generator
data/lookalikes.json        Registered Steam lookalikes found by DNS, defanged
data/benchmark.json         Every domain flagged in the million-domain run
data/live-eval.json         Live-feed run: every Steam-labelled URL and every hit
scripts/evaluate.js         Precision/recall/F1 across a threshold sweep
scripts/live-eval.js        Recall and specificity against live phishing feeds
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
npm test          # 103 tests: unit coverage plus corpus regression floors
npm run eval      # precision/recall on the labelled corpus
npm run discover  # generate typosquats, resolve them against DNS
npm run demo      # serve the demo phishing page
```

The million-domain benchmark needs a list, which is not vendored here:

```bash
curl -sSL -o top-1m.csv.zip https://tranco-list.eu/top-1m.csv.zip && unzip -o top-1m.csv.zip
npm run benchmark -- top-1m.csv
```

The live-feed evaluation needs two feeds, also not vendored. Both are rebuilt
continuously, so the command is the reproducible artefact, not the number:

```bash
curl -sSL -o online-valid.csv https://data.phishtank.com/data/online-valid.csv
curl -sSL -o openphish-feed.txt https://openphish.com/feed.txt
npm run live-eval -- online-valid.csv openphish-feed.txt
```

Both files contain live phishing URLs. Nothing in this repository fetches them —
they are scored as strings, and every URL printed or written to
`data/live-eval.json` is defanged.

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
