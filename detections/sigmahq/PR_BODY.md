Adds a `proxy` rule for Steam credential phishing.

Steam phishing pages consistently reuse one hostname shape: an official Steam
domain, or a Steam brand label joined by a hyphen, placed inside a domain Valve
does not control. A reader skimming the address bar sees the brand first.

```
steamcommunity.com.trade-skins.tk
login.steampowered.com.ru
steamcommunity-login.tk
```

I searched `rules/`, `rules-emerging-threats/` and `rules-threat-hunting/` for
existing typosquat, lookalike, homoglyph and punycode coverage and did not find
a rule for phishing domains of this kind, so I do not believe this duplicates
anything. Happy to be pointed at one if I missed it.

### False positive testing

I evaluated the rule's selections and filters directly against two sets:

| Set | Size | Hits |
|---|---:|---|
| Tranco top sites | 1,000,000 | 1 — `wsteamcommunity.com` |
| PhishTank verified-online | 73,250 | 1 — `login.steampowered[.]com[.]ru` (target: Steam) |

The single Tranco hit is a genuine Steam brand squat rather than a false
positive. The single PhishTank hit is a true positive, and PhishTank labels it
Steam.

On an 86-URL hand-labelled corpus the rule produces 8 true positives and 0 false
positives.

### On scope

I deliberately did **not** match a bare brand label. It catches roughly twice as
much, but adds `steampoweredfamily.com` (a STEM education site) and
`steamcommunity.fandom.com` (a fan wiki). Anchoring the brand match to a hyphen
keeps the rule clean.

The cost of that choice is missing lookalikes that use neither a hyphen nor the
full domain — `steamcomunity.eu.cc`, for example, which is a live PhishTank
entry. Catching those needs edit distance, which Sigma cannot express, so they
are out of scope here by design rather than by oversight.

### A detail in the filters

`filter_main_official_domain` matches the apex exactly and
`filter_main_official_subdomain` matches `.steamcommunity.com` with a leading
dot. Without that dot, an `endswith` filter would also swallow
`wsteamcommunity.com` and silently remove the rule's only Tranco detection.

### Testing

- `python tests/test_logsource.py` — OK
- `python tests/test_rules.py` — OK
- `sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml` — 0 errors, 0 issues

Derivation, corpus and the measurement scripts behind the numbers above:
https://github.com/OmereKurt/steam-phishing-detector
