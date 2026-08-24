# Submitting to SigmaHQ

## 1. Fork and clone

```bash
gh repo fork SigmaHQ/sigma --clone --remote
cd sigma
git checkout -b rule-steam-phishing-domain
```

## 2. Copy the rule in

```bash
cp ~/Documents/Projects/steam-phishing-detector/detections/sigmahq/proxy_steam_phishing_domain.yml \
   rules/web/proxy_generic/proxy_steam_phishing_domain.yml
```

Then delete the two generator comment lines at the top — they refer to tooling
that will not exist in their repo.

## 3. Run their tests before opening anything

```bash
pip install -r tests/requirements.txt sigma-cli pySigma-validators-sigmahq
python tests/test_logsource.py
python tests/test_rules.py
sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml rules/web/proxy_generic/proxy_steam_phishing_domain.yml
```

All three pass as of this writing.

## 4. PR title

    Add proxy rule for Steam credential phishing domains

## 5. PR body

Adds a `proxy` rule for Steam credential phishing, which uses a recognisable
hostname shape: an official Steam domain, or a Steam brand label joined by a
hyphen, placed inside a domain Valve does not control. A reader skimming the
address bar sees the brand first.

    steamcommunity.com.trade-skins.tk
    login.steampowered.com.ru
    steamcommunity-login.tk

I could not find an existing rule covering typosquatted or lookalike phishing
domains in `rules/`, so I do not believe this duplicates anything. Happy to be
pointed at one if I missed it.

**False positive testing.** I scored the rule's selections directly against two
sets:

| Set | Size | Hits |
|---|---:|---|
| Tranco top sites | 1,000,000 | 1 — `wsteamcommunity.com` |
| PhishTank verified-online | 73,250 | 1 — `login.steampowered[.]com[.]ru` (target: Steam) |

The single Tranco hit is a genuine Steam brand squat rather than a false
positive. The single PhishTank hit is a true positive.

**On scope.** I deliberately did not match a bare brand label. It catches more,
but adds `steampoweredfamily.com` (a STEM education site) and
`steamcommunity.fandom.com` (a fan wiki). Anchoring the brand match to a hyphen
keeps the rule clean, at the cost of missing lookalikes that use neither a
hyphen nor the full domain — `steamcomunity.eu.cc`, for example. Those need edit
distance, which Sigma cannot express, so they are out of scope here by design.

`filter_main_official_domain` matches the apex exactly and
`filter_main_official_subdomain` matches `.steamcommunity.com` with a leading
dot, so `wsteamcommunity.com` is not accidentally excluded by an `endswith`
that would otherwise swallow it.

Derivation, corpus and measurement scripts:
https://github.com/OmereKurt/steam-phishing-detector

## 6. Expect review comments

Likely questions, and the honest answers:

- *"Why `contains` rather than `endswith` for the embedded-domain selection?"*
  Because the shape is the official domain appearing anywhere in the host, not
  at the end. `steamcommunity.com.trade-skins.tk` has it in the middle.
- *"Level high?"* Defensible given 1 hit in a million legitimate domains, but
  accept `medium` without arguing if a maintainer prefers it.
- *"Add more brands?"* Say no. A Valve-specific rule is reviewable; a
  multi-brand one becomes an unmaintainable list, which is exactly the version
  that was left out.
