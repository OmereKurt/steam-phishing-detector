# chrome-extension/

The loadable extension. Detection logic is **not** written here.

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest. One permission: `activeTab`. |
| `scoring.js` | **Generated.** A verbatim copy of `../src/scoring.js`, written by `npm run sync`. Do not edit; CI fails if it drifts. |
| `content.js` | Collects DOM signals, calls the scorer, renders the banner in a closed shadow root. |
| `background.js` | Service worker. Mirrors the verdict onto the toolbar badge. |
| `popup.html` / `popup.js` | Asks the content script for the current tab's verdict and shows the reasons behind it. |

## Loading it

1. `chrome://extensions/`
2. Enable **Developer mode**
3. **Load unpacked** → select this folder
4. `npm run demo` from the repository root, then open the URL it prints

## Why scoring.js is duplicated

MV3 content scripts cannot use ES module imports. The alternative to copying one
file is adding a bundler for one file. `scripts/sync-extension.js` copies it and
`npm run sync:check` — which CI runs on every push — fails the build if the copy
and the source ever disagree.
