# docs/

| Path | What it is |
|---|---|
| `DESIGN.md` | Why each signal exists, what weight it carries, and what the scorer cannot do. |
| `demo.png` | Screenshot of the block banner, captured from `demo/login/`. |
| `demo/login/` | A mock Steam sign-in page used to exercise the banner locally. Inert: no network calls, dead password field. |

## Regenerating the screenshot

```bash
npm run demo
```

Then, in another terminal:

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless --disable-gpu --screenshot=docs/demo.png --window-size=1000,620 --hide-scrollbars --virtual-time-budget=4000 "http://steamcommunity.com.localhost:8731/docs/demo/login/"
```

The demo page loads `chrome-extension/scoring.js` and `chrome-extension/content.js`
directly as plain scripts with a small `chrome.*` stub, so the banner it renders
is produced by the same code the extension ships.
