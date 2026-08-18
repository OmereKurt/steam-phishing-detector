/**
 * Content script. Collects what only the DOM can tell us, hands it to the
 * scorer, and renders a warning if the verdict warrants one.
 *
 * All detection logic lives in scoring.js. This file is deliberately dumb: it
 * gathers signals, calls score(), and draws. That split is what lets the
 * detection be tested against a labelled corpus without a browser.
 */
(function () {
  "use strict";

  const BANNER_ID = "steam-phishing-detector-banner";
  const MAX_ALT_TEXTS = 50;
  const scoring = globalThis.SteamPhishScoring;

  if (!scoring) return;                       // sync failed; fail silent
  if (window.top !== window.self) return;     // never warn from inside an iframe

  let lastResult = null;
  let credentialFieldSeen = false;

  /** Everything the scorer wants that only exists in the DOM. */
  function collectPageSignals() {
    const altTexts = [];
    const images = document.images || [];
    for (let i = 0; i < images.length && altTexts.length < MAX_ALT_TEXTS; i++) {
      if (images[i].alt) altTexts.push(images[i].alt);
    }
    return {
      hasCredentialField: !!document.querySelector('input[type="password"]'),
      title: document.title || "",
      imageAltTexts: altTexts
    };
  }

  function evaluate() {
    const signals = collectPageSignals();
    credentialFieldSeen = credentialFieldSeen || signals.hasCredentialField;
    signals.hasCredentialField = credentialFieldSeen;

    lastResult = scoring.score(location.href, signals);

    try {
      chrome.runtime.sendMessage({
        type: "verdict",
        verdict: lastResult.verdict,
        score: lastResult.score
      });
    } catch (err) {
      // Service worker asleep or extension reloading. The banner still renders.
    }

    render(lastResult);
    return lastResult;
  }

  // ---------------------------------------------------------------------------
  // Rendering
  // ---------------------------------------------------------------------------

  const PALETTE = {
    block:   { background: "#b3202c", foreground: "#ffffff", label: "Likely phishing" },
    caution: { background: "#ffcc00", foreground: "#111111", label: "Suspicious page" }
  };

  function render(result) {
    const existing = document.getElementById(BANNER_ID);
    if (result.verdict === "silent") {
      if (existing) existing.remove();
      return;
    }
    if (existing) {
      if (existing.dataset.verdict === result.verdict) return;
      existing.remove();
    }

    const theme = PALETTE[result.verdict];
    const host = document.createElement("div");
    host.id = BANNER_ID;
    host.dataset.verdict = result.verdict;

    // A closed shadow root keeps the page's own CSS from restyling or hiding
    // the warning. On a page built to deceive, that is not a hypothetical.
    const shadow = host.attachShadow({ mode: "closed" });

    const style = document.createElement("style");
    style.textContent = `
      .bar {
        position: fixed; top: 0; left: 0; right: 0;
        z-index: 2147483647;
        background: ${theme.background};
        color: ${theme.foreground};
        font: 400 14px/1.45 system-ui, -apple-system, sans-serif;
        padding: 12px 16px;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
        display: flex; align-items: flex-start; gap: 16px;
      }
      .body { flex: 1; min-width: 0; }
      .headline { font-weight: 700; margin-bottom: 4px; }
      .score { opacity: 0.85; font-weight: 400; }
      ul { margin: 6px 0 0; padding-left: 18px; }
      li { margin: 2px 0; }
      .actions { display: flex; gap: 8px; flex-shrink: 0; }
      button {
        border: 0; border-radius: 4px; padding: 7px 12px;
        font: 600 13px system-ui, sans-serif; cursor: pointer;
        background: rgba(255, 255, 255, 0.92); color: #111;
      }
      button:hover { background: #ffffff; }
    `;

    const bar = document.createElement("div");
    bar.className = "bar";

    const body = document.createElement("div");
    body.className = "body";

    const headline = document.createElement("div");
    headline.className = "headline";
    headline.textContent = theme.label + " — do not enter your Steam password here.";
    const score = document.createElement("span");
    score.className = "score";
    score.textContent = " (risk score " + result.score + "/100)";
    headline.appendChild(score);
    body.appendChild(headline);

    const list = document.createElement("ul");
    for (const reason of result.reasons.filter(r => r.weight > 0).slice(0, 3)) {
      const item = document.createElement("li");
      item.textContent = reason.detail;
      list.appendChild(item);
    }
    if (list.childElementCount) body.appendChild(list);

    const actions = document.createElement("div");
    actions.className = "actions";

    if (result.verdict === "block" && history.length > 1) {
      const back = document.createElement("button");
      back.textContent = "Go back";
      back.addEventListener("click", () => history.back());
      actions.appendChild(back);
    }

    const dismiss = document.createElement("button");
    dismiss.textContent = "Dismiss";
    dismiss.addEventListener("click", () => host.remove());
    actions.appendChild(dismiss);

    bar.appendChild(body);
    bar.appendChild(actions);
    shadow.appendChild(style);
    shadow.appendChild(bar);
    document.documentElement.appendChild(host);
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  evaluate();

  // A password field injected after load is the whole attack on a single-page
  // app. Watch for one, re-score when it shows up, then stop watching.
  if (!credentialFieldSeen) {
    const observer = new MutationObserver(() => {
      if (!document.querySelector('input[type="password"]')) return;
      observer.disconnect();
      evaluate();
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => observer.disconnect(), 30000);
  }

  // The popup asks for this tab's verdict so it can show the same reasons the
  // banner does, rather than re-scoring the URL without any page context.
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === "getVerdict") {
      sendResponse(lastResult || evaluate());
    }
    return false;
  });
})();
