/**
 * Popup. Asks the content script for the verdict it already computed, because
 * that one had the page's DOM to work with. Falls back to scoring the URL alone
 * on pages where no content script runs.
 */
(function () {
  "use strict";

  const LABELS = {
    block: "Likely phishing",
    caution: "Suspicious",
    silent: "No warning"
  };

  const els = {
    host: document.getElementById("host"),
    verdict: document.getElementById("verdict"),
    label: document.getElementById("label"),
    score: document.getElementById("score"),
    reasons: document.getElementById("reasons"),
    note: document.getElementById("note"),
    button: document.getElementById("checkButton")
  };

  function render(result, url, urlOnly) {
    let host = url;
    try {
      host = new URL(url).hostname;
    } catch (err) {
      // Leave the raw string in place.
    }

    els.host.textContent = host;
    els.verdict.className = result.verdict;
    els.label.textContent = LABELS[result.verdict] || result.verdict;
    els.score.textContent = "Risk score " + result.score + " / 100";

    els.reasons.textContent = "";
    const scored = result.reasons.filter(r => r.weight > 0);
    for (const reason of scored) {
      const item = document.createElement("li");
      item.textContent = reason.detail + " (+" + reason.weight + ")";
      els.reasons.appendChild(item);
    }
    if (!scored.length) {
      const item = document.createElement("li");
      item.textContent = result.reasons.length ? result.reasons[0].detail : "No risk signals matched.";
      els.reasons.appendChild(item);
    }

    els.note.textContent = urlOnly
      ? "Scored from the URL alone — no page content was available, so branding and password-field checks did not run."
      : "";
  }

  function check() {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const tab = tabs[0];
      if (!tab || !tab.url) {
        els.host.textContent = "No active tab";
        return;
      }

      chrome.tabs.sendMessage(tab.id, { type: "getVerdict" }, response => {
        if (chrome.runtime.lastError || !response) {
          // No content script here: a chrome:// page, the web store, or a tab
          // opened before the extension loaded. Score what we can.
          render(SteamPhishScoring.score(tab.url), tab.url, true);
          return;
        }
        render(response, tab.url, false);
      });
    });
  }

  els.button.addEventListener("click", check);
  check();
})();
