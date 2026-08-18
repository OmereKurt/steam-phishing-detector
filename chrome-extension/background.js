/**
 * Service worker. Mirrors each tab's verdict onto the toolbar badge so the
 * result is visible without opening the popup.
 */
const BADGE = {
  block:   { text: "!", color: "#b3202c" },
  caution: { text: "?", color: "#c8a000" },
  silent:  { text: "",  color: "#4c6b22" }
};

chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeBackgroundColor({ color: BADGE.silent.color });
});

chrome.runtime.onMessage.addListener((message, sender) => {
  if (!message || message.type !== "verdict") return;
  const tabId = sender.tab && sender.tab.id;
  if (tabId === undefined) return;

  const badge = BADGE[message.verdict] || BADGE.silent;
  chrome.action.setBadgeText({ tabId, text: badge.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
  chrome.action.setTitle({
    tabId,
    title: "Steam Phishing Detector — " + message.verdict + " (score " + message.score + "/100)"
  });
});
