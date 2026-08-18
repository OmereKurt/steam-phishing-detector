"use strict";

const fs = require("fs");
const path = require("path");

const CORPUS_PATH = path.join(__dirname, "..", "corpus.json");

/**
 * Undo the defanging applied to every URL in the corpus.
 * hxxps://steamcommunity[.]com/ -> https://steamcommunity.com/
 *
 * Replaces every hxxp, not just a leading one: a few entries carry a second URL
 * inside a path or redirect parameter and that one is defanged as well.
 */
function refang(url) {
  return String(url).replace(/hxxp/gi, "http").split("[.]").join(".");
}

function loadCorpus() {
  const raw = JSON.parse(fs.readFileSync(CORPUS_PATH, "utf8"));
  return raw.entries.map(entry => ({
    url: refang(entry.url),
    defangedUrl: entry.url,
    label: entry.label,
    category: entry.category,
    pageSignals: entry.pageSignals || {},
    note: entry.note || ""
  }));
}

module.exports = { loadCorpus, refang, CORPUS_PATH };
