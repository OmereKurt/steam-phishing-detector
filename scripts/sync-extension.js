#!/usr/bin/env node
"use strict";

/**
 * The scorer has one source of truth, src/scoring.js, and it has to exist in
 * two places: Node requires it for the tests, and Chrome loads it as a content
 * script. MV3 content scripts cannot use ES module imports, so rather than pull
 * in a bundler for one file, the source is copied into the extension verbatim
 * with a generated header.
 *
 *   npm run sync          write chrome-extension/scoring.js
 *   npm run sync:check    fail if the copy has drifted (CI runs this)
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const SOURCE = path.join(ROOT, "src", "scoring.js");
const TARGET = path.join(ROOT, "chrome-extension", "scoring.js");

const HEADER = [
  "// ============================================================",
  "// GENERATED FILE - DO NOT EDIT",
  "//",
  "// Copied verbatim from src/scoring.js by scripts/sync-extension.js.",
  "// Edit the source, then run: npm run sync",
  "// CI runs `npm run sync:check` and fails if these two drift apart.",
  "// ============================================================",
  ""
].join("\n");

function build() {
  return HEADER + "\n" + fs.readFileSync(SOURCE, "utf8");
}

function main() {
  const expected = build();
  const check = process.argv.includes("--check");

  if (!check) {
    fs.writeFileSync(TARGET, expected);
    console.log("wrote " + path.relative(ROOT, TARGET));
    return;
  }

  const actual = fs.existsSync(TARGET) ? fs.readFileSync(TARGET, "utf8") : null;
  if (actual === expected) {
    console.log("chrome-extension/scoring.js is in sync with src/scoring.js");
    return;
  }

  console.error(
    actual === null
      ? "chrome-extension/scoring.js is missing."
      : "chrome-extension/scoring.js has drifted from src/scoring.js."
  );
  console.error("Run `npm run sync` and commit the result.");
  process.exit(1);
}

main();
