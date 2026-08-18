#!/usr/bin/env node
"use strict";

/**
 * Serves the repository so docs/demo/login/ can be opened on a hostname that
 * actually trips the scorer. Browsers resolve any *.localhost name to the
 * loopback address, so the demo is reachable at
 *
 *   http://steamcommunity.com.localhost:8731/docs/demo/login/
 *
 * which the scorer reads as steamcommunity.com embedded in someone else's
 * hostname -- the same shape as a real embedded-domain phish. No dependencies,
 * no hosts-file edits, nothing listening outside loopback.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const PORT = Number(process.env.PORT) || 8731;
const DEMO_PATH = "/docs/demo/login/";

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png"
};

const server = http.createServer((req, res) => {
  const requested = decodeURIComponent(req.url.split("?")[0]);
  let filePath = path.join(ROOT, requested);

  // Never serve outside the repository.
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403).end("Forbidden");
    return;
  }
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    filePath = path.join(filePath, "index.html");
  }
  if (!fs.existsSync(filePath)) {
    res.writeHead(404).end("Not found");
    return;
  }

  res.writeHead(200, { "Content-Type": TYPES[path.extname(filePath)] || "application/octet-stream" });
  fs.createReadStream(filePath).pipe(res);
});

server.listen(PORT, "127.0.0.1", () => {
  console.log("");
  console.log("  Demo phishing page (block verdict, score 60):");
  console.log("  http://steamcommunity.com.localhost:" + PORT + DEMO_PATH);
  console.log("");
  console.log("  Ctrl-C to stop.");
  console.log("");
});
