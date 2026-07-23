// Fixture app for the capwall observe→enforce walkthrough. NOT production code.
//
// This minimal Express server exercises a couple of real capabilities so capwall has
// something to observe:
//   - net: express binds and serves on a port (net grant).
//   - fs:  the /log route appends a line to ./logs/requests.log (fs:write grant).
//
// Run it under capwall (once the CLI is implemented):
//   capwall observe -- node src/server.js     # records what express + this app do
//   # review/tighten ../../capabilities.json, then:
//   capwall enforce -- node src/server.js
//
// See ./README.md for the full walkthrough.
const fs = require("node:fs");
const path = require("node:path");
const express = require("express");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const LOG_DIR = path.join(__dirname, "..", "logs");

app.get("/", (_req, res) => {
  res.type("text/plain").send("capwall express-app fixture: OK\n");
});

app.get("/log", (_req, res) => {
  // fs:write capability — capwall attributes this to the app (and express in the stack).
  fs.mkdirSync(LOG_DIR, { recursive: true });
  fs.appendFileSync(path.join(LOG_DIR, "requests.log"), `${new Date().toISOString()} /log\n`);
  res.type("text/plain").send("logged\n");
});

app.listen(PORT, () => {
  // net capability — binding/serving on a port.
  console.log(`express-app fixture listening on http://localhost:${PORT}`);
});
