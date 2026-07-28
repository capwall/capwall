// Fixture app for the capwall observe→enforce walkthrough. NOT production code.
//
// This minimal Express server exercises a couple of real capabilities so capwall has
// something to observe:
//   - fs:  the /log route appends a line to ./logs/requests.log (fs:write grant).
//   - env: this app and its dependency tree (express, debug, depd, mime) read process.env.
// Binding a listening socket is NOT mediated — capwall's net shim covers egress, so an
// inbound listener produces no net grant. See docs/threat-model.md.
//
// Run it under capwall:
//   capwall observe -o /tmp/observed.json -- node src/server.js   # draft policy
//   # review it against the committed ./capabilities.json, then:
//   capwall enforce -- node src/server.js                         # zero denials
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
  // Inbound listener — not a mediated capability (the net shim covers egress). This is also
  // where express reaches Node's cluster module, which reads NODE_CLUSTER_SCHED_POLICY. That
  // read is Node's, not express's, so since #119 it is not recorded and the policy does not
  // grant it.
  console.log(`express-app fixture listening on http://localhost:${PORT}`);
});
