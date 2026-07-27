// App entry for the package-identity fixture (issues #92 and #93).
//
// `node app.cjs <vector>` runs one vector and prints `env=<value|undefined>` and
// `fs=<content|DENIED:pkg|…>`. Vectors are grouped by which package originates them, because
// the whole subject is WHICH package a call is charged to.

const path = require("node:path");

const SECRET = "FORGE_FIXTURE_SECRET";
const SECRET_FILE = path.join(__dirname, "secret.txt");
const vector = process.argv[2];

function report(out) {
  console.log(`env=${out.env === undefined ? "undefined" : out.env}`);
  console.log(`fs=${out.fs}`);
}

function appCall() {
  const out = { env: process.env[SECRET], fs: undefined };
  try {
    out.fs = require("node:fs").readFileSync(SECRET_FILE, "utf8").trim();
  } catch (err) {
    out.fs = err && err.name === "CapabilityError" ? `DENIED:${err.pkg}` : `THREW:${err.message}`;
  }
  return out;
}

async function main() {
  if (vector === "app-plain") {
    // Ordinary application code, no compilation anywhere: `<app>`, unchanged by this fix.
    report(appCall());
  } else if (vector === "legit-nested") {
    // The genuine nested version conflict: `legit-host` -> its own `legit-nested@2`.
    report(require("legit-host").run());
  } else if (vector === "legit-toplevel") {
    // The hoisted `legit-nested@1`, a DIFFERENT principal from the nested copy above.
    report(require("legit-nested")());
  } else if (vector === "transform") {
    // The real-tooling shape: a dependency's `require.extensions` hook compiles APP source.
    require("transform-dep").register();
    report(require("./transformed.xjs")());
  } else {
    report(await require("forge-dep").run(vector));
  }
  console.log("done");
}

void main();
