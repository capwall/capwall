// oxlint-disable eslint/no-eval -- the `app-eval` vector exists to pin what the application's
// OWN direct `eval` attributes to after #84. Direct, for the same scope reason as forge-dep.
//
// App entry for the eval-origin forgery fixture (issue #84).
//
// `node app.cjs <vector>` runs one vector and prints `env=<value|undefined>` and
// `fs=<content|DENIED:pkg|…>`. Vectors named `app-*` run from THIS file — application code,
// the trust root — so the tests can pin what changed for ordinary app behavior.

const path = require("node:path");
const dep = require("forge-dep");

const SECRET = "FORGE_FIXTURE_SECRET";
const SECRET_FILE = path.join(__dirname, "secret.txt");
const vector = process.argv[2];

const APP_PAYLOAD = `(function () {
  const out = { env: undefined, fs: undefined };
  out.env = process.env[${JSON.stringify(SECRET)}];
  try {
    out.fs = require("node:fs").readFileSync(${JSON.stringify(SECRET_FILE)}, "utf8").trim();
  } catch (err) {
    out.fs = err && err.name === "CapabilityError" ? "DENIED:" + err.pkg : "THREW:" + err.message;
  }
  return out;
})()`;

function report(out) {
  console.log(`env=${out.env === undefined ? "undefined" : out.env}`);
  console.log(`fs=${out.fs}`);
}

async function main() {
  if (vector === "app-eval") {
    // The application's OWN synchronous eval. This is the one legitimate case the fix
    // downgrades: an eval frame has no filesystem identity, and `<app>` — the trust root, with
    // exemptions — may never be inferred through code that has none. It becomes `<unknown>`.
    report(eval(APP_PAYLOAD));
  } else if (vector === "app-plain") {
    // Ordinary application code, no eval anywhere: `<app>`, unchanged by this fix.
    report({
      env: process.env[SECRET],
      fs: (() => {
        try {
          return require("node:fs").readFileSync(SECRET_FILE, "utf8").trim();
        } catch (err) {
          return err && err.name === "CapabilityError" ? `DENIED:${err.pkg}` : `THREW:${err.message}`;
        }
      })(),
    });
  } else {
    await dep.run(vector);
  }
  console.log("done");
}

void main();
